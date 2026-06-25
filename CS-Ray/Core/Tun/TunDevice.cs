using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;

namespace CS_Ray.Core.Tun
{
    /// <summary>
    /// Phase 1/2 TUN device: arch-correct wintun load, create "CSRayTun", start a session, and run a
    /// background read loop that classifies IP packets (per-protocol counters) and logs headers — the
    /// high-frequency per-packet lines go to a separate "packet" log sink so the UI can rate-limit them,
    /// while a Test-IP match is ALWAYS logged on the priority sink. Routes nothing. Clean teardown.
    /// </summary>
    public class TunDevice
    {
        private const uint ERROR_HANDLE_EOF = 38;
        private const uint ERROR_NO_MORE_ITEMS = 259;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        private readonly Action<string> _log;        // priority sink (lifecycle, test-hits)
        private readonly Action<string> _logPacket;  // high-frequency per-packet sink (rate-limited by UI)
        private IntPtr _adapter;
        private IntPtr _session;
        private Thread _readThread;
        private volatile bool _stop;

        // Routing params — read dynamically by the handlers, so they can be (re)set on each Start-TUN
        // without recreating the pre-loaded adapter/handlers.
        public volatile string TestIp;
        /// <summary>When false (pre-loaded but routing off), the read loop drains+drops silently — no work shown.</summary>
        public volatile bool RoutingActive;
        private volatile uint _physicalIfIndex;
        private volatile int _enginePort = 10810;
        public uint PhysicalIfIndex { get { return _physicalIfIndex; } set { _physicalIfIndex = value; } }
        public int EnginePort { get { return _enginePort; } set { _enginePort = value; } }

        // 64-bit counters (Interlocked-safe on ARM32).
        private long _pTotal, _pV4, _pV6, _pTcp, _pUdp, _pIcmp;
        private long _pDropped, _pUdpRelayed, _pIcmpReplies, _pUdpQuicDropped, _pUdpViaEngine, _pUdpLeakDropped;

        private IcmpHandler _icmp;
        private UdpHandler _udp;
        private Tcp.TcpStack _tcp;
        private Func<Protocol.IUdpOutbound> _pendingUdpFactory; // set at full-tunnel start; applied to _udp

        /// <summary>Arm (or clear) the UDP outbound used to tunnel TUN UDP. Null = drop UDP (no leak).</summary>
        public void SetUdpOutboundFactory(Func<Protocol.IUdpOutbound> factory)
        {
            _pendingUdpFactory = factory;
            if (_udp != null) _udp.OutboundFactory = factory;
        }

        /// <summary>Live tunneled-UDP session count (NAT flows).</summary>
        public int UdpSessions { get { return _udp != null ? _udp.SessionCount : 0; } }

        private static WintunLoggerCallback _wintunLogger; // keep referenced (native callback)
        private static TunDevice s_active;

        public TunDevice(Action<string> log, Action<string> logPacket)
        {
            _log = log;
            _logPacket = logPacket;
        }

        public IntPtr Adapter => _adapter;

        /// <summary>Creates the adapter + session (does NOT start reading — call <see cref="BeginReading"/> after routing is up).</summary>
        public bool Start()
        {
            if (!WintunLoader.EnsureLoaded(_log)) return false;
            try
            {
                if (_wintunLogger == null)
                {
                    _wintunLogger = OnWintunLog;
                    WintunApi.WintunSetLogger(_wintunLogger);
                }

                var guid = new Guid("0c5a1b2c-3d4e-4f5a-8b6c-7d8e9f0a1b2c");

                // Adopt an existing CSRayTun (e.g. left by a prior crash/force-kill) — creating a
                // duplicate-named adapter fails with ERROR_FILE_NOT_FOUND (2). Only create if none exists.
                _adapter = WintunApi.WintunOpenAdapter("CSRayTun");
                if (_adapter != IntPtr.Zero)
                {
                    _log?.Invoke("TUN: reused existing CSRayTun adapter.");
                }
                else
                {
                    _adapter = WintunApi.WintunCreateAdapter("CSRayTun", "CS-Ray", ref guid);
                    if (_adapter == IntPtr.Zero)
                    {
                        int e = Marshal.GetLastWin32Error();
                        _log?.Invoke("TUN: CreateAdapter failed (" + e + " — " + new Win32Exception(e).Message + ")." +
                                     (e == 5 ? " Run CS-Ray as administrator." : e == 2 ? " Stale driver/adapter state — try rebooting." : ""));
                        return false;
                    }
                    uint ver = 0; try { ver = WintunApi.WintunGetRunningDriverVersion(); } catch { }
                    _log?.Invoke("TUN: adapter 'CSRayTun' created" +
                                 (ver != 0 ? " (driver " + (ver >> 16) + "." + (ver & 0xFFFF) + ")" : "") + ".");
                }

                _session = WintunApi.WintunStartSession(_adapter, 0x400000);
                if (_session == IntPtr.Zero)
                {
                    int e = Marshal.GetLastWin32Error();
                    _log?.Invoke("TUN: StartSession failed (" + e + " — " + new Win32Exception(e).Message + ").");
                    WintunApi.WintunCloseAdapter(_adapter);
                    _adapter = IntPtr.Zero;
                    return false;
                }

                _log?.Invoke("TUN: session started (ring 0x400000).");
                s_active = this;
                return true;
            }
            catch (Exception ex)
            {
                _log?.Invoke("TUN: start error — " + ex.Message);
                Stop();
                return false;
            }
        }

        /// <summary>Starts the background read loop (call after IP/routes are applied).</summary>
        public void BeginReading()
        {
            if (_session == IntPtr.Zero || _readThread != null) return;

            _icmp = new IcmpHandler(WritePacket, () => Interlocked.Increment(ref _pIcmpReplies));
            _udp = new UdpHandler(WritePacket, () => _enginePort,
                () => Interlocked.Increment(ref _pUdpViaEngine),
                () => Interlocked.Increment(ref _pUdpQuicDropped),
                () => Interlocked.Increment(ref _pUdpLeakDropped), _log)
            { OutboundFactory = _pendingUdpFactory };
            _tcp = new Tcp.TcpStack(WritePacket, () => _enginePort, _log);

            _stop = false;
            _readThread = new Thread(ReadLoop) { IsBackground = true, Name = "TunRead" };
            _readThread.Start();
        }

        private readonly object _writeLock = new object();

        /// <summary>Writes a built IP packet back into the adapter. Serialized — many handlers write concurrently.</summary>
        public void WritePacket(byte[] data)
        {
            if (_session == IntPtr.Zero || data == null || data.Length == 0) return;
            lock (_writeLock)
            {
                if (_session == IntPtr.Zero) return;
                IntPtr p = WintunApi.WintunAllocateSendPacket(_session, (uint)data.Length);
                if (p == IntPtr.Zero) return; // send ring full → drop
                Marshal.Copy(data, 0, p, data.Length);
                WintunApi.WintunSendPacket(_session, p);
            }
        }

        public void GetCounters(out long total, out long v4, out long v6, out long tcp, out long udp, out long icmp)
        {
            total = Interlocked.Read(ref _pTotal);
            v4 = Interlocked.Read(ref _pV4);
            v6 = Interlocked.Read(ref _pV6);
            tcp = Interlocked.Read(ref _pTcp);
            udp = Interlocked.Read(ref _pUdp);
            icmp = Interlocked.Read(ref _pIcmp);
        }

        public void GetRelayCounters(out long dropped, out long udpRelayed, out long icmpReplies, out long quicDropped, out long udpViaEngine, out long leakDropped)
        {
            dropped = Interlocked.Read(ref _pDropped);
            udpRelayed = Interlocked.Read(ref _pUdpRelayed);
            icmpReplies = Interlocked.Read(ref _pIcmpReplies);
            quicDropped = Interlocked.Read(ref _pUdpQuicDropped);
            udpViaEngine = Interlocked.Read(ref _pUdpViaEngine);
            leakDropped = Interlocked.Read(ref _pUdpLeakDropped);
        }

        public void GetTcpCounters(out long opened, out long active, out long closed, out long peak)
        {
            if (_tcp != null) _tcp.GetCounters(out opened, out active, out closed, out peak);
            else { opened = 0; active = 0; closed = 0; peak = 0; }
        }

        private void ReadLoop()
        {
            IntPtr waitEvent = WintunApi.WintunGetReadWaitEvent(_session);
            while (!_stop)
            {
                IntPtr packet = WintunApi.WintunReceivePacket(_session, out uint size);
                if (packet != IntPtr.Zero)
                {
                    ProcessPacket(packet, (int)size);
                    WintunApi.WintunReleaseReceivePacket(_session, packet);
                }
                else
                {
                    uint err = (uint)Marshal.GetLastWin32Error();
                    if (err == ERROR_NO_MORE_ITEMS) WaitForSingleObject(waitEvent, 1000);
                    else if (err == ERROR_HANDLE_EOF) break;
                    else { _log?.Invoke("TUN: ReceivePacket error " + err); break; }
                }
            }
        }

        // Copy out of the wintun buffer, count + log, then filter + relay.
        private void ProcessPacket(IntPtr p, int len)
        {
            // Idle pre-loaded adapter (routing off): drain+drop silently — no log/relay/stats.
            if (!RoutingActive) return;
            Interlocked.Increment(ref _pTotal);
            if (len <= 0) return;
            var buf = new byte[len];
            Marshal.Copy(p, buf, 0, len);

            ClassifyAndLog(buf, len);

            var action = PacketFilter.Decide(buf, len, out int ihl, out _, out _);
            int t0 = Environment.TickCount;
            switch (action)
            {
                case PacketAction.Drop: Interlocked.Increment(ref _pDropped); break;
                case PacketAction.Icmp: _icmp.Handle(buf, len, ihl); break;
                case PacketAction.Udp: _udp.Handle(buf, len, ihl); break;
                case PacketAction.Tcp: _tcp.Handle(buf, len, ihl); break;
                default: break; // Other ignored
            }
            // Sanity: the read loop must only parse+dispatch. Warn (rate-limited) if a dispatch ever blocks.
            int dt = unchecked(Environment.TickCount - t0);
            if (dt > 20 && unchecked(Environment.TickCount - _lastStallWarn) > 1000)
            {
                _lastStallWarn = Environment.TickCount;
                _log?.Invoke("TUN WARN: read-loop dispatch took " + dt + "ms (" + action + ") — should be non-blocking.");
            }
        }

        private int _lastStallWarn;

        // Per-protocol counters + the per-packet log line (TEST-HIT on priority sink, else flood sink).
        private void ClassifyAndLog(byte[] b, int len)
        {
            int version = len >= 1 ? b[0] >> 4 : 0;
            string line, destIp = null;

            if (version == 4 && len >= 20)
            {
                Interlocked.Increment(ref _pV4);
                byte proto = b[9];
                if (proto == 6) Interlocked.Increment(ref _pTcp);
                else if (proto == 17) Interlocked.Increment(ref _pUdp);
                else if (proto == 1) Interlocked.Increment(ref _pIcmp);
                string src = b[12] + "." + b[13] + "." + b[14] + "." + b[15];
                destIp = b[16] + "." + b[17] + "." + b[18] + "." + b[19];
                line = "IPv4 len=" + len + " " + ProtoName(proto) + " " + src + " -> " + destIp;
            }
            else if (version == 6 && len >= 40)
            {
                Interlocked.Increment(ref _pV6);
                byte nh = b[6];
                if (nh == 58) Interlocked.Increment(ref _pIcmp);
                line = "IPv6 len=" + len + " nextHdr=" + ProtoName(nh);
            }
            else line = "len=" + len + " ver=" + version + " (non-IP?)";

            var test = TestIp;
            if (destIp != null && !string.IsNullOrEmpty(test) && destIp == test)
                _log?.Invoke("TUN TEST-HIT: " + line);   // priority — always shown
            else
                _logPacket?.Invoke("TUN pkt: " + line);   // flood — rate-limited by the UI
        }

        private static string ProtoName(byte p)
        {
            switch (p) { case 1: return "ICMP"; case 6: return "TCP"; case 17: return "UDP"; case 58: return "ICMPv6"; default: return "proto" + p; }
        }

        private static void OnWintunLog(WintunLoggerLevel level, ulong timestamp, string message)
        {
            s_active?._log?.Invoke("  [wintun " + level.ToString().ToUpperInvariant() + "] " + message);
        }

        public void Stop()
        {
            _stop = true;
            try { _tcp?.Stop(); } catch { }
            try { _udp?.Stop(); } catch { }
            try { if (_session != IntPtr.Zero) WintunApi.WintunEndSession(_session); } catch { }
            try { if (_readThread != null && _readThread.IsAlive) _readThread.Join(2000); } catch { }
            try { if (_adapter != IntPtr.Zero) WintunApi.WintunCloseAdapter(_adapter); } catch { }
            if (_session != IntPtr.Zero || _adapter != IntPtr.Zero)
                _log?.Invoke("TUN: stopped (session ended, adapter closed).");
            _session = IntPtr.Zero;
            _adapter = IntPtr.Zero;
            _readThread = null;
            if (s_active == this) s_active = null;
        }

        public static void StopActive() { try { s_active?.Stop(); } catch { } }
    }
}

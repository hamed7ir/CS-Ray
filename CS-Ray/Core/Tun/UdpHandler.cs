using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using CS_Ray.Core.Protocol;

namespace CS_Ray.Core.Tun
{
    /// <summary>
    /// UDP-over-engine (Phase E2). Every captured TUN UDP datagram is tunneled through the proxy: a
    /// per-flow NAT table maps (srcIp:srcPort→dstIp:dstPort) to an <see cref="IUdpOutbound"/> association
    /// (VLESS UDP) to that destination. App datagrams are sent through it; replies are read off-thread and
    /// written back into the TUN as synthesized UDP/IPv4 packets (addresses/ports swapped, checksums fixed).
    /// Nothing goes direct anymore (no leak). Flows expire on idle and the table is size-capped with
    /// oldest-eviction. Engine I/O (connect/send/recv) runs on per-flow worker tasks — never the read loop.
    ///
    /// Multicast/broadcast/link-local destinations never reach here (PacketFilter.Decide drops them upstream).
    /// </summary>
    public class UdpHandler
    {
        private const int MaxFlows = 256;
        private static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(60);

        private sealed class Flow
        {
            public IUdpOutbound Out;
            public uint SrcIp; public ushort SrcPort;   // original app source (reply destination)
            public uint ReplySrcIp;                      // original packet dst — reply is rewritten to come FROM here
            public ushort DstPort;
            public uint TunnelDstIp;                     // where the VLESS UDP session actually connects
            public string Key;
            public volatile bool Closed;
            public DateTime LastActivity;
            public CancellationTokenSource Cts;
            public readonly ConcurrentQueue<byte[]> SendQ = new ConcurrentQueue<byte[]>();
            public readonly SemaphoreSlim Signal = new SemaphoreSlim(0);
        }

        private readonly Action<byte[]> _write;
        private readonly Action _onViaEngine;
        private readonly Action _onQuicDropped;
        private readonly Action _onLeakDropped;
        private readonly Func<int> _enginePort; // engine SOCKS inbound — DNS-over-TCP fallback when no native UDP outbound
        private readonly Action<string> _log;

        private readonly Dictionary<string, Flow> _flows = new Dictionary<string, Flow>();
        private readonly HashSet<string> _seenLog = new HashSet<string>(); // first-seen diagnostics, capped
        private readonly object _lock = new object();
        private readonly Timer _expiry;

        /// <summary>Creates a fresh (unconnected) UDP outbound for a destination. Null = no UDP outbound
        /// available (e.g. non-VLESS profile) → datagrams are dropped (never relayed direct = no leak).</summary>
        public Func<IUdpOutbound> OutboundFactory { get; set; }

        public UdpHandler(Action<byte[]> write, Func<int> enginePort, Action onViaEngine, Action onQuicDropped, Action onLeakDropped, Action<string> log)
        {
            _write = write;
            _enginePort = enginePort;
            _onViaEngine = onViaEngine;
            _onQuicDropped = onQuicDropped;
            _onLeakDropped = onLeakDropped;
            _log = log;
            _expiry = new Timer(Expire, null, 10000, 10000);
        }

        public int SessionCount { get { lock (_lock) { return _flows.Count; } } }

        public void Handle(byte[] pkt, int len, int ihl)
        {
            if (len < ihl + 8) return;

            // Skip fragments (we don't reassemble; DNS/STUN/QUIC datagrams we tunnel aren't fragmented).
            int frag = (pkt[6] << 8) | pkt[7];
            if ((frag & 0x2000) != 0 || (frag & 0x1FFF) != 0) return;

            uint srcIp = U32(pkt, 12), dstIp = U32(pkt, 16);
            ushort srcPort = (ushort)((pkt[ihl] << 8) | pkt[ihl + 1]);
            ushort dstPort = (ushort)((pkt[ihl + 2] << 8) | pkt[ihl + 3]);
            int payloadOff = ihl + 8;
            int payloadLen = len - payloadOff;
            if (payloadLen < 0) return;

            // QUIC toggle (default ON): drop UDP/443 so apps fall back to TCP.
            if (PacketFilter.BlockQuic && dstPort == 443)
            {
                _onQuicDropped?.Invoke();
                LogOnce("quic:" + ToIp(dstIp), "TUN: QUIC (UDP 443) to " + ToIp(dstIp) + " dropped (toggle) — TCP fallback.");
                return;
            }

            var payload = new byte[payloadLen];
            Buffer.BlockCopy(pkt, payloadOff, payload, 0, payloadLen);

            // DNS (53): always resolve, leak-safe. Force ALL DNS to the chosen public resolver (not whatever
            // ISP/Iranian server the OS aimed it at). If we have a native UDP outbound (VLESS), tunnel it as UDP;
            // otherwise (VMess/SS — native UDP lands in E4) fall back to DNS-over-TCP through the engine, which
            // works over ANY outbound. The reply is rewritten to come from the original server.
            if (dstPort == 53)
            {
                uint resolver = PacketFilter.DnsResolver != 0 ? PacketFilter.DnsResolver : dstIp;
                if (OutboundFactory != null)
                    Tunnel(srcIp, srcPort, dstIp, dstPort, resolver, payload);
                else
                    ThreadPool.QueueUserWorkItem(_ => DnsViaEngine(srcIp, srcPort, dstIp, dstPort, resolver, payload));
                return;
            }

            // Non-DNS UDP: needs a native UDP outbound (VLESS/VMess). Protocols without one (e.g. Shadowsocks)
            // drop it — never relay direct (= no leak). With a factory, it tunnels.
            if (OutboundFactory == null)
            {
                LogOnce("noudp", "TUN UDP: non-DNS UDP needs a native UDP outbound (not available for this protocol) — dropped. DNS still works.");
                return;
            }

            Tunnel(srcIp, srcPort, dstIp, dstPort, dstIp, payload);
        }

        // DNS-over-TCP to the resolver THROUGH the engine (SOCKS5 on loopback) — works for any outbound
        // protocol. Used when there's no native UDP outbound (VMess/SS before E4). Runs off the read thread.
        private void DnsViaEngine(uint srcIp, ushort srcPort, uint origDstIp, ushort dstPort, uint resolver, byte[] query)
        {
            try
            {
                using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true })
                {
                    s.ReceiveTimeout = 5000; s.SendTimeout = 5000;
                    s.Connect(IPAddress.Loopback, _enginePort());

                    s.Send(new byte[] { 0x05, 0x01, 0x00 });
                    var m = RecvExact(s, 2); if (m == null || m[0] != 0x05 || m[1] != 0x00) throw new Exception("socks method");
                    var req = new byte[10]; req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01;
                    WriteU32(req, 4, resolver); req[8] = (byte)(dstPort >> 8); req[9] = (byte)dstPort;
                    s.Send(req);
                    var rep = RecvExact(s, 10); if (rep == null || rep[1] != 0x00) throw new Exception("socks connect");

                    // DNS-over-TCP framing: 2-byte big-endian length prefix.
                    var framed = new byte[2 + query.Length];
                    framed[0] = (byte)(query.Length >> 8); framed[1] = (byte)query.Length;
                    Buffer.BlockCopy(query, 0, framed, 2, query.Length);
                    s.Send(framed);

                    var lp = RecvExact(s, 2); if (lp == null) throw new Exception("no resp len");
                    int rlen = (lp[0] << 8) | lp[1];
                    var resp = RecvExact(s, rlen); if (resp == null) throw new Exception("short resp");

                    _write(BuildUdpReturn(origDstIp, dstPort, srcIp, srcPort, resp, resp.Length));
                    _onViaEngine?.Invoke();
                }
            }
            catch (Exception ex) { LogOnce("dnstcp", "TUN UDP: DNS-over-TCP failed — " + ex.Message); }
        }

        private static byte[] RecvExact(Socket s, int n)
        {
            var buf = new byte[n]; int off = 0;
            while (off < n) { int r = s.Receive(buf, off, n - off, SocketFlags.None); if (r <= 0) return null; off += r; }
            return buf;
        }

        private void Tunnel(uint srcIp, ushort srcPort, uint dstIp, ushort dstPort, uint tunnelDst, byte[] payload)
        {
            string key = srcIp + ":" + srcPort + ">" + dstIp + ":" + dstPort;
            Flow f; Flow evicted = null; bool started = false;

            lock (_lock)
            {
                if (!_flows.TryGetValue(key, out f))
                {
                    if (_flows.Count >= MaxFlows) evicted = EvictOldestLocked();
                    IUdpOutbound outb = null;
                    try { outb = OutboundFactory(); } catch { outb = null; }
                    if (outb != null)
                    {
                        f = new Flow
                        {
                            Out = outb, Key = key,
                            SrcIp = srcIp, SrcPort = srcPort, ReplySrcIp = dstIp, DstPort = dstPort,
                            TunnelDstIp = tunnelDst, Cts = new CancellationTokenSource(), LastActivity = DateTime.UtcNow
                        };
                        _flows[key] = f; started = true;
                    }
                }
                if (f != null) f.SendQ.Enqueue(payload);
            }

            if (evicted != null) ThreadPool.QueueUserWorkItem(_ => CloseQuiet(evicted)); // close off the read thread
            if (f == null) { LogOnce("nooutf", "TUN UDP: outbound unavailable — datagram dropped."); return; }

            f.LastActivity = DateTime.UtcNow;
            try { f.Signal.Release(); } catch (ObjectDisposedException) { }
            if (started) StartFlow(f);
        }

        // Per-flow worker: connect once, then a receive loop (replies → TUN) plus a send pump (queue → engine).
        private void StartFlow(Flow f)
        {
            Task.Run(async () =>
            {
                try
                {
                    await f.Out.ConnectAsync(ToIp(f.TunnelDstIp).ToString(), f.DstPort, f.Cts.Token).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    LogOnce("udpfail", "TUN UDP: session connect failed (" + ToIp(f.TunnelDstIp) + ":" + f.DstPort + ") — " + ex.Message);
                    CloseFlow(f);
                    return;
                }

                var recv = ReceiveLoop(f);
                try
                {
                    while (!f.Cts.IsCancellationRequested)
                    {
                        await f.Signal.WaitAsync(f.Cts.Token).ConfigureAwait(false);
                        byte[] dg;
                        while (f.SendQ.TryDequeue(out dg))
                        {
                            await f.Out.SendAsync(dg, 0, dg.Length, f.Cts.Token).ConfigureAwait(false);
                            _onViaEngine?.Invoke();
                            f.LastActivity = DateTime.UtcNow;
                        }
                    }
                }
                catch (OperationCanceledException) { }
                catch (Exception ex) { LogOnce("udpsend", "TUN UDP: send loop ended — " + ex.Message); }

                CloseFlow(f);
                try { await recv.ConfigureAwait(false); } catch { }
            });
        }

        private async Task ReceiveLoop(Flow f)
        {
            try
            {
                while (!f.Cts.IsCancellationRequested)
                {
                    var dg = await f.Out.ReceiveAsync(f.Cts.Token).ConfigureAwait(false);
                    if (dg == null) break; // clean EOF
                    f.LastActivity = DateTime.UtcNow;
                    if (dg.Length > 0)
                        _write(BuildUdpReturn(f.ReplySrcIp, f.DstPort, f.SrcIp, f.SrcPort, dg, dg.Length));
                }
            }
            catch (OperationCanceledException) { }
            catch { }
            CloseFlow(f);
        }

        private Flow EvictOldestLocked() // caller closes the returned flow OUTSIDE the lock
        {
            Flow oldest = null;
            foreach (var kv in _flows)
                if (oldest == null || kv.Value.LastActivity < oldest.LastActivity) oldest = kv.Value;
            if (oldest != null) _flows.Remove(oldest.Key);
            return oldest;
        }

        private void CloseFlow(Flow f)
        {
            lock (_lock)
            {
                Flow cur;
                if (_flows.TryGetValue(f.Key, out cur) && ReferenceEquals(cur, f)) _flows.Remove(f.Key);
            }
            CloseQuiet(f);
        }

        private static void CloseQuiet(Flow f)
        {
            if (f.Closed) return;
            f.Closed = true;
            try { f.Cts.Cancel(); } catch { }
            try { f.Out.Dispose(); } catch { }
        }

        private void Expire(object state)
        {
            List<Flow> dead = null;
            lock (_lock)
            {
                var now = DateTime.UtcNow;
                foreach (var kv in _flows)
                    if (now - kv.Value.LastActivity > IdleTimeout) (dead ?? (dead = new List<Flow>())).Add(kv.Value);
                if (dead != null) foreach (var f in dead) _flows.Remove(f.Key);
            }
            if (dead != null) foreach (var f in dead) CloseQuiet(f);
        }

        public void Stop()
        {
            try { _expiry.Dispose(); } catch { }
            List<Flow> all;
            lock (_lock) { all = new List<Flow>(_flows.Values); _flows.Clear(); }
            foreach (var f in all) CloseQuiet(f);
        }

        private void LogOnce(string key, string msg)
        {
            bool first;
            lock (_lock) { first = _seenLog.Add(key); if (_seenLog.Count > 2000) _seenLog.Clear(); }
            if (first) _log?.Invoke(msg);
        }

        // Reply packet: src = the server the app queried (ReplySrcIp:DstPort), dst = the original app source.
        private static byte[] BuildUdpReturn(uint srcIp, ushort srcPort, uint dstIp, ushort dstPort, byte[] payload, int payloadLen)
        {
            int udpLen = 8 + payloadLen;
            int total = 20 + udpLen;
            var p = new byte[total];

            p[0] = 0x45; p[1] = 0;
            p[2] = (byte)(total >> 8); p[3] = (byte)total;
            p[4] = 0; p[5] = 0; p[6] = 0x40; p[7] = 0; // DF
            p[8] = 64; p[9] = 17;                      // TTL, proto=UDP
            WriteU32(p, 12, srcIp);
            WriteU32(p, 16, dstIp);

            p[20] = (byte)(srcPort >> 8); p[21] = (byte)srcPort;
            p[22] = (byte)(dstPort >> 8); p[23] = (byte)dstPort;
            p[24] = (byte)(udpLen >> 8); p[25] = (byte)udpLen;
            Buffer.BlockCopy(payload, 0, p, 28, payloadLen);

            Checksums.SetUdpV4(p, 0, 20, udpLen);
            Checksums.SetIpHeader(p, 0, 20);
            return p;
        }

        private static uint U32(byte[] b, int o) => (uint)((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]);
        private static void WriteU32(byte[] b, int o, uint v) { b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v; }
        private static IPAddress ToIp(uint ip) => new IPAddress(new byte[] { (byte)(ip >> 24), (byte)(ip >> 16), (byte)(ip >> 8), (byte)ip });
    }
}

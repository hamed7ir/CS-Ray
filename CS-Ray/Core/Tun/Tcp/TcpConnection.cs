using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;

namespace CS_Ray.Core.Tun.Tcp
{
    /// <summary>
    /// Managed TCP terminator for ONE flow. Concurrency model (Phase 4b): the read loop only PARSES +
    /// ENQUEUES segments (never blocks); a per-connection on-demand worker drains the queue and does
    /// the blocking engine I/O; the engine→client direction runs on its own pump; all TUN writes go
    /// through the (serialized) write callback. Client→server backpressure rides on our advertised
    /// window (shrinks as the inbound buffer fills). Bridges to the engine via SOCKS5 on loopback.
    /// </summary>
    public class TcpConnection
    {
        private const ushort MaxWindow = 65535;
        private const int RcvLimit = 256 * 1024;  // client→server buffer cap → window backpressure
        private const int DefaultMss = 1400;
        private const int RetransmitMs = 300;
        private const int MaxRetries = 8;

        private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        private enum St { SynRcvd, Established, Closed }
        private struct QueuedSeg { public TcpSeg Seg; public byte[] Payload; }

        private readonly uint _appIp, _srvIp;
        private readonly ushort _appPort, _srvPort;
        private readonly Action<byte[]> _writeTun;
        private readonly int _enginePort;
        private readonly Action _onClosed;
        private readonly Action<string> _log;

        private readonly object _lock = new object();      // connection state
        private readonly object _sendLock = new object();  // serializes sends on the engine socket
        private St _state;
        private uint _clientIsn, _ourIsn, _ourSeq, _ourAck, _sndUna, _ourFinSeq;
        private ushort _clientWindow = MaxWindow;
        private int _mss = DefaultMss;
        private bool _outConnected, _clientFinSeen, _ourFinSent, _ourFinAcked, _closed;
        private int _retries;
        private long _rcvQueued; // bytes enqueued client→server, not yet consumed

        private Socket _out;
        private List<byte[]> _pending = new List<byte[]>();
        private readonly List<Unacked> _unacked = new List<Unacked>();
        private Timer _retransTimer;

        private readonly ConcurrentQueue<QueuedSeg> _inQ = new ConcurrentQueue<QueuedSeg>();
        private int _workerRunning;

        private struct Unacked { public uint EndSeq; public byte[] Packet; }

        public TcpConnection(TcpSeg syn, Action<byte[]> writeTun, int enginePort, Action onClosed, Action<string> log)
        {
            _appIp = syn.SrcIp; _appPort = syn.SrcPort;
            _srvIp = syn.DstIp; _srvPort = syn.DstPort;
            _writeTun = writeTun; _enginePort = enginePort; _onClosed = onClosed; _log = log;

            _clientIsn = syn.Seq;
            var b = new byte[4]; Rng.GetBytes(b);
            _ourIsn = (uint)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
            _ourSeq = _ourIsn; _sndUna = _ourIsn;
            _ourAck = _clientIsn + 1;
            if (syn.Mss >= 536 && syn.Mss < DefaultMss) _mss = syn.Mss;
            _state = St.SynRcvd;

            SendCtl((byte)(TcpSegment.SYN | TcpSegment.ACK));
            _ourSeq = _ourIsn + 1;

            _retransTimer = new Timer(OnRetransmit, null, RetransmitMs, RetransmitMs);
        }

        // Read-loop entry: copy the payload, enqueue, schedule the worker. Never blocks.
        public void Enqueue(TcpSeg s, byte[] payload)
        {
            if (_closed) return;
            if (payload != null && payload.Length > 0) Interlocked.Add(ref _rcvQueued, payload.Length);
            _inQ.Enqueue(new QueuedSeg { Seg = s, Payload = payload });
            if (Interlocked.CompareExchange(ref _workerRunning, 1, 0) == 0)
                ThreadPool.QueueUserWorkItem(DrainInbound);
        }

        private void DrainInbound(object _)
        {
            try
            {
                while (true)
                {
                    while (_inQ.TryDequeue(out var q)) ProcessSeg(q.Seg, q.Payload);
                    Interlocked.Exchange(ref _workerRunning, 0);
                    if (_inQ.IsEmpty) break;
                    if (Interlocked.CompareExchange(ref _workerRunning, 1, 0) != 0) break;
                }
            }
            catch { }
        }

        private void ProcessSeg(TcpSeg s, byte[] payload)
        {
            int payLen = payload != null ? payload.Length : 0;
            if (_closed) { if (payLen > 0) Interlocked.Add(ref _rcvQueued, -payLen); return; }
            if ((s.Flags & TcpSegment.RST) != 0) { if (payLen > 0) Interlocked.Add(ref _rcvQueued, -payLen); Close(); return; }

            if (_state == St.SynRcvd)
            {
                if ((s.Flags & TcpSegment.ACK) != 0 && s.Ack == _ourIsn + 1)
                {
                    _state = St.Established;
                    lock (_lock) _clientWindow = s.Window;
                    StartOutbound();
                }
                else if ((s.Flags & TcpSegment.SYN) != 0) { SendCtl((byte)(TcpSegment.SYN | TcpSegment.ACK)); if (payLen > 0) Interlocked.Add(ref _rcvQueued, -payLen); return; }
                else { if (payLen > 0) Interlocked.Add(ref _rcvQueued, -payLen); return; }
            }

            if ((s.Flags & TcpSegment.ACK) != 0) ProcessTheirAck(s.Ack, s.Window);

            uint expected; lock (_lock) expected = _ourAck;
            bool inOrder = s.Seq == expected;
            bool needAck = false;

            if (payLen > 0)
            {
                if (inOrder) { SendToOutbound(payload); lock (_lock) _ourAck += (uint)payLen; }
                Interlocked.Add(ref _rcvQueued, -payLen); // consumed (sent in-order, or dropped if out-of-order)
                needAck = true;
            }

            if ((s.Flags & TcpSegment.FIN) != 0 && inOrder)
            {
                lock (_lock) _ourAck += 1;
                _clientFinSeen = true;
                lock (_sendLock) { try { if (_outConnected) _out.Shutdown(SocketShutdown.Send); } catch { } }
                needAck = true;
            }

            if (needAck) SendCtl(TcpSegment.ACK);
            MaybeClose();
        }

        private void ProcessTheirAck(uint ack, ushort window)
        {
            lock (_lock)
            {
                if (SeqGt(ack, _sndUna)) { _sndUna = ack; _unacked.RemoveAll(u => SeqLeq(u.EndSeq, ack)); _retries = 0; }
                _clientWindow = window;
                if (_ourFinSent && SeqGeq(ack, _ourFinSeq + 1)) _ourFinAcked = true;
                Monitor.PulseAll(_lock);
            }
        }

        private void StartOutbound()
        {
            var th = new Thread(() =>
            {
                try
                {
                    _out = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    _out.Connect(IPAddress.Loopback, _enginePort);

                    _out.Send(new byte[] { 0x05, 0x01, 0x00 });
                    var m = RecvExact(2);
                    if (m == null || m[0] != 0x05 || m[1] != 0x00) throw new Exception("SOCKS method");

                    var req = new byte[10];
                    req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x01;
                    req[4] = (byte)(_srvIp >> 24); req[5] = (byte)(_srvIp >> 16); req[6] = (byte)(_srvIp >> 8); req[7] = (byte)_srvIp;
                    req[8] = (byte)(_srvPort >> 8); req[9] = (byte)_srvPort;
                    _out.Send(req);
                    var rep = RecvExact(10);
                    if (rep == null || rep[1] != 0x00) throw new Exception("SOCKS connect rep=" + (rep != null ? rep[1] : 255));

                    List<byte[]> pend;
                    lock (_lock) { _outConnected = true; pend = _pending; _pending = new List<byte[]>(); }
                    lock (_sendLock) { foreach (var d in pend) _out.Send(d); }
                    _log?.Invoke("TUN TCP: " + Ip(_srvIp) + ":" + _srvPort + " established via engine.");

                    new Thread(ReadPump) { IsBackground = true, Name = "TcpOut" }.Start();
                }
                catch (Exception ex)
                {
                    _log?.Invoke("TUN TCP: outbound " + Ip(_srvIp) + ":" + _srvPort + " failed — " + ex.Message);
                    Reset();
                }
            }) { IsBackground = true, Name = "TcpConnect" };
            th.Start();
        }

        private void ReadPump()
        {
            var buf = new byte[_mss];
            while (!_closed)
            {
                int n;
                try { n = _out.Receive(buf); } catch { break; }
                if (n <= 0) { OnOutboundEof(); return; }

                lock (_lock)
                {
                    int waits = 0;
                    while (!_closed && (uint)(_ourSeq - _sndUna) + (uint)n > Math.Max(_clientWindow, (ushort)1) && waits++ < 4)
                        Monitor.Wait(_lock, 1000);
                    if (_closed) return;

                    var seg = TcpSegment.Build(_srvIp, _srvPort, _appIp, _appPort, _ourSeq, _ourAck,
                        (byte)(TcpSegment.PSH | TcpSegment.ACK), AdvWindow(), buf, 0, n);
                    _writeTun(seg);
                    _unacked.Add(new Unacked { EndSeq = _ourSeq + (uint)n, Packet = seg });
                    _ourSeq += (uint)n;
                }
            }
        }

        private void OnOutboundEof()
        {
            lock (_lock)
            {
                if (_ourFinSent || _closed) return;
                var fin = TcpSegment.Build(_srvIp, _srvPort, _appIp, _appPort, _ourSeq, _ourAck,
                    (byte)(TcpSegment.FIN | TcpSegment.ACK), AdvWindow(), null, 0, 0);
                _writeTun(fin);
                _unacked.Add(new Unacked { EndSeq = _ourSeq + 1, Packet = fin });
                _ourFinSeq = _ourSeq; _ourSeq += 1; _ourFinSent = true;
            }
            MaybeClose();
        }

        private void SendToOutbound(byte[] data)
        {
            lock (_lock) { if (!_outConnected) { _pending.Add(data); return; } }
            lock (_sendLock) { try { _out.Send(data); } catch { Reset(); } }
        }

        private void SendCtl(byte flags)
        {
            uint seq, ack;
            lock (_lock) { seq = _ourSeq; ack = _ourAck; }
            _writeTun(TcpSegment.Build(_srvIp, _srvPort, _appIp, _appPort, seq, ack, flags, AdvWindow(), null, 0, 0));
        }

        private ushort AdvWindow()
        {
            long free = RcvLimit - Interlocked.Read(ref _rcvQueued);
            if (free < 0) free = 0;
            if (free > MaxWindow) free = MaxWindow;
            return (ushort)free;
        }

        private void OnRetransmit(object state)
        {
            byte[] resend = null; bool doReset = false;
            lock (_lock)
            {
                if (_closed || _unacked.Count == 0) return;
                if (++_retries > MaxRetries) doReset = true;
                else resend = _unacked[0].Packet;
            }
            if (doReset) Reset();
            else if (resend != null) _writeTun(resend);
        }

        private void MaybeClose()
        {
            if (_clientFinSeen && _ourFinSent && _ourFinAcked) Close();
        }

        private void Reset()
        {
            if (!MarkClosed()) return;
            uint seq, ack; lock (_lock) { seq = _ourSeq; ack = _ourAck; }
            try { _writeTun(TcpSegment.Build(_srvIp, _srvPort, _appIp, _appPort, seq, ack, TcpSegment.RST, 0, null, 0, 0)); } catch { }
            Finish();
        }

        public void Close()
        {
            if (MarkClosed()) Finish();
        }

        private bool MarkClosed()
        {
            lock (_lock) { if (_closed) return false; _closed = true; _state = St.Closed; Monitor.PulseAll(_lock); }
            return true;
        }

        private void Finish()
        {
            try { _retransTimer?.Dispose(); } catch { }
            try { _out?.Close(); } catch { }
            _onClosed?.Invoke();
        }

        private byte[] RecvExact(int n)
        {
            var buf = new byte[n]; int off = 0;
            while (off < n) { int r = _out.Receive(buf, off, n - off, SocketFlags.None); if (r <= 0) return null; off += r; }
            return buf;
        }

        private static bool SeqGt(uint a, uint b) => (int)(a - b) > 0;
        private static bool SeqGeq(uint a, uint b) => (int)(a - b) >= 0;
        private static bool SeqLeq(uint a, uint b) => (int)(a - b) <= 0;
        private static string Ip(uint ip) => (ip >> 24) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + (ip & 0xFF);
    }
}

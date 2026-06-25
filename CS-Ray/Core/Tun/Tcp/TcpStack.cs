using System;
using System.Collections.Generic;
using System.Threading;

namespace CS_Ray.Core.Tun.Tcp
{
    /// <summary>
    /// Owns the TCP connection table (keyed by 4-tuple), dispatches inbound segments to the right
    /// <see cref="TcpConnection"/> (creating one on a pure SYN), and provides the write-back-to-TUN
    /// callback. Size-capped with idle expiry. Connections bridge to the engine via SOCKS5 on the
    /// local inbound port. Construction/eviction happen OUTSIDE the table lock to avoid lock inversion.
    /// </summary>
    public class TcpStack
    {
        private const int MaxConns = 512;
        private static readonly TimeSpan Idle = TimeSpan.FromSeconds(60);

        private sealed class Entry { public TcpConnection Conn; public string Key; public DateTime Last; }

        private readonly Dictionary<string, Entry> _table = new Dictionary<string, Entry>();
        private readonly object _lock = new object();
        private readonly Action<byte[]> _writeTun;
        private readonly Func<int> _enginePort; // read dynamically — set when routing is (re)activated
        private readonly Action<string> _log;
        private readonly Timer _expiry;
        private long _opened, _closed, _peak;

        public TcpStack(Action<byte[]> writeTun, Func<int> enginePort, Action<string> log)
        {
            _writeTun = writeTun; _enginePort = enginePort; _log = log;
            _expiry = new Timer(Expire, null, 15000, 15000);
        }

        public void Handle(byte[] ip, int len, int ihl)
        {
            if (!TcpSegment.Parse(ip, len, ihl, out var s)) return;
            string key = s.SrcIp + ":" + s.SrcPort + ">" + s.DstIp + ":" + s.DstPort;

            Entry e;
            bool create = false, full = false;
            lock (_lock)
            {
                if (_table.TryGetValue(key, out e)) e.Last = DateTime.UtcNow;
                else
                {
                    bool isSyn = (s.Flags & TcpSegment.SYN) != 0 && (s.Flags & TcpSegment.ACK) == 0;
                    if (!isSyn) return; // unknown non-SYN segment → ignore
                    if (_table.Count >= MaxConns) full = true; else create = true;
                }
            }

            if (full) { SendRstFor(s); return; } // table full → refuse with RST, never stall

            if (create)
            {
                // Ctor sends the SYN-ACK (no stack lock held → no lock inversion with onClosed).
                var conn = new TcpConnection(s, _writeTun, _enginePort(), () => OnConnClosed(key), _log);
                bool inserted;
                lock (_lock)
                {
                    inserted = !_table.ContainsKey(key);
                    if (inserted)
                    {
                        _table[key] = new Entry { Conn = conn, Key = key, Last = DateTime.UtcNow };
                        Interlocked.Increment(ref _opened);
                        if (_table.Count > _peak) _peak = _table.Count;
                    }
                }
                if (!inserted) conn.Close();
                return; // this SYN is consumed by the ctor
            }

            byte[] payload = null;
            if (s.PayloadLength > 0) { payload = new byte[s.PayloadLength]; Buffer.BlockCopy(ip, s.PayloadOffset, payload, 0, s.PayloadLength); }
            e.Conn.Enqueue(s, payload);
        }

        private void OnConnClosed(string key)
        {
            lock (_lock) { if (_table.Remove(key)) Interlocked.Increment(ref _closed); }
        }

        // Refuse a connection (table full) with a RST from the impersonated server to the app.
        private void SendRstFor(TcpSeg s)
        {
            uint synFin = (((s.Flags & TcpSegment.SYN) != 0 || (s.Flags & TcpSegment.FIN) != 0) ? 1u : 0u);
            uint ack = s.Seq + (uint)s.PayloadLength + synFin;
            _writeTun(TcpSegment.Build(s.DstIp, s.DstPort, s.SrcIp, s.SrcPort, 0, ack,
                (byte)(TcpSegment.RST | TcpSegment.ACK), 0, null, 0, 0));
        }

        private void Expire(object state)
        {
            List<TcpConnection> dead = null;
            lock (_lock)
            {
                var now = DateTime.UtcNow;
                foreach (var kv in _table)
                    if (now - kv.Value.Last > Idle) (dead ?? (dead = new List<TcpConnection>())).Add(kv.Value.Conn);
            }
            if (dead != null) foreach (var c in dead) { try { c.Close(); } catch { } }
        }

        public void GetCounters(out long opened, out long active, out long closed, out long peak)
        {
            opened = Interlocked.Read(ref _opened);
            closed = Interlocked.Read(ref _closed);
            lock (_lock) { active = _table.Count; peak = _peak; }
        }

        public void Stop()
        {
            try { _expiry.Dispose(); } catch { }
            List<TcpConnection> all;
            lock (_lock) { all = new List<TcpConnection>(); foreach (var kv in _table) all.Add(kv.Value.Conn); _table.Clear(); }
            foreach (var c in all) { try { c.Close(); } catch { } }
        }
    }
}

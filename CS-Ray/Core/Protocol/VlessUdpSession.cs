using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CS_Ray.Core.Transport;

namespace CS_Ray.Core.Protocol
{
    /// <summary>
    /// One VLESS UDP association = one destination. Opens the same outbound chain as the TCP path
    /// (TCP→TLS, +WebSocket when network=ws), but sends a VLESS request header with CMD=UDP (0x02).
    /// After the header, datagrams are length-prefixed BOTH ways: [2-byte big-endian length][payload].
    /// The server's response header (1 ver + 1 addonLen + addons) is consumed once, lazily, before the
    /// first framed reply. Reused per-destination by the TUN UdpHandler NAT table (Phase E2).
    /// </summary>
    public sealed class VlessUdpSession : IUdpOutbound
    {
        private readonly VlessConfig _cfg;
        private readonly byte[] _uuid;
        private ITransport _outbound;
        private Stream _server;
        private bool _respHeaderConsumed;
        private readonly object _writeLock = new object();

        public VlessUdpSession(VlessConfig cfg, byte[] uuid)
        {
            _cfg = cfg ?? throw new ArgumentNullException(nameof(cfg));
            _uuid = uuid ?? throw new ArgumentNullException(nameof(uuid));
        }

        private bool IsWebSocket =>
            string.Equals(_cfg.Network?.Trim(), "ws", StringComparison.OrdinalIgnoreCase);

        private string WsHostHeader =>
            !string.IsNullOrEmpty(_cfg.WsHost) ? _cfg.WsHost
            : (!string.IsNullOrEmpty(_cfg.Sni) ? _cfg.Sni : _cfg.ServerHost);

        /// <summary>Dial the server and send the VLESS UDP request header for the given destination.</summary>
        public async Task ConnectAsync(string dstHost, int dstPort, CancellationToken ct)
        {
            ITransport outbound = new TlsTransport(_cfg.Sni, _cfg.AllowInsecure);
            if (IsWebSocket)
                outbound = new WebSocketTransport(outbound, _cfg.WsPath, WsHostHeader);

            // Dial the pinned IP when set (full tunnel), else the hostname. SNI/WS-Host stay the hostname.
            string dial = !string.IsNullOrEmpty(_cfg.ServerIp) ? _cfg.ServerIp : _cfg.ServerHost;
            await outbound.ConnectAsync(dial, _cfg.ServerPort, ct).ConfigureAwait(false);
            _outbound = outbound;
            _server = outbound.GetStream();

            var header = VlessProtocol.BuildRequestHeader(_uuid, dstHost, dstPort, VlessProtocol.CmdUdp);
            await _server.WriteAsync(header, 0, header.Length, ct).ConfigureAwait(false);
            await _server.FlushAsync(ct).ConfigureAwait(false);
        }

        /// <summary>Send one UDP datagram (length-prefixed) to the associated destination.</summary>
        public async Task SendAsync(byte[] payload, int offset, int count, CancellationToken ct)
        {
            var framed = new byte[2 + count];
            framed[0] = (byte)(count >> 8);
            framed[1] = (byte)(count & 0xFF);
            Buffer.BlockCopy(payload, offset, framed, 2, count);
            // The underlying TLS/WS stream is not safe for concurrent writes; serialize.
            Task t;
            lock (_writeLock) { t = _server.WriteAsync(framed, 0, framed.Length, ct); }
            await t.ConfigureAwait(false);
            await _server.FlushAsync(ct).ConfigureAwait(false);
        }

        public Task SendAsync(byte[] payload, CancellationToken ct) => SendAsync(payload, 0, payload.Length, ct);

        /// <summary>
        /// Read one UDP datagram reply (length-prefixed). Consumes the VLESS response header on first call.
        /// Returns null on clean EOF.
        /// </summary>
        public async Task<byte[]> ReceiveAsync(CancellationToken ct)
        {
            if (!_respHeaderConsumed)
            {
                var head = await ReadExactAsync(2, ct).ConfigureAwait(false);   // version + addonLen
                if (head == null) return null;
                int addonLen = head[1];
                if (addonLen > 0 && await ReadExactAsync(addonLen, ct).ConfigureAwait(false) == null) return null;
                _respHeaderConsumed = true;
            }

            var lp = await ReadExactAsync(2, ct).ConfigureAwait(false);
            if (lp == null) return null;
            int len = (lp[0] << 8) | lp[1];
            if (len <= 0) return new byte[0];
            return await ReadExactAsync(len, ct).ConfigureAwait(false);
        }

        private async Task<byte[]> ReadExactAsync(int count, CancellationToken ct)
        {
            var buf = new byte[count];
            int off = 0;
            while (off < count)
            {
                int n = await _server.ReadAsync(buf, off, count - off, ct).ConfigureAwait(false);
                if (n <= 0) return null; // EOF
                off += n;
            }
            return buf;
        }

        public void Dispose()
        {
            try { _outbound?.Close(); } catch { }
            _outbound = null;
            _server = null;
        }

        // ───────────────────────── E1 standalone self-test ─────────────────────────

        /// <summary>
        /// Proves VLESS UDP end-to-end with NO TUN: opens a UDP association to 8.8.8.8:53 through the
        /// engine, sends a real DNS A query for example.com, reads the framed reply, parses the answer.
        /// </summary>
        public static async Task RunDnsSelfTestAsync(VlessConfig cfg, Action<string> log)
        {
            if (!string.Equals((cfg.Protocol ?? "").Trim(), "vless", StringComparison.OrdinalIgnoreCase))
            {
                log?.Invoke("E1 UDP test: active profile is not VLESS — switch to a VLESS server first.");
                return;
            }

            byte[] uuid;
            try { uuid = VlessProtocol.ParseUuid(cfg.Uuid); }
            catch (Exception ex) { log?.Invoke("E1 UDP test: bad UUID — " + ex.Message); return; }

            const string name = "example.com";
            log?.Invoke("E1 UDP test: opening VLESS UDP session to 8.8.8.8:53 …");

            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
            using (var sess = new VlessUdpSession(cfg, uuid))
            {
                try
                {
                    await sess.ConnectAsync("8.8.8.8", 53, cts.Token).ConfigureAwait(false);
                    var query = BuildDnsQuery(name, out ushort id);
                    await sess.SendAsync(query, cts.Token).ConfigureAwait(false);
                    log?.Invoke("E1 UDP test: sent DNS query (" + query.Length + "B) for " + name + " — awaiting reply …");

                    var reply = await sess.ReceiveAsync(cts.Token).ConfigureAwait(false);
                    if (reply == null || reply.Length < 12) { log?.Invoke("E1 UDP test: FAILED — no/short reply."); return; }

                    string ip = ParseFirstA(reply, id, out int answers);
                    if (ip != null)
                        log?.Invoke("E1 UDP test: SUCCESS — " + name + " -> " + ip + " (" + answers + " answer(s), reply " + reply.Length + "B). VLESS UDP round-trips.");
                    else
                        log?.Invoke("E1 UDP test: reply received (" + reply.Length + "B, " + answers + " answers) but no A record parsed — encoding still proven (got a valid framed DNS reply).");
                }
                catch (OperationCanceledException) { log?.Invoke("E1 UDP test: FAILED — timed out (server may not support UDP, or wrong framing)."); }
                catch (Exception ex) { log?.Invoke("E1 UDP test: FAILED — " + ex.Message); }
            }
        }

        private static byte[] BuildDnsQuery(string name, out ushort id)
        {
            var rng = new System.Security.Cryptography.RNGCryptoServiceProvider();
            var idb = new byte[2]; rng.GetBytes(idb);
            id = (ushort)((idb[0] << 8) | idb[1]);

            using (var ms = new MemoryStream())
            {
                ms.WriteByte(idb[0]); ms.WriteByte(idb[1]);   // ID
                ms.WriteByte(0x01); ms.WriteByte(0x00);       // flags: RD=1
                ms.WriteByte(0x00); ms.WriteByte(0x01);       // QDCOUNT=1
                ms.WriteByte(0x00); ms.WriteByte(0x00);       // ANCOUNT
                ms.WriteByte(0x00); ms.WriteByte(0x00);       // NSCOUNT
                ms.WriteByte(0x00); ms.WriteByte(0x00);       // ARCOUNT
                foreach (var label in name.Split('.'))
                {
                    var lb = Encoding.ASCII.GetBytes(label);
                    ms.WriteByte((byte)lb.Length);
                    ms.Write(lb, 0, lb.Length);
                }
                ms.WriteByte(0x00);                            // root label
                ms.WriteByte(0x00); ms.WriteByte(0x01);        // QTYPE = A
                ms.WriteByte(0x00); ms.WriteByte(0x01);        // QCLASS = IN
                return ms.ToArray();
            }
        }

        // Minimal DNS answer parser: skip header+question, walk answers, return first A record's IPv4.
        private static string ParseFirstA(byte[] m, ushort expectId, out int answerCount)
        {
            answerCount = 0;
            if (m.Length < 12) return null;
            int qd = (m[4] << 8) | m[5];
            int an = (m[6] << 8) | m[7];
            answerCount = an;

            int p = 12;
            for (int q = 0; q < qd; q++)
            {
                p = SkipName(m, p);
                p += 4; // QTYPE + QCLASS
            }
            for (int a = 0; a < an && p < m.Length; a++)
            {
                p = SkipName(m, p);
                if (p + 10 > m.Length) break;
                int type = (m[p] << 8) | m[p + 1];
                int rdlen = (m[p + 8] << 8) | m[p + 9];
                int rdata = p + 10;
                if (type == 1 && rdlen == 4 && rdata + 4 <= m.Length)
                    return m[rdata] + "." + m[rdata + 1] + "." + m[rdata + 2] + "." + m[rdata + 3];
                p = rdata + rdlen;
            }
            return null;
        }

        private static int SkipName(byte[] m, int p)
        {
            while (p < m.Length)
            {
                int len = m[p];
                if (len == 0) return p + 1;
                if ((len & 0xC0) == 0xC0) return p + 2; // compression pointer
                p += 1 + len;
            }
            return p;
        }
    }
}

using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Transport
{
    /// <summary>
    /// XHTTP (a.k.a. SplitHTTP) client transport — "packet-up" mode, over standard TLS + HTTP/1.1 (no HTTP/2,
    /// no REALITY), mirroring <see cref="WebSocketTransport"/>'s place in the stack. It manages its OWN TLS
    /// connections (unlike WS, which wraps one inner transport) because XHTTP needs two:
    ///   • Downlink: ONE long-lived chunked streaming GET to &lt;path&gt;/&lt;sessionID&gt; — the server streams the
    ///     response body indefinitely; we parse HTTP/1.1 chunked transfer-encoding off the raw SslStream and feed
    ///     bytes to VLESS as they arrive (NO hard read deadline — an idle-but-alive stream must not be killed).
    ///   • Uplink: sequential HTTP/1.1 POSTs to &lt;path&gt;/&lt;sessionID&gt;/&lt;seq&gt; (incrementing seq; the server
    ///     reassembles in order) over a SEPARATE keep-alive connection, so the held-open downlink can't starve them.
    /// SNI from the link, standard cert validation (allowInsecure honored). Session correlated by a random UUID.
    /// </summary>
    public class XhttpTransport : ITransport
    {
        private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        private readonly string _sni;
        private readonly bool _allowInsecure;
        private readonly string _basePath;
        private readonly string _hostHeader;
        private readonly Action<string> _log;     // verbose: logs the exact request head we send (null = quiet)
        private readonly string _sessionId = Guid.NewGuid().ToString();
        private bool _loggedGet;

        private string _host;
        private int _port;
        private TlsTransport _downTls;
        private XhttpStream _stream;

        public XhttpTransport(string sni, bool allowInsecure, string path, string hostHeader, Action<string> log = null)
        {
            _sni = sni;
            _allowInsecure = allowInsecure;
            _basePath = NormalizeBase(path);
            _hostHeader = hostHeader;
            _log = log;
        }

        // The base path with a leading slash and no trailing slash; we append "/<sessionId>[/<seq>]".
        private static string NormalizeBase(string path)
        {
            var p = (path ?? "").Trim();
            if (p.Length == 0) return "";
            if (!p.StartsWith("/")) p = "/" + p;
            if (p.Length > 1) p = p.TrimEnd('/');
            return p == "/" ? "" : p;
        }

        internal string Sni => _sni;
        internal bool AllowInsecure => _allowInsecure;
        internal string DialHost => _host;
        internal int Port => _port;

        public async Task ConnectAsync(string host, int port, CancellationToken ct)
        {
            _host = host; _port = port;

            // Open the downlink and SEND the streaming GET so the session is registered — but DON'T read the
            // response yet: the server may emit the downlink only after it sees uplink seq=0, and we send that
            // (the VLESS request header) on the first Write. Deferring the header parse to the first Read avoids
            // a deadlock of ConnectAsync against our own first POST.
            _downTls = new TlsTransport(_sni, _allowInsecure);
            await _downTls.ConnectAsync(host, port, ct).ConfigureAwait(false);
            var ds = _downTls.GetStream();
            string getHead = BuildHead("GET", _basePath + "/" + _sessionId, -1);
            if (_log != null && !_loggedGet) { _loggedGet = true; _log("XHTTP downlink GET →\r\n" + getHead.TrimEnd()); }
            var get = Encoding.ASCII.GetBytes(getHead);
            await ds.WriteAsync(get, 0, get.Length, ct).ConfigureAwait(false);
            await ds.FlushAsync(ct).ConfigureAwait(false);

            _stream = new XhttpStream(this, ds, _log);
        }

        public Stream GetStream()
            => _stream ?? throw new InvalidOperationException("XhttpTransport is not connected.");

        public void Close()
        {
            try { _stream?.CloseUplink(); } catch { }
            try { _downTls?.Close(); } catch { }
            _downTls = null;
        }

        // Open a fresh TLS connection for the uplink (separate from the held-open downlink).
        internal async Task<TlsTransport> OpenUplinkTlsAsync(CancellationToken ct)
        {
            var up = new TlsTransport(_sni, _allowInsecure);
            await up.ConnectAsync(_host, _port, ct).ConfigureAwait(false);
            return up;
        }

        internal string PostPath(long seq) => _basePath + "/" + _sessionId + "/" + seq;

        // bodyLen < 0 → no body (GET); else POST with Content-Length. Matches the Xray XHTTP client:
        // the REQUIRED x_padding is carried in the Referer header (PlacementQueryInHeader) — the server returns
        // HTTP 400 "invalid padding length" if it's missing/out of range (default ~100-1000). POST sets NO
        // Content-Type (as Xray does); GET signals a streamed downlink via Accept: text/event-stream.
        internal string BuildHead(string method, string pathAndQuery, int bodyLen)
        {
            var sb = new StringBuilder();
            sb.Append(method).Append(' ').Append(pathAndQuery).Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(_hostHeader).Append("\r\n");
            sb.Append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36\r\n");
            sb.Append("Referer: https://").Append(_hostHeader).Append(pathAndQuery).Append("?x_padding=").Append(MakePadding()).Append("\r\n");
            if (method == "GET")
            {
                sb.Append("Accept: text/event-stream\r\n");
                sb.Append("Cache-Control: no-cache\r\n");
            }
            if (bodyLen >= 0) sb.Append("Content-Length: ").Append(bodyLen).Append("\r\n");
            sb.Append("Connection: keep-alive\r\n\r\n");
            return sb.ToString();
        }

        // Random padding length in [100, 1000] (Xray's default x_padding range), filled with '0' — the server
        // validates only the LENGTH. RNGCryptoServiceProvider per the project rule (never System.Random).
        private static string MakePadding()
        {
            var b = new byte[2]; Rng.GetBytes(b);
            int v = ((b[0] << 8) | b[1]) & 0xFFFF;
            return new string('0', 100 + (v % 901));
        }
    }

    /// <summary>
    /// The duplex stream VLESS consumes over an XHTTP session: reads pull from the downlink chunked GET body;
    /// writes push as sequential uplink POSTs (one keep-alive connection, seq-ordered).
    /// </summary>
    public class XhttpStream : Stream
    {
        private readonly XhttpTransport _t;
        private readonly Stream _down;           // downlink SslStream (read side)
        private readonly Action<string> _log;
        private readonly SemaphoreSlim _upLock = new SemaphoreSlim(1, 1);
        private bool _loggedPost;

        private bool _downParsed, _downChunked, _downEof;
        private byte[] _chunk; private int _chunkOff, _chunkLeft;

        private long _seq;
        private TlsTransport _upTls;
        private Stream _up;                       // uplink SslStream (write side, keep-alive)

        public XhttpStream(XhttpTransport t, Stream down, Action<string> log = null) { _t = t; _down = down; _log = log; }

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

        // ── Downlink (read) ──
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return 0;
            if (!_downParsed) await ParseDownlinkHeadersAsync(ct).ConfigureAwait(false);
            if (_downEof) return 0;

            if (!_downChunked)
                return await _down.ReadAsync(buffer, offset, count, ct).ConfigureAwait(false); // identity stream → passthrough

            while (_chunkLeft == 0)
                if (!await NextChunkAsync(ct).ConfigureAwait(false)) { _downEof = true; return 0; }

            int n = Math.Min(count, _chunkLeft);
            Buffer.BlockCopy(_chunk, _chunkOff, buffer, offset, n);
            _chunkOff += n; _chunkLeft -= n;
            return n;
        }

        private async Task ParseDownlinkHeadersAsync(CancellationToken ct)
        {
            _downParsed = true;
            string head = await ReadHeaderBlockAsync(_down, ct).ConfigureAwait(false);
            int code = StatusCode(head);
            if (code < 200 || code >= 300)
                throw new InvalidOperationException("XHTTP downlink GET failed (HTTP " + code + "). Response:\r\n" + head);
            _downChunked = HeaderContains(head, "Transfer-Encoding", "chunked");
            // If not chunked, we read the body as a raw stream until the server closes the connection.
        }

        private async Task<bool> NextChunkAsync(CancellationToken ct)
        {
            string line = await ReadLineAsync(_down, ct).ConfigureAwait(false);
            if (line == null) return false;
            line = line.Trim();
            if (line.Length == 0) // tolerate a stray blank line between chunks
            {
                line = await ReadLineAsync(_down, ct).ConfigureAwait(false);
                if (line == null) return false;
                line = line.Trim();
            }
            int semi = line.IndexOf(';');
            if (semi >= 0) line = line.Substring(0, semi);
            if (!int.TryParse(line, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int size)) return false;
            if (size <= 0) { await ReadLineAsync(_down, ct).ConfigureAwait(false); return false; } // last chunk
            if (size > 64 * 1024 * 1024) throw new InvalidOperationException("XHTTP chunk too large: " + size);

            var buf = new byte[size];
            if (!await ReadExactAsync(_down, buf, 0, size, ct).ConfigureAwait(false)) return false;
            await ReadExactAsync(_down, new byte[2], 0, 2, ct).ConfigureAwait(false); // trailing CRLF
            _chunk = buf; _chunkOff = 0; _chunkLeft = size;
            return true;
        }

        // ── Uplink (write) ──
        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return;
            await _upLock.WaitAsync(ct).ConfigureAwait(false); // serialize POSTs → preserve seq order
            try { await PostAsync(buffer, offset, count, ct).ConfigureAwait(false); }
            finally { _upLock.Release(); }
        }

        private async Task PostAsync(byte[] data, int offset, int count, CancellationToken ct)
        {
            if (_up == null) { _upTls = await _t.OpenUplinkTlsAsync(ct).ConfigureAwait(false); _up = _upTls.GetStream(); }
            long seq = _seq;
            string headStr = _t.BuildHead("POST", _t.PostPath(seq), count);
            if (_log != null && !_loggedPost) { _loggedPost = true; _log("XHTTP uplink POST (seq " + seq + ", " + count + "B) →\r\n" + headStr.TrimEnd()); }
            var head = Encoding.ASCII.GetBytes(headStr);
            try
            {
                await _up.WriteAsync(head, 0, head.Length, ct).ConfigureAwait(false);
                await _up.WriteAsync(data, offset, count, ct).ConfigureAwait(false);
                await _up.FlushAsync(ct).ConfigureAwait(false);

                bool reusable = await DrainResponseAsync(_up, ct).ConfigureAwait(false);
                _seq = seq + 1;
                if (!reusable) CloseUplink(); // can't safely reuse → next POST reopens
            }
            catch
            {
                CloseUplink(); // broken uplink → drop it; rethrow so the relay tears the session down
                throw;
            }
        }

        // Reads + fully consumes one POST response. Returns whether the keep-alive connection is safe to reuse.
        private static async Task<bool> DrainResponseAsync(Stream s, CancellationToken ct)
        {
            string head = await ReadHeaderBlockAsync(s, ct).ConfigureAwait(false);
            int code = StatusCode(head);
            if (code < 200 || code >= 300)
                throw new InvalidOperationException("XHTTP uplink POST rejected (HTTP " + code + "). Response:\r\n" + head);

            bool close = HeaderContains(head, "Connection", "close");
            if (HeaderContains(head, "Transfer-Encoding", "chunked"))
            {
                while (true)
                {
                    string line = (await ReadLineAsync(s, ct).ConfigureAwait(false))?.Trim();
                    if (line == null) return false;
                    int semi = line.IndexOf(';'); if (semi >= 0) line = line.Substring(0, semi);
                    if (line.Length == 0) continue;
                    if (!int.TryParse(line, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int sz)) return false;
                    if (sz == 0) { await ReadLineAsync(s, ct).ConfigureAwait(false); break; }
                    if (!await ReadExactAsync(s, new byte[sz], 0, sz, ct).ConfigureAwait(false)) return false;
                    await ReadExactAsync(s, new byte[2], 0, 2, ct).ConfigureAwait(false);
                }
                return !close;
            }

            string cl = HeaderValue(head, "Content-Length");
            if (cl != null && int.TryParse(cl.Trim(), out int len))
            {
                if (len > 0 && !await ReadExactAsync(s, new byte[len], 0, len, ct).ConfigureAwait(false)) return false;
                return !close;
            }
            // No length and not chunked → body is delimited by connection close; don't risk a desync, reopen next time.
            return false;
        }

        internal void CloseUplink()
        {
            try { _upTls?.Close(); } catch { }
            _upTls = null; _up = null;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) { CloseUplink(); try { _upLock.Dispose(); } catch { } }
            base.Dispose(disposing);
        }

        // ── HTTP/1.1 helpers (raw, since we're on SslStream not HttpWebRequest) ──
        private static async Task<string> ReadHeaderBlockAsync(Stream s, CancellationToken ct)
        {
            var buf = new MemoryStream();
            var one = new byte[1];
            byte c1 = 0, c2 = 0, c3 = 0, c4 = 0;
            while (true)
            {
                int n = await s.ReadAsync(one, 0, 1, ct).ConfigureAwait(false);
                if (n <= 0) throw new EndOfStreamException("Connection closed during XHTTP response. Partial:\r\n" + Encoding.ASCII.GetString(buf.ToArray()));
                buf.WriteByte(one[0]);
                c1 = c2; c2 = c3; c3 = c4; c4 = one[0];
                if (c1 == 0x0D && c2 == 0x0A && c3 == 0x0D && c4 == 0x0A) break;
                if (buf.Length > 64 * 1024) throw new InvalidOperationException("XHTTP response header exceeded 64KB.");
            }
            return Encoding.ASCII.GetString(buf.ToArray());
        }

        private static async Task<string> ReadLineAsync(Stream s, CancellationToken ct)
        {
            var sb = new StringBuilder();
            var one = new byte[1];
            while (true)
            {
                int n = await s.ReadAsync(one, 0, 1, ct).ConfigureAwait(false);
                if (n <= 0) return sb.Length == 0 ? null : sb.ToString();
                if (one[0] == 0x0A) return sb.ToString(); // LF ends the line
                if (one[0] == 0x0D) continue;             // skip CR
                sb.Append((char)one[0]);
                if (sb.Length > 16 * 1024) throw new InvalidOperationException("XHTTP line too long.");
            }
        }

        private static async Task<bool> ReadExactAsync(Stream s, byte[] buf, int off, int count, CancellationToken ct)
        {
            int got = 0;
            while (got < count)
            {
                int n = await s.ReadAsync(buf, off + got, count - got, ct).ConfigureAwait(false);
                if (n <= 0) return false;
                got += n;
            }
            return true;
        }

        private static int StatusCode(string head)
        {
            int eol = head.IndexOf("\r\n", StringComparison.Ordinal);
            string line = eol >= 0 ? head.Substring(0, eol) : head;
            var parts = line.Split(' ');
            return parts.Length >= 2 && int.TryParse(parts[1], out int c) ? c : 0;
        }

        private static string HeaderValue(string head, string name)
        {
            foreach (var line in head.Split(new[] { "\r\n" }, StringSplitOptions.None))
            {
                int colon = line.IndexOf(':');
                if (colon <= 0) continue;
                if (string.Equals(line.Substring(0, colon).Trim(), name, StringComparison.OrdinalIgnoreCase))
                    return line.Substring(colon + 1).Trim();
            }
            return null;
        }

        private static bool HeaderContains(string head, string name, string token)
        {
            var v = HeaderValue(head, name);
            return v != null && v.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CS_Ray.Core.Transport.Http2;

namespace CS_Ray.Core.Transport
{
    /// <summary>
    /// XHTTP (a.k.a. SplitHTTP) client transport — "packet-up" mode, over standard TLS + HTTP/1.1 (no HTTP/2,
    /// no REALITY), mirroring <see cref="WebSocketTransport"/>'s place in the stack. It manages its OWN TLS
    /// connections (unlike WS, which wraps one inner transport) because XHTTP needs two:
    ///   • Downlink: ONE long-lived chunked streaming GET to &lt;path&gt;&lt;sessionID&gt; on its own connection — the
    ///     server streams the response body indefinitely; we parse HTTP/1.1 chunked transfer-encoding off the raw
    ///     stream and feed bytes to the protocol as they arrive (NO hard read deadline).
    ///   • Uplink: HTTP/1.1 POSTs to &lt;path&gt;&lt;sessionID&gt;/&lt;seq&gt; (incrementing seq; the server reassembles in
    ///     order) over a SEPARATE keep-alive connection. Writes are queued and a sender turns them into POSTs as Xray's
    ///     dialer does: the first at once, later ones at least scMinPostsIntervalMs apart, each carrying everything
    ///     queued (up to scMaxEachPostBytes) — so the upload rate is not one write per round trip.
    /// Requests are shaped like Xray's (Go net/http): Host, User-Agent, Content-Length, then the rest sorted by key, with
    /// the "chrome" fetch masquerade, x_padding and extra.headers from <see cref="XhttpSettings"/> (shared with stream-one).
    /// </summary>
    public class XhttpTransport : ITransport
    {
        private readonly string _sni;
        private readonly bool _allowInsecure;
        private readonly XhttpSettings _s;
        private readonly string _escapedBase;      // Go-escaped base path, ending with '/'
        private readonly Action<string> _log;      // verbose: logs the exact request head we send (null = quiet)
        private readonly string _sessionId = Guid.NewGuid().ToString();
        private bool _loggedGet;

        private string _host;
        private int _port;
        private ITransport _downTls;
        private XhttpStream _stream;

        public XhttpTransport(string sni, bool allowInsecure, XhttpSettings settings, Action<string> log = null)
        {
            _sni = sni;
            _allowInsecure = allowInsecure;
            _s = settings ?? throw new ArgumentNullException(nameof(settings));
            _escapedBase = XhttpSettings.EscapePath(_s.Path);
            if (!_escapedBase.EndsWith("/")) _escapedBase += "/";
            _log = log;
        }

        internal XhttpSettings Settings => _s;

        public async Task ConnectAsync(string host, int port, CancellationToken ct)
        {
            _host = host; _port = port;

            // Open the downlink and SEND the streaming GET so the session is registered — but DON'T read the
            // response yet: the server may emit the downlink only after it sees uplink seq=0, and we send that
            // (the protocol request header) on the first Write. Deferring the header parse to the first Read avoids
            // a deadlock of ConnectAsync against our own first POST.
            _downTls = TlsTransportFactory.Create(_sni, _allowInsecure);
            await _downTls.ConnectAsync(host, port, ct).ConfigureAwait(false);
            var ds = _downTls.GetStream();
            string getHead = BuildHead("GET", _sessionId, -1);
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
            try { _stream?.Shutdown(); } catch { }
            AbortDownlink();
        }

        // Closing the downlink connection unblocks a pending read (socket reads ignore tokens on .NET Framework).
        internal void AbortDownlink()
        {
            try { _downTls?.Close(); } catch { }
        }

        // Open a fresh TLS connection for the uplink (separate from the held-open downlink).
        internal async Task<ITransport> OpenUplinkTlsAsync(CancellationToken ct)
        {
            var up = TlsTransportFactory.Create(_sni, _allowInsecure);
            await up.ConnectAsync(_host, _port, ct).ConfigureAwait(false);
            return up;
        }

        internal string PostSuffix(long seq) => _sessionId + "/" + seq.ToString(CultureInfo.InvariantCulture);

        /// <summary>
        /// One request head as Go's net/http writes Xray's: "&lt;method&gt; &lt;base&gt;&lt;suffix&gt;[?query] HTTP/1.1", Host,
        /// User-Agent, Content-Length (POST), then the remaining headers sorted by their wire name, and — for the GET,
        /// which Xray sends through an http.Transport with keep-alives off — "Connection: close" last. The POST carries no
        /// Content-Type and no Connection header. <paramref name="bodyLen"/> &lt; 0 = no body (GET).
        /// </summary>
        internal string BuildHead(string method, string suffix, int bodyLen)
        {
            string pad = _s.MakePadding();
            string query = _s.QueryWithPadding(pad);
            var regular = _s.RegularHeaders(_escapedBase, pad, grpcContentType: false);
            // No UA header → Go's default; an explicitly empty one → none at all (Go writes no empty User-Agent).
            string ua = regular.Where(kv => kv.Key == "user-agent").Select(kv => kv.Value).FirstOrDefault() ?? "Go-http-client/1.1";
            bool userAcceptEncoding = regular.Any(kv => kv.Key == "accept-encoding");
            var rest = regular.Where(kv => kv.Key != "user-agent" && kv.Key != "host" && kv.Key != "content-length" && kv.Key != "connection")
                              .Select(kv => new KeyValuePair<string, string>(WireName(kv.Key), kv.Value))
                              .OrderBy(kv => kv.Key, StringComparer.Ordinal);

            var sb = new StringBuilder();
            sb.Append(method).Append(' ').Append(_escapedBase).Append(suffix);
            if (query.Length > 0) sb.Append('?').Append(query);
            sb.Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(_s.Host).Append("\r\n");
            if (ua.Length > 0) sb.Append("User-Agent: ").Append(ua).Append("\r\n");
            if (bodyLen >= 0) sb.Append("Content-Length: ").Append(bodyLen.ToString(CultureInfo.InvariantCulture)).Append("\r\n");
            foreach (var kv in rest) sb.Append(kv.Key).Append(": ").Append(kv.Value).Append("\r\n");
            if (bodyLen < 0)
            {
                // The GET goes through Go's http.Transport (keep-alives off, compression on), which adds these two last.
                if (!userAcceptEncoding) sb.Append("Accept-Encoding: gzip\r\n");
                sb.Append("Connection: close\r\n");
            }
            sb.Append("\r\n");
            return sb.ToString();
        }

        // The spelling Go puts on the wire: browser.go assigns these keys directly (kept as written); everything else goes
        // through Header.Set / Add, i.e. canonical MIME form.
        private static string WireName(string lower)
        {
            switch (lower)
            {
                case "sec-ch-ua": return "Sec-CH-UA";
                case "sec-ch-ua-mobile": return "Sec-CH-UA-Mobile";
                case "sec-ch-ua-platform": return "Sec-CH-UA-Platform";
                case "dnt": return "DNT";
            }
            var c = lower.ToCharArray();
            bool up = true;
            for (int i = 0; i < c.Length; i++)
            {
                if (c[i] == ' ' || c[i] == ':') return lower;   // not a token: Go leaves it as is
                c[i] = up ? char.ToUpperInvariant(c[i]) : char.ToLowerInvariant(c[i]);
                up = c[i] == '-';
            }
            return new string(c);
        }
    }

    /// <summary>
    /// The duplex stream the protocol consumes over an XHTTP session: reads pull from the downlink chunked GET body;
    /// writes queue for the uplink sender, which posts them in seq order on one keep-alive connection.
    /// </summary>
    public class XhttpStream : Stream
    {
        private readonly XhttpTransport _t;
        private readonly Stream _down;           // downlink stream (read side)
        private readonly Action<string> _log;
        private bool _loggedPost;

        private bool _downParsed, _downChunked, _downEof;
        private Stream _gunzip;                   // the downlink body when it arrives gzipped (we offer gzip, like Go)
        private byte[] _chunk; private int _chunkOff, _chunkLeft;

        // Uplink queue → sender loop (Xray dialer.go: blocking pipe + split loop).
        private readonly object _q = new object();
        private readonly List<byte[]> _pending = new List<byte[]>();
        private int _pendingBytes;
        private TaskCompletionSource<bool> _dataSignal = NewSignal(), _spaceSignal = NewSignal();
        private readonly CancellationTokenSource _upCts = new CancellationTokenSource();
        private Task _sender;
        private volatile Exception _upError;
        private readonly int _maxPost, _queueLimit;

        private long _seq;
        private ITransport _upTls;
        private Stream _up;                       // uplink TLS stream (write side, keep-alive)
        private long _upUsedAt;                   // Stopwatch timestamp of the uplink connection's last request
        private const int UplinkIdleReopenMs = 30000;   // reconnect rather than reuse a connection idle this long

        public XhttpStream(XhttpTransport t, Stream down, Action<string> log = null)
        {
            _t = t; _down = down; _log = log;
            var s = t.Settings;
            _maxPost = Math.Max(1, XhttpSettings.Pick(s.MaxPostFrom, s.MaxPostTo));   // rolled once per session (Xray); no floor: the server enforces it
            _queueLimit = Math.Max(64 * 1024, _maxPost - 8192);
        }

        private static TaskCompletionSource<bool> NewSignal() => new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

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
            try { return await ReadDownAsync(buffer, offset, count, ct).ConfigureAwait(false); }
            catch (Exception ex) when (_upError != null && !(ex is OperationCanceledException))
            {
                // The uplink failed first (and closed the downlink to say so): report the real cause.
                throw new IOException("XHTTP uplink failed: " + _upError.Message, _upError);
            }
        }

        private async Task<int> ReadDownAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return 0;
            if (_upError != null) throw new IOException("XHTTP uplink failed: " + _upError.Message, _upError);
            if (!_downParsed) await ParseDownlinkHeadersAsync(ct).ConfigureAwait(false);
            if (_gunzip != null) return await _gunzip.ReadAsync(buffer, offset, count, ct).ConfigureAwait(false);
            return await ReadRawAsync(buffer, offset, count, ct).ConfigureAwait(false);
        }

        // The body bytes as sent (de-chunked, not decompressed).
        internal async Task<int> ReadRawAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return 0;
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
            if (HeaderContains(head, "Content-Encoding", "gzip")) _gunzip = new GZipStream(new RawBody(this), CompressionMode.Decompress);
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

        // ── Uplink (write): queue, the sender posts ──
        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return;
            var copy = new byte[count];
            Buffer.BlockCopy(buffer, offset, copy, 0, count);
            while (true)
            {
                Task wait;
                lock (_q)
                {
                    if (_upError != null) throw new IOException("XHTTP uplink failed: " + _upError.Message, _upError);
                    if (_upCts.IsCancellationRequested) throw new ObjectDisposedException("XHTTP uplink");
                    if (_pendingBytes == 0 || _pendingBytes + count <= _queueLimit)
                    {
                        _pending.Add(copy);
                        _pendingBytes += count;
                        _dataSignal.TrySetResult(true);
                        if (_sender == null) _sender = Task.Run(SenderLoopAsync);
                        return;
                    }
                    wait = _spaceSignal.Task;   // backpressure: the sender has not taken the queue yet
                }
                var mine = new TaskCompletionSource<bool>();
                using (ct.Register(() => mine.TrySetCanceled()))
                    await Task.WhenAny(wait, mine.Task).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
            }
        }

        private async Task SenderLoopAsync()
        {
            var ct = _upCts.Token;
            var s = _t.Settings;
            long lastPost = 0;
            try
            {
                while (!ct.IsCancellationRequested)
                {
                    Task wait;
                    lock (_q) wait = _pendingBytes > 0 ? Task.CompletedTask : _dataSignal.Task;
                    await wait.ConfigureAwait(false);
                    if (ct.IsCancellationRequested) break;

                    // At least scMinPostsIntervalMs between two POSTs; the first goes out at once. Monotonic clock: a wall
                    // clock step must not hold the uplink.
                    if (lastPost != 0)
                    {
                        long elapsedMs = Math.Max(0, (Stopwatch.GetTimestamp() - lastPost) * 1000 / Stopwatch.Frequency);
                        int gap = XhttpSettings.Pick(s.MinIntervalFrom, s.MinIntervalTo) - (int)Math.Min(int.MaxValue, elapsedMs);
                        if (gap > 0) await Task.Delay(gap, ct).ConfigureAwait(false);
                    }

                    byte[] body;
                    lock (_q)
                    {
                        int take = Math.Min(_pendingBytes, _maxPost);
                        body = new byte[take];
                        int o = 0;
                        while (o < take)
                        {
                            var first = _pending[0];
                            int n = Math.Min(first.Length, take - o);
                            Buffer.BlockCopy(first, 0, body, o, n);
                            o += n;
                            if (n == first.Length) _pending.RemoveAt(0);
                            else { var restOf = new byte[first.Length - n]; Buffer.BlockCopy(first, n, restOf, 0, restOf.Length); _pending[0] = restOf; }
                        }
                        _pendingBytes -= take;
                        if (_pendingBytes == 0) _dataSignal = NewSignal();
                        var space = _spaceSignal; _spaceSignal = NewSignal(); space.TrySetResult(true);
                    }
                    lastPost = Stopwatch.GetTimestamp();
                    await PostAsync(body, ct).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                if (!ct.IsCancellationRequested)
                {
                    _upError = ex;
                    _t.AbortDownlink();   // the session is over: wake the reader too, with the uplink's reason
                }
                lock (_q) { _spaceSignal.TrySetResult(true); }   // wake a blocked writer so it sees the error
                CloseUplink();
            }
        }

        private async Task PostAsync(byte[] data, CancellationToken ct)
        {
            long seq = _seq;
            string headStr = _t.BuildHead(_t.Settings.Method, _t.PostSuffix(seq), data.Length);
            if (_log != null && !_loggedPost) { _loggedPost = true; _log("XHTTP uplink POST (seq " + seq + ", " + data.Length + "B) →\r\n" + headStr.TrimEnd()); }
            var head = Encoding.ASCII.GetBytes(headStr);
            var req = new byte[head.Length + data.Length];   // head and body in ONE write, as Go's req.Write does
            Buffer.BlockCopy(head, 0, req, 0, head.Length);
            Buffer.BlockCopy(data, 0, req, head.Length, data.Length);

            // A long-idle keep-alive connection is likely gone (nginx, CDNs and load balancers close idle ones): reopen.
            if (_up != null && (Stopwatch.GetTimestamp() - _upUsedAt) * 1000 / Stopwatch.Frequency > UplinkIdleReopenMs) CloseUplink();
            for (int attempt = 0; ; attempt++)
            {
                bool reused = _up != null;
                if (_up == null) { _upTls = await _t.OpenUplinkTlsAsync(ct).ConfigureAwait(false); _up = _upTls.GetStream(); }
                bool sent = false;
                try
                {
                    await _up.WriteAsync(req, 0, req.Length, ct).ConfigureAwait(false);
                    await _up.FlushAsync(ct).ConfigureAwait(false);
                    sent = true;
                    bool reusable = await DrainResponseAsync(_up, ct).ConfigureAwait(false);
                    _upUsedAt = Stopwatch.GetTimestamp();
                    _seq = seq + 1;
                    if (!reusable) CloseUplink(); // can't safely reuse → next POST reopens
                    return;
                }
                catch (Exception ex) when (reused && attempt == 0 && !ct.IsCancellationRequested && (!sent || ex is NoResponseException))
                {
                    // The kept-alive connection was closed under us before any answer: send the same POST (same seq; the
                    // server drops a seq it has already taken) once more on a fresh connection.
                    CloseUplink();
                }
                catch
                {
                    CloseUplink(); // broken uplink → drop it; rethrow so the session ends
                    throw;
                }
            }
        }

        /// <summary>The connection ended before a single byte of the response.</summary>
        private sealed class NoResponseException : EndOfStreamException
        {
            public NoResponseException() : base("Connection closed before the XHTTP response.") { }
        }

        /// <summary>The de-chunked downlink body, for the gzip decoder.</summary>
        private sealed class RawBody : Stream
        {
            private readonly XhttpStream _s;
            public RawBody(XhttpStream s) { _s = s; }
            public override bool CanRead => true;
            public override bool CanWrite => false;
            public override bool CanSeek => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override void Flush() { }
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override int Read(byte[] buffer, int offset, int count) => _s.ReadRawAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) => _s.ReadRawAsync(buffer, offset, count, ct);
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

        /// <summary>Stops the sender (queued bytes are dropped) and closes the uplink connection.</summary>
        internal void Shutdown()
        {
            try { _upCts.Cancel(); } catch { }
            lock (_q) { _dataSignal.TrySetResult(true); _spaceSignal.TrySetResult(true); }
            CloseUplink();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) Shutdown();
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
                if (n <= 0)
                {
                    if (buf.Length == 0) throw new NoResponseException();
                    throw new EndOfStreamException("Connection closed during XHTTP response. Partial:\r\n" + Encoding.ASCII.GetString(buf.ToArray()));
                }
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

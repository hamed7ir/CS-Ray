using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Transport
{
    /// <summary>
    /// WebSocket (RFC6455) client transport, shaped like Xray's (transport/internet/websocket): it connects the inner
    /// transport (e.g. <see cref="TlsTransport"/> for security=tls), sends the upgrade with Xray's default Chrome "ws"
    /// header masquerade in Go's header order, then exposes a <see cref="WebSocketFrameStream"/> that frames/masks all
    /// subsequent traffic. An "ed=N" query parameter in the path is Xray early data: it is not sent as part of the path;
    /// the upgrade waits for the first write, and a first write of at most N bytes rides in Sec-WebSocket-Protocol.
    /// </summary>
    public class WebSocketTransport : ITransport
    {
        private const string WsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        private const int HandshakeTimeoutMs = 8000;   // Xray's websocket.Dialer HandshakeTimeout
        private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        private readonly ITransport _inner;
        private readonly string _path;
        private readonly int _earlyData;
        private readonly string _hostHeader;
        private WebSocketFrameStream _frameStream;

        /// <param name="inner">Underlying transport (connected during <see cref="ConnectAsync"/>).</param>
        /// <param name="path">Configured path (defaults to "/"); an "ed" query parameter enables early data.</param>
        /// <param name="hostHeader">Value for the HTTP Host header (wsHost ?? sni ?? server).</param>
        public WebSocketTransport(ITransport inner, string path, string hostHeader)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            if (string.IsNullOrEmpty(path)) path = "/";
            if (path[0] != '/') path = "/" + path;   // Xray GetNormalizedPath
            _path = RequestTarget(SplitEarlyData(path, out _earlyData));
            _hostHeader = Http2.XhttpSettings.AsciiHost(hostHeader);   // an IDN host goes out as punycode (Go)
        }

        public async Task ConnectAsync(string host, int port, CancellationToken ct)
        {
            await _inner.ConnectAsync(host, port, ct).ConfigureAwait(false);
            var stream = _inner.GetStream();
            if (_earlyData > 0)
            {
                // Xray delayDialConn: no upgrade until the first write, which rides in it when it fits.
                _frameStream = new WebSocketFrameStream(stream, _earlyData, (ed, c) => UpgradeAsync(stream, ed, c));
                return;
            }
            await UpgradeAsync(stream, null, ct).ConfigureAwait(false);
            _frameStream = new WebSocketFrameStream(stream);
        }

        public Stream GetStream()
        {
            if (_frameStream == null)
                throw new InvalidOperationException("WebSocketTransport is not connected.");
            return _frameStream;
        }

        public void Close()
        {
            _frameStream?.AbandonUpgrade();   // a reader parked on a deferred upgrade must not wait forever
            _inner.Close();
        }

        /// <summary>
        /// Xray (infra/conf WebSocketConfig.Build): a non-empty "ed" query parameter is removed from the request path and
        /// sets the early-data limit (non-numeric → 0); every other parameter stays, ordered by key the way Go's
        /// url.Values.Encode writes them. A path without "ed" is returned untouched.
        /// </summary>
        internal static string SplitEarlyData(string path, out int earlyData)
        {
            earlyData = 0;
            int q = path.IndexOf('?');
            if (q < 0) return path;
            var parts = path.Substring(q + 1).Split('&').Where(x => x.Length > 0).ToList();
            Func<string, string> keyOf = x => Unescape(x.IndexOf('=') < 0 ? x : x.Substring(0, x.IndexOf('=')));
            string first = parts.FirstOrDefault(x => keyOf(x) == "ed");
            string value = first == null || first.IndexOf('=') < 0 ? "" : Unescape(first.Substring(first.IndexOf('=') + 1));
            if (value.Length == 0) return path;   // Go: q.Get("ed") == "" → nothing changes
            if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int n)) earlyData = n;
            var kept = parts.Where(x => keyOf(x) != "ed").OrderBy(keyOf, StringComparer.Ordinal).ToList();
            return path.Substring(0, q) + (kept.Count > 0 ? "?" + string.Join("&", kept) : "");
        }

        /// <summary>
        /// The request target as Go writes it (url.Parse + Request.Write → RequestURI): a fragment is dropped; a path that
        /// is already validly escaped is kept as-is, otherwise it is unescaped and every byte outside Go's encodePath set
        /// becomes %XX (UTF-8); the query keeps its text, with spaces / control / non-ASCII bytes %-escaped so the request
        /// line stays one ASCII token.
        /// </summary>
        internal static string RequestTarget(string path)
        {
            int hash = path.IndexOf('#');
            if (hash >= 0) path = path.Substring(0, hash);
            int q = path.IndexOf('?');
            string p = q >= 0 ? path.Substring(0, q) : path, query = q >= 0 ? path.Substring(q) : "";
            if (!ValidEncodedPath(p))
            {
                var sb = new StringBuilder();
                foreach (byte b in PercentDecode(p))
                    if (b < 128 && KeptInPath((char)b)) sb.Append((char)b);
                    else sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
                p = sb.ToString();
            }
            var qs = new StringBuilder();
            foreach (byte b in Encoding.UTF8.GetBytes(query))
                if (b > 0x20 && b < 0x7F) qs.Append((char)b);
                else qs.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
            return p + qs;
        }

        // Go net/url shouldEscape(c, encodePath) == false.
        private static bool KeptInPath(char c)
            => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "-_.~$&+,/:;=@".IndexOf(c) >= 0;

        // Go net/url validEncoded(s, encodePath), plus well-formed %XX triples.
        private static bool ValidEncodedPath(string s)
        {
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '%')
                {
                    if (i + 2 >= s.Length || !IsHex(s[i + 1]) || !IsHex(s[i + 2])) return false;
                    i += 2;
                    continue;
                }
                if (KeptInPath(c) || "!'()*[]".IndexOf(c) >= 0) continue;
                return false;
            }
            return true;
        }

        // UTF-8 bytes of s with every well-formed %XX turned into its byte (a stray '%' stays a byte).
        private static byte[] PercentDecode(string s)
        {
            var src = Encoding.UTF8.GetBytes(s);
            var outp = new System.Collections.Generic.List<byte>(src.Length);
            for (int i = 0; i < src.Length; i++)
            {
                if (src[i] == (byte)'%' && i + 2 < src.Length && IsHex((char)src[i + 1]) && IsHex((char)src[i + 2]))
                {
                    outp.Add(byte.Parse(((char)src[i + 1]).ToString() + (char)src[i + 2], NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                    i += 2;
                }
                else outp.Add(src[i]);
            }
            return outp.ToArray();
        }

        private static bool IsHex(char c) => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

        private static string Unescape(string s)
        {
            try { return Uri.UnescapeDataString(s.Replace('+', ' ')); } catch { return s; }
        }

        /// <summary>The upgrade request Xray's client sends: Host, User-Agent, then the remaining headers sorted by key
        /// (Go's Request.Write), with the "chrome" + "ws" masquerade of transport/internet/browser.go.</summary>
        internal static string BuildUpgradeRequest(string path, string host, string key, byte[] earlyData)
        {
            var sb = new StringBuilder();
            Action<string, string> h = (n, v) => sb.Append(n).Append(": ").Append(v).Append("\r\n");
            sb.Append("GET ").Append(path).Append(" HTTP/1.1\r\n");
            h("Host", host);
            h("User-Agent", BrowserHeaders.ChromeUserAgent);
            h("Accept", "*/*");
            h("Accept-Language", "en-US,en;q=0.9");
            h("Cache-Control", "no-cache");
            h("Connection", "Upgrade");
            h("DNT", "1");
            h("Pragma", "no-cache");
            h("Sec-CH-UA", BrowserHeaders.ChromeSecChUa);
            h("Sec-CH-UA-Mobile", "?0");
            h("Sec-CH-UA-Platform", "\"Windows\"");
            h("Sec-Fetch-Dest", "empty");
            h("Sec-Fetch-Mode", "websocket");
            h("Sec-Fetch-Site", "same-origin");
            h("Sec-WebSocket-Key", key);
            if (earlyData != null && earlyData.Length > 0)   // base64url without padding (Go RawURLEncoding)
                h("Sec-WebSocket-Protocol", Convert.ToBase64String(earlyData).TrimEnd('=').Replace('+', '-').Replace('/', '_'));
            h("Sec-WebSocket-Version", "13");
            h("Upgrade", "websocket");
            sb.Append("\r\n");
            return sb.ToString();
        }

        /// <summary>Sends the upgrade (carrying <paramref name="earlyData"/> when given) and checks the 101 answer. Gives up
        /// after Xray's 8 s handshake timeout by closing the connection (blocking reads ignore tokens on .NET Framework).</summary>
        private async Task UpgradeAsync(Stream stream, byte[] earlyData, CancellationToken ct)
        {
            // 16 random bytes (RNGCryptoServiceProvider, never System.Random), base64-encoded.
            var keyBytes = new byte[16];
            Rng.GetBytes(keyBytes);
            var key = Convert.ToBase64String(keyBytes);
            var req = Encoding.ASCII.GetBytes(BuildUpgradeRequest(_path, _hostHeader, key, earlyData));

            string response;
            using (var hs = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                hs.CancelAfter(HandshakeTimeoutMs);
                using (hs.Token.Register(() => { try { _inner.Close(); } catch { } }))
                {
                    try
                    {
                        await stream.WriteAsync(req, 0, req.Length, hs.Token).ConfigureAwait(false);
                        await stream.FlushAsync(hs.Token).ConfigureAwait(false);
                        response = await ReadResponseHeaderAsync(stream, hs.Token).ConfigureAwait(false);
                    }
                    catch (Exception) when (hs.IsCancellationRequested && !ct.IsCancellationRequested)
                    {
                        throw new TimeoutException("WebSocket upgrade got no answer within " + HandshakeTimeoutMs / 1000 + " s.");
                    }
                }
            }

            // Status line must be 101 Switching Protocols.
            int firstEol = response.IndexOf("\r\n", StringComparison.Ordinal);
            string statusLine = firstEol >= 0 ? response.Substring(0, firstEol) : response;
            if (statusLine.IndexOf(" 101", StringComparison.Ordinal) < 0)
                throw new InvalidOperationException(
                    "WebSocket handshake failed (expected HTTP 101). Full response:\r\n" + response);

            // Sec-WebSocket-Accept must equal base64(SHA1(key + magic)).
            string expected;
            using (var sha1 = SHA1.Create())
                expected = Convert.ToBase64String(sha1.ComputeHash(Encoding.ASCII.GetBytes(key + WsMagic)));

            var accept = ExtractHeader(response, "Sec-WebSocket-Accept");
            if (accept == null || !string.Equals(accept, expected, StringComparison.Ordinal))
                throw new InvalidOperationException(
                    "WebSocket Sec-WebSocket-Accept mismatch (expected " + expected +
                    ", got " + (accept ?? "<none>") + "). Full response:\r\n" + response);
        }

        /// <summary>Reads the HTTP response one byte at a time up to the CRLFCRLF terminator (never over-reads into frame data).</summary>
        private static async Task<string> ReadResponseHeaderAsync(Stream stream, CancellationToken ct)
        {
            var buf = new MemoryStream();
            var one = new byte[1];
            byte c1 = 0, c2 = 0, c3 = 0, c4 = 0;
            while (true)
            {
                int n = await stream.ReadAsync(one, 0, 1, ct).ConfigureAwait(false);
                if (n <= 0)
                    throw new EndOfStreamException(
                        "Connection closed during WebSocket handshake. Partial response:\r\n" +
                        Encoding.ASCII.GetString(buf.ToArray()));

                buf.WriteByte(one[0]);
                c1 = c2; c2 = c3; c3 = c4; c4 = one[0];
                if (c1 == 0x0D && c2 == 0x0A && c3 == 0x0D && c4 == 0x0A)
                    break;

                if (buf.Length > 64 * 1024)
                    throw new InvalidOperationException("WebSocket handshake response exceeded 64KB without terminator.");
            }
            return Encoding.ASCII.GetString(buf.ToArray());
        }

        private static string ExtractHeader(string response, string name)
        {
            var lines = response.Split(new[] { "\r\n" }, StringSplitOptions.None);
            foreach (var line in lines)
            {
                int colon = line.IndexOf(':');
                if (colon <= 0) continue;
                if (string.Equals(line.Substring(0, colon).Trim(), name, StringComparison.OrdinalIgnoreCase))
                    return line.Substring(colon + 1).Trim();
            }
            return null;
        }
    }

    /// <summary>
    /// A duplex <see cref="Stream"/> over a post-handshake WebSocket connection.
    /// Each write becomes one masked binary frame (FIN set). Reads parse RFC6455
    /// frames and retain undelivered payload bytes across calls (frames do not align
    /// with caller buffers). Control frames are handled minimally (close → EOF;
    /// ping/pong skipped).
    /// </summary>
    public class WebSocketFrameStream : Stream
    {
        private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        private readonly Stream _inner;
        private byte[] _leftover;
        private int _leftoverOffset;
        private int _leftoverCount;
        private bool _closed;

        // Frame writes are serialised: the reader answers pings while a data write may be in flight.
        private readonly SemaphoreSlim _writeLock = new SemaphoreSlim(1, 1);

        // Deferred upgrade (Xray early data): run by the first write; reads wait for it.
        private readonly Func<byte[], CancellationToken, Task> _upgrade;
        private readonly int _earlyMax;
        private readonly TaskCompletionSource<bool> _upgraded = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _upgradeClaimed;

        public WebSocketFrameStream(Stream inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _upgraded.TrySetResult(true);
        }

        /// <summary>A stream whose WebSocket upgrade has not happened yet: <paramref name="upgrade"/> runs on the first
        /// write, carrying that write as early data when it is 1..<paramref name="earlyMax"/> bytes (Xray sends a longer
        /// first write normally, with no early data at all).</summary>
        internal WebSocketFrameStream(Stream inner, int earlyMax, Func<byte[], CancellationToken, Task> upgrade)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _earlyMax = earlyMax;
            _upgrade = upgrade ?? throw new ArgumentNullException(nameof(upgrade));
        }

        /// <summary>Fails a still-pending deferred upgrade (the transport is closing) so parked readers return.</summary>
        internal void AbandonUpgrade() => _upgraded.TrySetException(new IOException("WebSocket closed before its upgrade."));

        // True when the write was carried whole as early data (nothing left to frame).
        private async Task<bool> UpgradeOnFirstWriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (Interlocked.Exchange(ref _upgradeClaimed, 1) != 0) { await WaitUpgradedAsync(ct).ConfigureAwait(false); return false; }
            byte[] early = null;
            if (count <= _earlyMax) { early = new byte[count]; Buffer.BlockCopy(buffer, offset, early, 0, count); }
            try { await _upgrade(early, ct).ConfigureAwait(false); }
            catch (Exception ex) { _upgraded.TrySetException(ex); throw; }
            _upgraded.TrySetResult(true);
            return early != null;
        }

        private async Task WaitUpgradedAsync(CancellationToken ct)
        {
            var t = _upgraded.Task;
            if (!t.IsCompleted)
            {
                var cancelled = new TaskCompletionSource<bool>();
                using (ct.Register(() => cancelled.TrySetCanceled()))
                    await Task.WhenAny(t, cancelled.Task).ConfigureAwait(false);
                ct.ThrowIfCancellationRequested();
            }
            await t.ConfigureAwait(false);   // rethrows a failed / abandoned upgrade
        }

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => _inner.Flush();
        public override Task FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return 0;
            if (_upgrade != null) await WaitUpgradedAsync(ct).ConfigureAwait(false);

            // Refill from the next data frame(s) if nothing is buffered.
            while (_leftoverCount == 0)
            {
                var payload = await ReadNextDataFrameAsync(ct).ConfigureAwait(false);
                if (payload == null) return 0; // close / EOF
                _leftover = payload;
                _leftoverOffset = 0;
                _leftoverCount = payload.Length;
                // empty data frame → loop and read the next one
            }

            int toCopy = Math.Min(count, _leftoverCount);
            Buffer.BlockCopy(_leftover, _leftoverOffset, buffer, offset, toCopy);
            _leftoverOffset += toCopy;
            _leftoverCount -= toCopy;
            return toCopy;
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return;
            if (_upgrade != null)
            {
                if (!_upgraded.Task.IsCompleted) { if (await UpgradeOnFirstWriteAsync(buffer, offset, count, ct).ConfigureAwait(false)) return; }
                else await _upgraded.Task.ConfigureAwait(false);   // rethrows a failed upgrade
            }
            var frame = BuildClientFrame(0x82, buffer, offset, count);
            await _writeLock.WaitAsync(ct).ConfigureAwait(false);
            try { await _inner.WriteAsync(frame, 0, frame.Length, ct).ConfigureAwait(false); }
            finally { _writeLock.Release(); }
        }

        // RFC 6455 §5.5.2: a Ping is answered with a Pong carrying its payload (gorilla — Xray's client — does). Sent off the
        // read path so a reader is never stuck behind a data write blocked on a full send buffer.
        private void SendPong(byte[] payload)
        {
            if (_closed || payload.Length > 125) return;
            var frame = BuildClientFrame(0x8A, payload, 0, payload.Length);
            var t = Task.Run(async () =>
            {
                await _writeLock.WaitAsync().ConfigureAwait(false);
                try
                {
                    await _inner.WriteAsync(frame, 0, frame.Length).ConfigureAwait(false);
                    await _inner.FlushAsync().ConfigureAwait(false);
                }
                finally { _writeLock.Release(); }
            });
            t.ContinueWith(x => { var unused = x.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
        }

        /// <summary>Reads frames until a data frame arrives; returns its (unmasked) payload, or null on close/EOF.</summary>
        private async Task<byte[]> ReadNextDataFrameAsync(CancellationToken ct)
        {
            while (true)
            {
                if (_closed) return null;

                var h = await ReadExactAsync(2, ct).ConfigureAwait(false);
                if (h == null) return null;

                int opcode = h[0] & 0x0F;
                bool masked = (h[1] & 0x80) != 0;
                long len = h[1] & 0x7F;

                if (len == 126)
                {
                    var e = await ReadExactAsync(2, ct).ConfigureAwait(false);
                    if (e == null) return null;
                    len = (e[0] << 8) | e[1];
                }
                else if (len == 127)
                {
                    var e = await ReadExactAsync(8, ct).ConfigureAwait(false);
                    if (e == null) return null;
                    len = 0;
                    for (int i = 0; i < 8; i++) len = (len << 8) | e[i];
                }

                if (len < 0 || len > 64L * 1024 * 1024)
                    throw new InvalidOperationException("WebSocket frame length out of range: " + len);

                byte[] mask = null;
                if (masked)
                {
                    mask = await ReadExactAsync(4, ct).ConfigureAwait(false);
                    if (mask == null) return null;
                }

                byte[] payload;
                if (len == 0)
                {
                    payload = Array.Empty<byte>();
                }
                else
                {
                    payload = await ReadExactAsync((int)len, ct).ConfigureAwait(false);
                    if (payload == null) return null;
                    if (masked)
                        for (int i = 0; i < payload.Length; i++) payload[i] ^= mask[i & 3];
                }

                switch (opcode)
                {
                    case 0x0: // continuation
                    case 0x1: // text
                    case 0x2: // binary
                        return payload;
                    case 0x8: // close
                        _closed = true;
                        return null;
                    case 0x9: // ping
                        SendPong(payload);
                        continue;
                    case 0xA: // pong
                    default:  // unknown control — skip and keep reading
                        continue;
                }
            }
        }

        private async Task<byte[]> ReadExactAsync(int count, CancellationToken ct)
        {
            var buf = new byte[count];
            int off = 0;
            while (off < count)
            {
                int n = await _inner.ReadAsync(buf, off, count - off, ct).ConfigureAwait(false);
                if (n <= 0) return null; // EOF (clean or mid-frame) → end the stream
                off += n;
            }
            return buf;
        }

        // FIN + opcode (0x82 binary, 0x8A pong), mask bit set, 4-byte random mask, masked payload.
        private static byte[] BuildClientFrame(byte first, byte[] data, int offset, int count)
        {
            var mask = new byte[4];
            Rng.GetBytes(mask);

            int lenFieldBytes = count < 126 ? 0 : (count <= 0xFFFF ? 2 : 8);
            var frame = new byte[2 + lenFieldBytes + 4 + count];
            int pos = 0;

            frame[pos++] = first; // FIN=1 + opcode

            if (count < 126)
            {
                frame[pos++] = (byte)(0x80 | count);
            }
            else if (count <= 0xFFFF)
            {
                frame[pos++] = 0x80 | 126;
                frame[pos++] = (byte)(count >> 8);
                frame[pos++] = (byte)(count & 0xFF);
            }
            else
            {
                frame[pos++] = 0x80 | 127;
                long c = count;
                for (int i = 7; i >= 0; i--) frame[pos++] = (byte)((c >> (8 * i)) & 0xFF);
            }

            Buffer.BlockCopy(mask, 0, frame, pos, 4);
            pos += 4;

            for (int i = 0; i < count; i++)
                frame[pos + i] = (byte)(data[offset + i] ^ mask[i & 3]);

            return frame;
        }
    }
}

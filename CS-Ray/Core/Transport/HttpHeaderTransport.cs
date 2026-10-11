using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Transport
{
    /// <summary>
    /// Xray / V2Ray TCP "http" header camouflage (<c>tcpSettings.header.type = "http"</c>; share links
    /// <c>type=tcp&amp;headerType=http&amp;host=…&amp;path=…</c>), client side — a port of
    /// <c>transport/internet/headers/http</c>: the first write is preceded by a fake HTTP/1.1 request, the first read
    /// strips the server's fake HTTP response header, and everything after is the raw protocol stream. Wraps whatever
    /// is underneath (plain TCP, or TLS — Xray applies the header inside TLS too).
    ///
    /// The server only checks the request PATH (it must be one of its configured paths) — a mismatch, or a stream that
    /// isn't an HTTP request at all, gets Xray's fixed "400 Bad Request" + close. Host / User-Agent / the rest are
    /// camouflage; when the link carries no host, Xray's own defaults are used.
    /// </summary>
    public sealed class HttpHeaderTransport : ITransport
    {
        // Xray's built-in request defaults (infra/conf AuthenticatorRequest.Build).
        private static readonly string[] DefaultHosts = { "www.baidu.com", "www.bing.com" };
        private static readonly string[] DefaultUserAgents =
        {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/53.0.2785.109 Mobile/14A456 Safari/601.1.46"
        };

        private readonly ITransport _inner;
        private readonly string[] _hosts, _paths;
        private HttpHeaderStream _stream;

        /// <param name="inner">The connection to camouflage (TCP or TLS).</param>
        /// <param name="hosts">Comma-separated Host values from the link (empty → Xray defaults); one is picked per connection.</param>
        /// <param name="paths">Comma-separated request paths from the link (empty → "/"); one is picked per connection.</param>
        public HttpHeaderTransport(ITransport inner, string hosts, string paths)
        {
            _inner = inner;
            _hosts = SplitList(hosts, DefaultHosts);
            _paths = SplitList(paths, new[] { "/" });
            for (int i = 0; i < _paths.Length; i++) if (!_paths[i].StartsWith("/", StringComparison.Ordinal)) _paths[i] = "/" + _paths[i];
        }

        public async Task ConnectAsync(string host, int port, CancellationToken ct)
        {
            await _inner.ConnectAsync(host, port, ct).ConfigureAwait(false);
            _stream = new HttpHeaderStream(_inner.GetStream(), BuildRequestHeader());
        }

        public Stream GetStream()
        {
            if (_stream == null) throw new InvalidOperationException("HttpHeaderTransport is not connected.");
            return _stream;
        }

        public void Close()
        {
            try { _stream?.Dispose(); } catch { }
            _stream = null;
            _inner.Close();
        }

        /// <summary>The fake request Xray's client sends: "GET {path} HTTP/1.1" + its default header set.</summary>
        internal byte[] BuildRequestHeader()
        {
            var sb = new StringBuilder();
            sb.Append("GET ").Append(Pick(_paths)).Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(Pick(_hosts)).Append("\r\n");
            sb.Append("User-Agent: ").Append(Pick(DefaultUserAgents)).Append("\r\n");
            sb.Append("Accept-Encoding: gzip, deflate\r\n");
            sb.Append("Connection: keep-alive\r\n");
            sb.Append("Pragma: no-cache\r\n");
            sb.Append("\r\n");
            return Encoding.UTF8.GetBytes(sb.ToString());   // Xray writes the configured path/host bytes as-is (UTF-8)
        }

        private static string[] SplitList(string csv, string[] fallback)
        {
            if (string.IsNullOrWhiteSpace(csv)) return (string[])fallback.Clone();
            var parts = csv.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            int n = 0;
            for (int i = 0; i < parts.Length; i++) { var t = parts[i].Trim(); if (t.Length > 0) parts[n++] = t; }
            if (n == 0) return (string[])fallback.Clone();
            Array.Resize(ref parts, n);
            return parts;
        }

        private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        private static string Pick(string[] options)
        {
            if (options.Length == 1) return options[0];
            var b = new byte[4];
            lock (Rng) Rng.GetBytes(b);
            return options[(int)(BitConverter.ToUInt32(b, 0) % (uint)options.Length)];
        }
    }

    /// <summary>Prepends the fake request to the FIRST write; strips the fake response header on the FIRST read
    /// (bytes after it are kept and served first). Pass-through afterwards. One writer starts the stream (the protocol
    /// header) and one reader consumes it, as everywhere in the engine.</summary>
    internal sealed class HttpHeaderStream : Stream
    {
        private const int MaxHeader = 8192;   // Xray's maxHeaderLength
        private static readonly byte[] Ending = { 13, 10, 13, 10 };

        private readonly Stream _inner;
        private byte[] _pendingRequest;        // sent with the first write, then null
        private bool _responseParsed;
        private byte[] _left; private int _leftOff, _leftLen;   // payload bytes that arrived with the response header

        public HttpHeaderStream(Stream inner, byte[] requestHeader)
        {
            _inner = inner;
            _pendingRequest = requestHeader;
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            byte[] head = Interlocked.Exchange(ref _pendingRequest, null);
            if (head == null) { await _inner.WriteAsync(buffer, offset, count, ct).ConfigureAwait(false); return; }
            var first = new byte[head.Length + count];       // one write: header + first payload (one TCP segment)
            Buffer.BlockCopy(head, 0, first, 0, head.Length);
            Buffer.BlockCopy(buffer, offset, first, head.Length, count);
            await _inner.WriteAsync(first, 0, first.Length, ct).ConfigureAwait(false);
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (!_responseParsed) await ReadResponseHeaderAsync(ct).ConfigureAwait(false);
            if (_leftLen > 0)
            {
                int n = Math.Min(count, _leftLen);
                Buffer.BlockCopy(_left, _leftOff, buffer, offset, n);
                _leftOff += n; _leftLen -= n;
                if (_leftLen == 0) _left = null;
                return n;
            }
            return await _inner.ReadAsync(buffer, offset, count, ct).ConfigureAwait(false);
        }

        // Accumulate until "\r\n\r\n"; the server's fake response must be an HTTP status line. A 4xx/5xx is Xray
        // rejecting our request (usually a path the server doesn't list) — surface that clearly instead of garbage.
        private async Task ReadResponseHeaderAsync(CancellationToken ct)
        {
            var acc = new byte[MaxHeader + 4096];
            int len = 0;
            while (true)
            {
                int n = await _inner.ReadAsync(acc, len, acc.Length - len, ct).ConfigureAwait(false);
                if (n <= 0)
                {
                    if (len == 0) { _responseParsed = true; return; }   // closed before replying → EOF to the caller
                    throw new IOException("HTTP header camouflage: connection closed inside the server's response header.");
                }
                len += n;
                int end = IndexOf(acc, len, Ending);
                if (end >= 0)
                {
                    string head = Encoding.ASCII.GetString(acc, 0, end);
                    string status = head.Split('\r')[0];
                    if (!status.StartsWith("HTTP/1.", StringComparison.Ordinal))
                        throw new IOException("HTTP header camouflage: the server did not reply with an HTTP header (is headerType=http right?).");
                    string[] parts = status.Split(' ');
                    if (parts.Length >= 2 && parts[1].Length == 3 && (parts[1][0] == '4' || parts[1][0] == '5'))
                        throw new IOException("HTTP header camouflage: the server rejected the request (" + status.Trim() + ") — check the path.");
                    int body = end + Ending.Length;
                    if (len > body) { _left = acc; _leftOff = body; _leftLen = len - body; }
                    _responseParsed = true;
                    return;
                }
                if (len >= MaxHeader) throw new IOException("HTTP header camouflage: server response header too long.");
            }
        }

        private static int IndexOf(byte[] data, int len, byte[] pattern)
        {
            for (int i = 0; i + pattern.Length <= len; i++)
            {
                int k = 0;
                while (k < pattern.Length && data[i + k] == pattern[k]) k++;
                if (k == pattern.Length) return i;
            }
            return -1;
        }

        public override Task FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);
        public override void Flush() => _inner.Flush();
        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing) { try { _inner.Dispose(); } catch { } }
            base.Dispose(disposing);
        }
    }
}

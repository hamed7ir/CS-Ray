using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Transport
{
    /// <summary>
    /// WebSocket (RFC6455) client transport. Wraps an already-built inner transport
    /// (e.g. <see cref="TlsTransport"/> for security=tls): it connects the inner
    /// transport, performs the WebSocket upgrade handshake over it, then exposes a
    /// <see cref="WebSocketFrameStream"/> that frames/masks all subsequent traffic.
    /// </summary>
    public class WebSocketTransport : ITransport
    {
        private const string WsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        private readonly ITransport _inner;
        private readonly string _path;
        private readonly string _hostHeader;
        private WebSocketFrameStream _frameStream;

        /// <param name="inner">Underlying transport (connected during <see cref="ConnectAsync"/>).</param>
        /// <param name="path">Request path for the GET (defaults to "/").</param>
        /// <param name="hostHeader">Value for the HTTP Host header (wsHost ?? sni ?? server).</param>
        public WebSocketTransport(ITransport inner, string path, string hostHeader)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _path = string.IsNullOrEmpty(path) ? "/" : path;
            _hostHeader = hostHeader;
        }

        public async Task ConnectAsync(string host, int port, CancellationToken ct)
        {
            await _inner.ConnectAsync(host, port, ct).ConfigureAwait(false);
            var stream = _inner.GetStream();

            // 16 random bytes (RNGCryptoServiceProvider, never System.Random), base64-encoded.
            var keyBytes = new byte[16];
            Rng.GetBytes(keyBytes);
            var key = Convert.ToBase64String(keyBytes);

            var sb = new StringBuilder();
            sb.Append("GET ").Append(_path).Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(_hostHeader).Append("\r\n");
            sb.Append("Upgrade: websocket\r\n");
            sb.Append("Connection: Upgrade\r\n");
            sb.Append("Sec-WebSocket-Key: ").Append(key).Append("\r\n");
            sb.Append("Sec-WebSocket-Version: 13\r\n");
            sb.Append("\r\n");
            var req = Encoding.ASCII.GetBytes(sb.ToString());

            await stream.WriteAsync(req, 0, req.Length, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);

            var response = await ReadResponseHeaderAsync(stream, ct).ConfigureAwait(false);

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
            _inner.Close();
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

        public WebSocketFrameStream(Stream inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
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
            var frame = BuildClientFrame(buffer, offset, count);
            await _inner.WriteAsync(frame, 0, frame.Length, ct).ConfigureAwait(false);
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

        // FIN + binary opcode (0x82), mask bit set, 4-byte random mask, masked payload.
        private static byte[] BuildClientFrame(byte[] data, int offset, int count)
        {
            var mask = new byte[4];
            Rng.GetBytes(mask);

            int lenFieldBytes = count < 126 ? 0 : (count <= 0xFFFF ? 2 : 8);
            var frame = new byte[2 + lenFieldBytes + 4 + count];
            int pos = 0;

            frame[pos++] = 0x82; // FIN=1, opcode=binary

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

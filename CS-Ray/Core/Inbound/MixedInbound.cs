using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Inbound
{
    /// <summary>
    /// A mixed local inbound on one port: peeks the first byte (without losing it) and routes
    /// 0x05 → SOCKS5, 0x04 → rejected SOCKS4, anything else → HTTP proxy (CONNECT or absolute-URI).
    /// Both paths resolve a target host:port and raise <see cref="ConnectRequested"/> with an
    /// <see cref="InboundConnection"/> whose Stream is positioned for the outbound relay — so HTTP
    /// and SOCKS share the exact same outbound chain (VLESS/VMess/SS).
    /// </summary>
    public class MixedInbound
    {
        private readonly IPAddress _address;
        private readonly int _port;
        private TcpListener _listener;
        private CancellationTokenSource _cts;

        public MixedInbound(IPAddress address, int port) { _address = address; _port = port; }

        public event Func<InboundConnection, Task> ConnectRequested;
        public event Action<string> Log;

        /// <summary>When false, suppress per-connection logging (the high-frequency spam under browser load).</summary>
        public bool Verbose;

        private void LogVerbose(string s) { if (Verbose) Log?.Invoke(s); }

        public void Start()
        {
            _cts = new CancellationTokenSource();
            _listener = new TcpListener(_address, _port);
            _listener.Start();
            Task.Run(() => AcceptLoopAsync(_cts.Token));
        }

        public void Stop()
        {
            try { _cts?.Cancel(); } catch { }
            try { _listener?.Stop(); } catch { }
            _listener = null;
        }

        private async Task AcceptLoopAsync(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await _listener.AcceptTcpClientAsync().ConfigureAwait(false); }
                catch { break; }
                _ = HandleClientAsync(client, ct);
            }
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
        {
            try
            {
                client.NoDelay = true;
                var ns = client.GetStream();

                // Peek the first byte, then push it back so the chosen handler sees the whole stream.
                var first = new byte[1];
                int r = await ns.ReadAsync(first, 0, 1, ct).ConfigureAwait(false);
                if (r <= 0) { client.Close(); return; }

                var stream = new PushbackStream(ns, new[] { first[0] });

                if (first[0] == 0x05)
                    await HandleSocks5Async(client, stream, ct).ConfigureAwait(false);
                else if (first[0] == 0x04)
                {
                    LogVerbose("SOCKS4 not supported (use SOCKS5 or HTTP).");
                    client.Close();
                }
                else
                    await HandleHttpAsync(client, stream, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                LogVerbose("Inbound client error: " + ex.Message);
                try { client.Close(); } catch { }
            }
        }

        // ---------------- SOCKS5 ----------------
        private async Task HandleSocks5Async(TcpClient client, Stream stream, CancellationToken ct)
        {
            var head = await ReadExactAsync(stream, 2, ct).ConfigureAwait(false); // VER(0x05) NMETHODS
            int nMethods = head[1];
            await ReadExactAsync(stream, nMethods, ct).ConfigureAwait(false);      // discard methods
            await stream.WriteAsync(new byte[] { 0x05, 0x00 }, 0, 2, ct).ConfigureAwait(false); // no-auth

            var req = await ReadExactAsync(stream, 4, ct).ConfigureAwait(false);   // VER CMD RSV ATYP
            byte cmd = req[1], atyp = req[3];
            if (cmd != 0x01) { await SendSocksReplyAsync(stream, 0x07, ct).ConfigureAwait(false); client.Close(); return; }

            string host;
            switch (atyp)
            {
                case 0x01: host = new IPAddress(await ReadExactAsync(stream, 4, ct).ConfigureAwait(false)).ToString(); break;
                case 0x03:
                    int len = (await ReadExactAsync(stream, 1, ct).ConfigureAwait(false))[0];
                    host = Encoding.ASCII.GetString(await ReadExactAsync(stream, len, ct).ConfigureAwait(false));
                    break;
                case 0x04: host = new IPAddress(await ReadExactAsync(stream, 16, ct).ConfigureAwait(false)).ToString(); break;
                default: await SendSocksReplyAsync(stream, 0x08, ct).ConfigureAwait(false); client.Close(); return;
            }
            var pb = await ReadExactAsync(stream, 2, ct).ConfigureAwait(false);
            int port = (pb[0] << 8) | pb[1];

            await SendSocksReplyAsync(stream, 0x00, ct).ConfigureAwait(false);
            LogVerbose("SOCKS5 CONNECT " + host + ":" + port);
            await Dispatch(client, stream, host, port).ConfigureAwait(false);
        }

        private static Task SendSocksReplyAsync(Stream s, byte rep, CancellationToken ct)
            => s.WriteAsync(new byte[] { 0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0 }, 0, 10, ct);

        // ---------------- HTTP ----------------
        private async Task HandleHttpAsync(TcpClient client, Stream stream, CancellationToken ct)
        {
            var head = await ReadHttpHeadAsync(stream, ct).ConfigureAwait(false);
            if (head == null) { client.Close(); return; }

            int firstEol = head.IndexOf("\r\n", StringComparison.Ordinal);
            var requestLine = firstEol >= 0 ? head.Substring(0, firstEol) : head;
            var parts = requestLine.Split(' ');
            if (parts.Length < 3) { client.Close(); return; }
            string method = parts[0], target = parts[1], version = parts[2];

            if (string.Equals(method, "CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                if (!SplitHostPort(target, 443, out var host, out var port)) { client.Close(); return; }
                await WriteAsciiAsync(stream, "HTTP/1.1 200 Connection Established\r\n\r\n", ct).ConfigureAwait(false);
                LogVerbose("HTTP CONNECT " + host + ":" + port);
                await Dispatch(client, stream, host, port).ConfigureAwait(false);
                return;
            }

            // Absolute-URI request (plain HTTP via proxy), or origin-form fallback via Host header.
            string hostName; int hostPort; string pathAndQuery;
            if (target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                target.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                var uri = new Uri(target);
                hostName = uri.Host; hostPort = uri.Port; pathAndQuery = uri.PathAndQuery;
            }
            else
            {
                var hostHeader = GetHeader(head, "Host");
                if (string.IsNullOrEmpty(hostHeader)) { client.Close(); return; }
                if (!SplitHostPort(hostHeader, 80, out hostName, out hostPort)) { client.Close(); return; }
                pathAndQuery = target;
            }

            // Rewrite to origin-form and drop proxy-only headers; deliver this head to the outbound first.
            var newHead = RewriteHttpHead(head, method + " " + pathAndQuery + " " + version);
            var connStream = new PushbackStream(stream, Encoding.ASCII.GetBytes(newHead));
            LogVerbose("HTTP " + method + " " + hostName + ":" + hostPort + pathAndQuery);
            await Dispatch(client, connStream, hostName, hostPort).ConfigureAwait(false);
        }

        private async Task Dispatch(TcpClient client, Stream stream, string host, int port)
        {
            var handler = ConnectRequested;
            if (handler != null) await handler(new InboundConnection(client, stream, host, port)).ConfigureAwait(false);
            else client.Close();
        }

        // Read the HTTP head byte-by-byte up to CRLFCRLF (never over-reads into the body).
        private static async Task<string> ReadHttpHeadAsync(Stream stream, CancellationToken ct)
        {
            var buf = new MemoryStream();
            var one = new byte[1];
            byte c1 = 0, c2 = 0, c3 = 0, c4 = 0;
            while (true)
            {
                int n = await stream.ReadAsync(one, 0, 1, ct).ConfigureAwait(false);
                if (n <= 0) return buf.Length > 0 ? Encoding.ASCII.GetString(buf.ToArray()) : null;
                buf.WriteByte(one[0]);
                c1 = c2; c2 = c3; c3 = c4; c4 = one[0];
                if (c1 == 0x0D && c2 == 0x0A && c3 == 0x0D && c4 == 0x0A) break;
                if (buf.Length > 64 * 1024) break;
            }
            return Encoding.ASCII.GetString(buf.ToArray());
        }

        private static string RewriteHttpHead(string head, string newRequestLine)
        {
            var lines = head.Split(new[] { "\r\n" }, StringSplitOptions.None);
            var sb = new StringBuilder();
            sb.Append(newRequestLine).Append("\r\n");
            for (int i = 1; i < lines.Length; i++)
            {
                var line = lines[i];
                if (line.Length == 0) break; // end of headers
                if (line.StartsWith("Proxy-Connection", StringComparison.OrdinalIgnoreCase)) continue;
                sb.Append(line).Append("\r\n");
            }
            sb.Append("\r\n");
            return sb.ToString();
        }

        private static string GetHeader(string head, string name)
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

        private static bool SplitHostPort(string s, int defaultPort, out string host, out int port)
        {
            host = s; port = defaultPort;
            int c = s.LastIndexOf(':');
            if (c < 0) return !string.IsNullOrEmpty(s);
            host = s.Substring(0, c);
            return int.TryParse(s.Substring(c + 1), out port) && !string.IsNullOrEmpty(host);
        }

        private static Task WriteAsciiAsync(Stream s, string text, CancellationToken ct)
        {
            var b = Encoding.ASCII.GetBytes(text);
            return s.WriteAsync(b, 0, b.Length, ct);
        }

        private static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken ct)
        {
            var buf = new byte[count];
            int off = 0;
            while (off < count)
            {
                int n = await stream.ReadAsync(buf, off, count - off, ct).ConfigureAwait(false);
                if (n <= 0) throw new EndOfStreamException("Stream closed after " + off + " of " + count + " bytes.");
                off += n;
            }
            return buf;
        }
    }

    /// <summary>A parsed inbound CONNECT request (SOCKS5 or HTTP) plus the live client connection.</summary>
    public class InboundConnection
    {
        public InboundConnection(TcpClient client, Stream stream, string targetHost, int targetPort)
        {
            Client = client; Stream = stream; TargetHost = targetHost; TargetPort = targetPort;
        }

        public TcpClient Client { get; }
        public Stream Stream { get; }
        public string TargetHost { get; }
        public int TargetPort { get; }
    }

    /// <summary>
    /// Stream wrapper that serves a buffered prefix (the peeked byte, or a rewritten HTTP head)
    /// before delegating reads to the inner stream; writes/flush pass straight through.
    /// </summary>
    public class PushbackStream : Stream
    {
        private readonly Stream _inner;
        private readonly byte[] _prefix;
        private int _pos;

        public PushbackStream(Stream inner, byte[] prefix) { _inner = inner; _prefix = prefix ?? new byte[0]; }

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
        public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
            => _inner.WriteAsync(buffer, offset, count, ct);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (_pos < _prefix.Length)
            {
                int n = Math.Min(count, _prefix.Length - _pos);
                Buffer.BlockCopy(_prefix, _pos, buffer, offset, n);
                _pos += n;
                return Task.FromResult(n);
            }
            return _inner.ReadAsync(buffer, offset, count, ct);
        }
    }
}

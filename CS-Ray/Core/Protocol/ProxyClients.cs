using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Protocol
{
    /// <summary>
    /// SOCKS5 outbound client handshake (RFC1928 + RFC1929 user/pass). Given an already-connected stream to the
    /// proxy, negotiates and issues CONNECT to the target, leaving the stream as a clean tunnel to the target.
    /// TCP only this pass (no UDP ASSOCIATE).
    /// </summary>
    public static class SocksClient
    {
        public static async Task HandshakeAsync(Stream s, string host, int port, string user, string pass, CancellationToken ct)
        {
            bool auth = !string.IsNullOrEmpty(user);

            // Greeting: offer no-auth (+ user/pass if we have creds).
            byte[] greet = auth ? new byte[] { 0x05, 2, 0x00, 0x02 } : new byte[] { 0x05, 1, 0x00 };
            await s.WriteAsync(greet, 0, greet.Length, ct).ConfigureAwait(false);
            await s.FlushAsync(ct).ConfigureAwait(false);

            var sel = await ReadExact(s, 2, ct).ConfigureAwait(false);
            if (sel[0] != 0x05) throw new IOException("SOCKS5: bad version in method reply.");
            byte method = sel[1];
            if (method == 0xFF) throw new IOException("SOCKS5: server accepted no offered auth method.");
            if (method == 0x02)
            {
                if (!auth) throw new IOException("SOCKS5: server requires username/password auth.");
                var u = Encoding.UTF8.GetBytes(user ?? "");
                var p = Encoding.UTF8.GetBytes(pass ?? "");
                if (u.Length > 255 || p.Length > 255) throw new IOException("SOCKS5: credentials too long.");
                var areq = new byte[3 + u.Length + p.Length];
                int i = 0;
                areq[i++] = 0x01;
                areq[i++] = (byte)u.Length; Buffer.BlockCopy(u, 0, areq, i, u.Length); i += u.Length;
                areq[i++] = (byte)p.Length; Buffer.BlockCopy(p, 0, areq, i, p.Length);
                await s.WriteAsync(areq, 0, areq.Length, ct).ConfigureAwait(false);
                await s.FlushAsync(ct).ConfigureAwait(false);
                var ar = await ReadExact(s, 2, ct).ConfigureAwait(false);
                if (ar[1] != 0x00) throw new IOException("SOCKS5: username/password auth rejected.");
            }
            else if (method != 0x00) throw new IOException("SOCKS5: unsupported auth method " + method + ".");

            // CONNECT with ATYP=domain (0x03) so the proxy resolves the hostname.
            var hb = Encoding.ASCII.GetBytes(host ?? "");
            if (hb.Length > 255) throw new IOException("SOCKS5: hostname too long.");
            var req = new byte[5 + hb.Length + 2];
            int j = 0;
            req[j++] = 0x05; req[j++] = 0x01; req[j++] = 0x00; req[j++] = 0x03;
            req[j++] = (byte)hb.Length; Buffer.BlockCopy(hb, 0, req, j, hb.Length); j += hb.Length;
            req[j++] = (byte)(port >> 8); req[j++] = (byte)(port & 0xFF);
            await s.WriteAsync(req, 0, req.Length, ct).ConfigureAwait(false);
            await s.FlushAsync(ct).ConfigureAwait(false);

            // Reply: VER REP RSV ATYP BND.ADDR BND.PORT — consume the bound addr/port.
            var rep = await ReadExact(s, 4, ct).ConfigureAwait(false);
            if (rep[0] != 0x05) throw new IOException("SOCKS5: bad version in connect reply.");
            if (rep[1] != 0x00) throw new IOException("SOCKS5: CONNECT rejected (reply code " + rep[1] + ").");
            int addrLen;
            switch (rep[3])
            {
                case 0x01: addrLen = 4; break;
                case 0x04: addrLen = 16; break;
                case 0x03: addrLen = (await ReadExact(s, 1, ct).ConfigureAwait(false))[0]; break;
                default: throw new IOException("SOCKS5: bad ATYP " + rep[3] + " in reply.");
            }
            await ReadExact(s, addrLen + 2, ct).ConfigureAwait(false); // BND.ADDR + BND.PORT
        }

        private static async Task<byte[]> ReadExact(Stream s, int count, CancellationToken ct)
        {
            var buf = new byte[count];
            int off = 0;
            while (off < count)
            {
                int n = await s.ReadAsync(buf, off, count - off, ct).ConfigureAwait(false);
                if (n <= 0) throw new EndOfStreamException("SOCKS5: connection closed during handshake.");
                off += n;
            }
            return buf;
        }
    }

    /// <summary>
    /// HTTP CONNECT outbound client. Given an already-connected stream to the proxy (plain TCP for http, or TLS
    /// for https), issues CONNECT host:port (optional Basic auth) and leaves the stream as a clean tunnel.
    /// </summary>
    public static class HttpConnectClient
    {
        public static async Task ConnectAsync(Stream s, string host, int port, string user, string pass, CancellationToken ct)
        {
            string hp = host + ":" + port;
            var sb = new StringBuilder();
            sb.Append("CONNECT ").Append(hp).Append(" HTTP/1.1\r\n");
            sb.Append("Host: ").Append(hp).Append("\r\n");
            if (!string.IsNullOrEmpty(user))
            {
                string cred = Convert.ToBase64String(Encoding.UTF8.GetBytes((user ?? "") + ":" + (pass ?? "")));
                sb.Append("Proxy-Authorization: Basic ").Append(cred).Append("\r\n");
            }
            sb.Append("Proxy-Connection: keep-alive\r\n\r\n");
            var bytes = Encoding.ASCII.GetBytes(sb.ToString());
            await s.WriteAsync(bytes, 0, bytes.Length, ct).ConfigureAwait(false);
            await s.FlushAsync(ct).ConfigureAwait(false);

            string resp = await ReadHeaderBlock(s, ct).ConfigureAwait(false);
            int eol = resp.IndexOf("\r\n", StringComparison.Ordinal);
            string line = eol >= 0 ? resp.Substring(0, eol) : resp;
            var parts = line.Split(' ');
            int code = parts.Length >= 2 && int.TryParse(parts[1], out int c) ? c : 0;
            if (code < 200 || code >= 300)
                throw new IOException("HTTP CONNECT failed: " + line);
        }

        private static async Task<string> ReadHeaderBlock(Stream s, CancellationToken ct)
        {
            var buf = new MemoryStream();
            var one = new byte[1];
            byte c1 = 0, c2 = 0, c3 = 0, c4 = 0;
            while (true)
            {
                int n = await s.ReadAsync(one, 0, 1, ct).ConfigureAwait(false);
                if (n <= 0) throw new EndOfStreamException("HTTP CONNECT: connection closed before response.");
                buf.WriteByte(one[0]);
                c1 = c2; c2 = c3; c3 = c4; c4 = one[0];
                if (c1 == 0x0D && c2 == 0x0A && c3 == 0x0D && c4 == 0x0A) break;
                if (buf.Length > 64 * 1024) throw new IOException("HTTP CONNECT: response header exceeded 64KB.");
            }
            return Encoding.ASCII.GetString(buf.ToArray());
        }
    }
}

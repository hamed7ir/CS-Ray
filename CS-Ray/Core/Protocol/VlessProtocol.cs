using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Protocol
{
    /// <summary>
    /// VLESS protocol helpers: builds the request header, strips the server's
    /// response header, and pumps bytes bidirectionally between client and server.
    ///
    /// Request header layout:
    ///   1  VER            = 0x00
    ///   16 UUID           (RFC4122 byte order, i.e. the string order, NOT Guid.ToByteArray)
    ///   1  addons length  = 0x00 (no addons)
    ///   1  CMD            = 0x01 (TCP)
    ///   2  port           (big-endian)
    ///   1  ATYP           1=IPv4, 2=domain, 3=IPv6   (note: differs from SOCKS5 codes)
    ///   .. address        IPv4=4B, domain=1B len + n, IPv6=16B
    /// </summary>
    public static class VlessProtocol
    {
        public const byte AtypIPv4 = 0x01;
        public const byte AtypDomain = 0x02;
        public const byte AtypIPv6 = 0x03;

        public const byte CmdTcp = 0x01;
        public const byte CmdUdp = 0x02;

        /// <summary>Builds the VLESS request header for a TCP CONNECT to host:port.</summary>
        public static byte[] BuildRequestHeader(byte[] uuid, string host, int port)
        {
            return BuildRequestHeader(uuid, host, port, CmdTcp);
        }

        /// <summary>Builds the VLESS request header with an explicit command (TCP=0x01, UDP=0x02).</summary>
        public static byte[] BuildRequestHeader(byte[] uuid, string host, int port, byte cmd)
        {
            if (uuid == null || uuid.Length != 16)
                throw new ArgumentException("UUID must be 16 bytes.", nameof(uuid));

            byte atyp;
            byte[] addr;

            if (IPAddress.TryParse(host, out var ip))
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    atyp = AtypIPv4;
                    addr = ip.GetAddressBytes(); // 4 bytes, network order
                }
                else
                {
                    atyp = AtypIPv6;
                    addr = ip.GetAddressBytes(); // 16 bytes, network order
                }
            }
            else
            {
                atyp = AtypDomain;
                var domain = Encoding.ASCII.GetBytes(host);
                addr = new byte[domain.Length + 1];
                addr[0] = (byte)domain.Length;
                Buffer.BlockCopy(domain, 0, addr, 1, domain.Length);
            }

            using (var ms = new MemoryStream())
            {
                ms.WriteByte(0x00);                 // VER
                ms.Write(uuid, 0, 16);              // UUID
                ms.WriteByte(0x00);                 // addons length
                ms.WriteByte(cmd);                  // CMD (0x01 TCP, 0x02 UDP)
                ms.WriteByte((byte)(port >> 8));    // port hi
                ms.WriteByte((byte)(port & 0xFF));  // port lo
                ms.WriteByte(atyp);                 // ATYP
                ms.Write(addr, 0, addr.Length);     // address
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Reads and discards the VLESS response header from the server stream:
        /// 1 byte version + 1 byte addon length + addon bytes. The header arrives
        /// prepended to the first server→client data chunk, so this is done inside
        /// the server→client pump (concurrently with the client→server pump) rather
        /// than up-front, which would deadlock the target's request/response cycle.
        /// </summary>
        public static async Task ConsumeResponseHeaderAsync(Stream server, CancellationToken ct)
        {
            var head = await ReadExactAsync(server, 2, ct).ConfigureAwait(false); // version + addonLen
            int addonLen = head[1];
            if (addonLen > 0)
                await ReadExactAsync(server, addonLen, ct).ConfigureAwait(false);
        }

        /// <summary>
        /// Parses a UUID string (with or without dashes) into 16 bytes in RFC4122 /
        /// string byte order. Deliberately not <see cref="Guid.ToByteArray"/>, which
        /// reorders the first three fields to little-endian.
        /// </summary>
        public static byte[] ParseUuid(string uuid)
        {
            if (string.IsNullOrWhiteSpace(uuid))
                throw new ArgumentException("UUID is empty.", nameof(uuid));

            var hex = uuid.Replace("-", "").Trim();
            if (hex.Length != 32)
                throw new ArgumentException("UUID must be 32 hex chars (16 bytes).", nameof(uuid));

            var bytes = new byte[16];
            for (int i = 0; i < 16; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }

        private static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken ct)
        {
            var buf = new byte[count];
            int off = 0;
            while (off < count)
            {
                int n = await stream.ReadAsync(buf, off, count - off, ct).ConfigureAwait(false);
                if (n <= 0)
                    throw new EndOfStreamException("Stream closed after " + off + " of " + count + " bytes.");
                off += n;
            }
            return buf;
        }
    }
}

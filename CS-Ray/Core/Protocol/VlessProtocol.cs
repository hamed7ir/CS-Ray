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

        /// <summary>The only VLESS flow we speak (XTLS Vision). "xtls-rprx-vision-udp443" is an Xray client-side alias
        /// that still sends this on the wire.</summary>
        public const string FlowVision = "xtls-rprx-vision";

        /// <summary>What it means when a VLESS server closes before its response header: it accepted the request but
        /// couldn't (or wouldn't) connect to the target — e.g. that site blocks the exit, or the server's routing refuses it.</summary>
        public const string NoAnswerMessage = "the server closed the connection without answering (it could not reach the target, or refused it)";

        /// <summary>Normalizes a share-link / config flow: Vision (incl. its -udp443 alias) → <see cref="FlowVision"/>,
        /// empty/"none" → null, anything else unchanged (and unsupported).</summary>
        public static string NormalizeFlow(string flow)
        {
            string f = (flow ?? "").Trim().ToLowerInvariant();
            if (f.Length == 0 || f == "none") return null;
            if (f == FlowVision || f == FlowVision + "-udp443") return FlowVision;
            return flow.Trim();
        }

        /// <summary>Builds the VLESS request header for a TCP CONNECT to host:port.</summary>
        public static byte[] BuildRequestHeader(byte[] uuid, string host, int port)
        {
            return BuildRequestHeader(uuid, host, port, CmdTcp);
        }

        /// <summary>Builds the VLESS request header with an explicit command (TCP=0x01, UDP=0x02).</summary>
        public static byte[] BuildRequestHeader(byte[] uuid, string host, int port, byte cmd)
            => BuildRequestHeader(uuid, host, port, cmd, null);

        /// <summary>Builds the VLESS request header; a non-null <paramref name="flow"/> goes into the addons
        /// (protobuf Addons{Flow=1}: 0A len flow — Xray EncodeHeaderAddons).</summary>
        public static byte[] BuildRequestHeader(byte[] uuid, string host, int port, byte cmd, string flow)
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
                if (string.IsNullOrEmpty(flow)) ms.WriteByte(0x00);   // addons length
                else
                {
                    var f = Encoding.ASCII.GetBytes(flow);
                    ms.WriteByte((byte)(f.Length + 2));             // addons length
                    ms.WriteByte(0x0A);                             // field 1 (Flow), wire type 2
                    ms.WriteByte((byte)f.Length);
                    ms.Write(f, 0, f.Length);
                }
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
            // Only OUR EOF check means "no answer": a transport's own exception (e.g. an XHTTP downlink failure) passes
            // through unchanged.
            var head = new byte[2];
            for (int got = 0; got < 2;)
            {
                int r = await server.ReadAsync(head, got, 2 - got, ct).ConfigureAwait(false);   // version + addonLen
                if (r <= 0) throw new IOException(got == 0 ? NoAnswerMessage : "VLESS response header truncated");
                got += r;
            }
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

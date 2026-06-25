using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace CS_Ray.Core.Protocol.Vmess
{
    /// <summary>
    /// Builds a VMess AEAD (alterId=0) request-header body and seals it. Holds the per-connection
    /// secrets (body key/IV, response auth byte, security) that the phase-2 body stream will need.
    ///
    /// Body layout (then 4-byte FNV1a checksum, then sealed by <see cref="VmessAead"/>):
    ///   1  Version = 1
    ///   16 request body IV
    ///   16 request body Key
    ///   1  response auth V
    ///   1  Option = 0x01 (standard / chunk stream)
    ///   1  (paddingLen &lt;&lt; 4) | Security
    ///   1  reserved = 0
    ///   1  Command = 0x01 (TCP)
    ///   2  Port (big-endian)        -- VMess writes Port THEN address
    ///   1  ATYP (1=IPv4, 2=Domain, 3=IPv6)
    ///   .. Address
    ///   .. random padding (paddingLen bytes)
    ///   4  FNV1a-32(all of the above)
    /// </summary>
    public class VmessRequest
    {
        public const byte Version = 0x01;
        public const byte CommandTcp = 0x01;
        public const byte CommandUdp = 0x02;
        public const byte OptionChunkStream = 0x01;
        public const byte SecurityAes128Gcm = 0x03; // "auto" → AES-128-GCM

        // VMess address types (1=IPv4, 2=Domain, 3=IPv6).
        public const byte AtypIPv4 = 0x01;
        public const byte AtypDomain = 0x02;
        public const byte AtypIPv6 = 0x03;

        private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        public byte[] RequestBodyIV { get; }   // 16
        public byte[] RequestBodyKey { get; }  // 16
        public byte ResponseHeader { get; }    // V — used to validate the response
        public byte Security { get; }
        public byte Option { get; }

        public VmessRequest()
        {
            RequestBodyIV = new byte[16];
            RequestBodyKey = new byte[16];
            Rng.GetBytes(RequestBodyIV);
            Rng.GetBytes(RequestBodyKey);
            var v = new byte[1]; Rng.GetBytes(v);
            ResponseHeader = v[0];
            Security = SecurityAes128Gcm;
            Option = OptionChunkStream;
        }

        /// <summary>Builds the plaintext request-header body (including the trailing FNV1a checksum).</summary>
        public byte[] BuildHeaderBody(string host, int port, byte command = CommandTcp)
        {
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(Version);
                ms.Write(RequestBodyIV, 0, 16);
                ms.Write(RequestBodyKey, 0, 16);
                ms.WriteByte(ResponseHeader);
                ms.WriteByte(Option);

                int paddingLen = NextPaddingLen();
                ms.WriteByte((byte)((paddingLen << 4) | (Security & 0x0F)));
                ms.WriteByte(0x00); // reserved
                ms.WriteByte(command);

                // Port (big-endian) THEN address (VMess PortThenAddress ordering).
                ms.WriteByte((byte)(port >> 8));
                ms.WriteByte((byte)(port & 0xFF));
                WriteAddress(ms, host);

                if (paddingLen > 0)
                {
                    var padding = new byte[paddingLen];
                    Rng.GetBytes(padding);
                    ms.Write(padding, 0, paddingLen);
                }

                var body = ms.ToArray();
                uint fnv = Fnv1a32(body, 0, body.Length);
                var withChecksum = new byte[body.Length + 4];
                Buffer.BlockCopy(body, 0, withChecksum, 0, body.Length);
                withChecksum[body.Length + 0] = (byte)(fnv >> 24);
                withChecksum[body.Length + 1] = (byte)(fnv >> 16);
                withChecksum[body.Length + 2] = (byte)(fnv >> 8);
                withChecksum[body.Length + 3] = (byte)fnv;
                return withChecksum;
            }
        }

        /// <summary>Builds + AEAD-seals the request header, producing on-wire bytes.</summary>
        public byte[] BuildSealedHeader(byte[] cmdKey, string host, int port, byte command = CommandTcp)
            => VmessAead.SealVMessAEADHeader(cmdKey, BuildHeaderBody(host, port, command));

        private static void WriteAddress(Stream ms, string host)
        {
            if (IPAddress.TryParse(host, out var ip))
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    ms.WriteByte(AtypIPv4);
                    var b = ip.GetAddressBytes(); ms.Write(b, 0, b.Length);
                }
                else
                {
                    ms.WriteByte(AtypIPv6);
                    var b = ip.GetAddressBytes(); ms.Write(b, 0, b.Length);
                }
            }
            else
            {
                var domain = Encoding.ASCII.GetBytes(host);
                ms.WriteByte(AtypDomain);
                ms.WriteByte((byte)domain.Length);
                ms.Write(domain, 0, domain.Length);
            }
        }

        private static int NextPaddingLen()
        {
            var b = new byte[1];
            Rng.GetBytes(b);
            return b[0] % 16; // 0..15
        }

        /// <summary>FNV-1a 32-bit hash.</summary>
        public static uint Fnv1a32(byte[] data, int offset, int length)
        {
            const uint OffsetBasis = 2166136261;
            const uint Prime = 16777619;
            uint hash = OffsetBasis;
            for (int i = 0; i < length; i++)
            {
                hash ^= data[offset + i];
                hash *= Prime;
            }
            return hash;
        }
    }
}

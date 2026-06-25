using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

namespace CS_Ray.Core.Protocol.Vmess
{
    /// <summary>
    /// Phase-1 self-tests for the VMess AEAD handshake crypto. Returns a PASS/FAIL report.
    /// Not wired into the engine; intended to be invoked directly (e.g. via reflection) for review.
    /// </summary>
    public static class VmessSelfTest
    {
        public static string Run()
        {
            var sb = new StringBuilder();
            int pass = 0, fail = 0;
            void Check(string name, bool ok, string detail = "")
            {
                if (ok) { pass++; sb.AppendLine("PASS  " + name); }
                else { fail++; sb.AppendLine("FAIL  " + name + (detail.Length > 0 ? "  -- " + detail : "")); }
            }

            // 1) KDF leaf: Kdf(X) with no path == HMAC-SHA256(key="VMess AEAD KDF", msg=X)
            {
                var x = Encoding.ASCII.GetBytes("the quick brown fox");
                byte[] expected;
                using (var h = new HMACSHA256(Encoding.ASCII.GetBytes("VMess AEAD KDF")))
                    expected = h.ComputeHash(x);
                var got = VmessKdf.Kdf(x);
                Check("KDF leaf == HMACSHA256(\"VMess AEAD KDF\", X)", Eq(expected, got), Hex(got));
            }

            // 2) KDF two-level == independent manual nested HMAC (leaf via System HMACSHA256)
            {
                var key = Encoding.ASCII.GetBytes("master-key-material");
                var label = Encoding.ASCII.GetBytes("VMess Header AEAD Key");
                Func<byte[], byte[]> h1 = m =>
                {
                    using (var h = new HMACSHA256(Encoding.ASCII.GetBytes("VMess AEAD KDF")))
                        return h.ComputeHash(m);
                };
                var expected = ManualHmac(h1, label, key); // HMAC over H1 with key=label, msg=key
                var got = VmessKdf.Kdf(key, label);
                Check("KDF nested (1 label) == independent HMAC nest", Eq(expected, got), Hex(got));
            }

            // 3) Output lengths
            {
                var k = Encoding.ASCII.GetBytes("k");
                Check("Kdf length == 32", VmessKdf.Kdf(k).Length == 32);
                Check("Kdf16 length == 16", VmessKdf.Kdf16(k).Length == 16);
                Check("Kdf12 length == 12", VmessKdf.Kdf12(k).Length == 12);
            }

            // 4) CRC32(IEEE) of "123456789" == 0xCBF43926
            {
                var data = Encoding.ASCII.GetBytes("123456789");
                uint crc = Crc32.Compute(data, 0, data.Length);
                Check("CRC32(\"123456789\") == 0xCBF43926", crc == 0xCBF43926, "0x" + crc.ToString("X8"));
            }

            // 5) FNV1a-32 of "foobar" == 0xBF9CF968
            {
                var data = Encoding.ASCII.GetBytes("foobar");
                uint fnv = VmessRequest.Fnv1a32(data, 0, data.Length);
                Check("FNV1a32(\"foobar\") == 0xBF9CF968", fnv == 0xBF9CF968, "0x" + fnv.ToString("X8"));
            }

            // 6) AuthID: decrypt with the same key, confirm embedded CRC32 is valid
            {
                var cmdKey = VmessAead.GetCmdKey(SampleUuid());
                var random4 = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
                var authId = VmessAead.CreateAuthID(cmdKey, 1700000000L, random4); // fixed time
                var key = VmessKdf.Kdf16(cmdKey, VmessKdf.LabelAuthIDEncryptionKey);
                var plain = AesEcbDecryptBlock(key, authId);
                uint embedded = ((uint)plain[12] << 24) | ((uint)plain[13] << 16) | ((uint)plain[14] << 8) | plain[15];
                uint calc = Crc32.Compute(plain, 0, 12);
                Check("AuthID 16 bytes", authId.Length == 16);
                Check("AuthID embedded CRC32 valid after AES-ECB decrypt", embedded == calc,
                      "embedded=0x" + embedded.ToString("X8") + " calc=0x" + calc.ToString("X8"));
            }

            // 7) AEAD header seal/open round-trip with FIXED authId + connectionNonce
            {
                var cmdKey = VmessAead.GetCmdKey(SampleUuid());
                var data = Encoding.ASCII.GetBytes("VMESS-HEADER-BODY-ROUNDTRIP-PAYLOAD-0123456789");
                var authId = VmessAead.CreateAuthID(cmdKey, 1700000000L, new byte[] { 1, 2, 3, 4 });
                var connNonce = new byte[] { 9, 8, 7, 6, 5, 4, 3, 2 };
                var wire = VmessAead.SealVMessAEADHeader(cmdKey, data, authId, connNonce);
                int expectedLen = 16 + (2 + 16) + 8 + (data.Length + 16);
                Check("Sealed header length == 16+18+8+(N+16)", wire.Length == expectedLen,
                      "got=" + wire.Length + " expected=" + expectedLen);
                var opened = VmessAead.OpenVMessAEADHeader(cmdKey, wire);
                Check("AEAD header seal→open round-trips", Eq(data, opened));
            }

            // 8) Full request: build body → seal → open → equal, and FNV checksum verifies
            {
                var cmdKey = VmessAead.GetCmdKey(SampleUuid());
                var req = new VmessRequest();
                var body = req.BuildHeaderBody("api.ipify.org", 443);
                uint fnvCalc = VmessRequest.Fnv1a32(body, 0, body.Length - 4);
                uint fnvEmbed = ((uint)body[body.Length - 4] << 24) | ((uint)body[body.Length - 3] << 16) |
                                ((uint)body[body.Length - 2] << 8) | body[body.Length - 1];
                Check("Request body FNV1a checksum matches", fnvCalc == fnvEmbed,
                      "calc=0x" + fnvCalc.ToString("X8") + " embed=0x" + fnvEmbed.ToString("X8"));
                Check("Request body version byte == 1", body[0] == 1);
                var wire = VmessAead.SealVMessAEADHeader(cmdKey, body);
                var opened = VmessAead.OpenVMessAEADHeader(cmdKey, wire);
                Check("Full request header seal→open round-trips", Eq(body, opened));
            }

            sb.AppendLine();
            sb.AppendLine("RESULT: " + pass + " passed, " + fail + " failed.");
            return sb.ToString();
        }

        // Independent HMAC over an arbitrary inner hash (block size 64) for the cross-check.
        private static byte[] ManualHmac(Func<byte[], byte[]> h, byte[] key, byte[] msg)
        {
            const int B = 64;
            if (key.Length > B) key = h(key);
            var k = new byte[B];
            Buffer.BlockCopy(key, 0, k, 0, key.Length);
            var ip = new byte[B + msg.Length];
            var op = new byte[B];
            for (int i = 0; i < B; i++) { ip[i] = (byte)(k[i] ^ 0x36); op[i] = (byte)(k[i] ^ 0x5c); }
            Buffer.BlockCopy(msg, 0, ip, B, msg.Length);
            var inner = h(ip);
            var oi = new byte[B + inner.Length];
            Buffer.BlockCopy(op, 0, oi, 0, B);
            Buffer.BlockCopy(inner, 0, oi, B, inner.Length);
            return h(oi);
        }

        private static byte[] AesEcbDecryptBlock(byte[] key, byte[] block16)
        {
            var aes = new AesEngine();
            aes.Init(false, new KeyParameter(key));
            var outBuf = new byte[16];
            aes.ProcessBlock(block16, 0, outBuf, 0);
            return outBuf;
        }

        private static byte[] SampleUuid()
        {
            // Fixed 16-byte UUID for deterministic tests.
            return new byte[] { 0x78, 0x2a, 0xa1, 0xba, 0x4c, 0x2d, 0x49, 0xe0,
                                0xb8, 0x17, 0x0d, 0x47, 0xaf, 0x59, 0x95, 0xf8 };
        }

        private static bool Eq(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        private static string Hex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (var x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }
    }
}

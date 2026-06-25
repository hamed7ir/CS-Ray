using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CS_Ray.Core.Protocol.Vmess
{
    /// <summary>
    /// VMess AEAD (alterId=0) request-header sealing, per the v2ray VMess AEAD spec.
    ///
    /// cmdKey   = MD5(uuid16 || "c48619fe-8f02-49e0-b9e9-edf763e17e21").
    /// AuthID   = AES-128-ECB( key=KDF16(cmdKey,"AES Auth ID Encryption"),
    ///                         block=[8B BE unix time][4B random][4B CRC32 of the first 12] ).
    /// Header   = AuthID(16) || lengthAEAD(2+16) || connNonce(8) || payloadAEAD(len+16), where the
    ///            length/payload AEADs are AES-128-GCM with per-field KDF-derived key+nonce and
    ///            AAD = AuthID.
    /// </summary>
    public static class VmessAead
    {
        private const int TagBits = 128;
        private static readonly byte[] CmdKeyMagic = Encoding.ASCII.GetBytes("c48619fe-8f02-49e0-b9e9-edf763e17e21");
        private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        /// <summary>cmdKey = MD5(uuid16 || magic). 16 bytes.</summary>
        public static byte[] GetCmdKey(byte[] uuid16)
        {
            if (uuid16 == null || uuid16.Length != 16)
                throw new ArgumentException("UUID must be 16 bytes.", nameof(uuid16));
            using (var md5 = MD5.Create())
            {
                var buf = new byte[16 + CmdKeyMagic.Length];
                Buffer.BlockCopy(uuid16, 0, buf, 0, 16);
                Buffer.BlockCopy(CmdKeyMagic, 0, buf, 16, CmdKeyMagic.Length);
                return md5.ComputeHash(buf);
            }
        }

        /// <summary>
        /// 16-byte encrypted Auth ID. Plaintext = [8B time][4B rand][4B CRC32(first 12)], then
        /// AES-128-ECB encrypted with KDF16(cmdKey,"AES Auth ID Encryption").
        /// <paramref name="random4"/> may be supplied for deterministic tests.
        /// </summary>
        public static byte[] CreateAuthID(byte[] cmdKey, long unixTime, byte[] random4 = null)
        {
            var plain = new byte[16];
            // 8-byte big-endian time
            for (int i = 0; i < 8; i++)
                plain[i] = (byte)(unixTime >> (8 * (7 - i)));
            // 4 random bytes
            if (random4 == null) { random4 = new byte[4]; Rng.GetBytes(random4); }
            Buffer.BlockCopy(random4, 0, plain, 8, 4);
            // 4-byte big-endian CRC32 of the first 12 bytes
            uint crc = Crc32.Compute(plain, 0, 12);
            plain[12] = (byte)(crc >> 24);
            plain[13] = (byte)(crc >> 16);
            plain[14] = (byte)(crc >> 8);
            plain[15] = (byte)crc;

            var key = VmessKdf.Kdf16(cmdKey, VmessKdf.LabelAuthIDEncryptionKey);
            return AesEcbEncryptBlock(key, plain);
        }

        /// <summary>Seals a VMess request header body, producing the on-wire header bytes.</summary>
        public static byte[] SealVMessAEADHeader(byte[] cmdKey, byte[] data, byte[] authId = null, byte[] connectionNonce = null)
        {
            if (authId == null) authId = CreateAuthID(cmdKey, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            if (connectionNonce == null) { connectionNonce = new byte[8]; Rng.GetBytes(connectionNonce); }

            var lengthBytes = new byte[] { (byte)(data.Length >> 8), (byte)(data.Length & 0xFF) };

            var lenKey = VmessKdf.Kdf16(cmdKey, VmessKdf.LabelVMessHeaderPayloadLengthKey, authId, connectionNonce);
            var lenNonce = VmessKdf.Kdf12(cmdKey, VmessKdf.LabelVMessHeaderPayloadLengthIV, authId, connectionNonce);
            var encLength = GcmSeal(lenKey, lenNonce, lengthBytes, authId);

            var payloadKey = VmessKdf.Kdf16(cmdKey, VmessKdf.LabelVMessHeaderPayloadAEADKey, authId, connectionNonce);
            var payloadNonce = VmessKdf.Kdf12(cmdKey, VmessKdf.LabelVMessHeaderPayloadAEADIV, authId, connectionNonce);
            var encPayload = GcmSeal(payloadKey, payloadNonce, data, authId);

            using (var ms = new MemoryStream())
            {
                ms.Write(authId, 0, authId.Length);             // 16
                ms.Write(encLength, 0, encLength.Length);       // 2 + 16
                ms.Write(connectionNonce, 0, connectionNonce.Length); // 8
                ms.Write(encPayload, 0, encPayload.Length);     // data.Length + 16
                return ms.ToArray();
            }
        }

        /// <summary>
        /// Reverses <see cref="SealVMessAEADHeader"/> (what a server does) — used by self-tests to
        /// prove the seal is correct and reversible. Returns the decrypted header body.
        /// </summary>
        public static byte[] OpenVMessAEADHeader(byte[] cmdKey, byte[] wire)
        {
            var authId = Slice(wire, 0, 16);
            var encLength = Slice(wire, 16, 18);              // 2 + 16
            var connectionNonce = Slice(wire, 34, 8);

            var lenKey = VmessKdf.Kdf16(cmdKey, VmessKdf.LabelVMessHeaderPayloadLengthKey, authId, connectionNonce);
            var lenNonce = VmessKdf.Kdf12(cmdKey, VmessKdf.LabelVMessHeaderPayloadLengthIV, authId, connectionNonce);
            var lengthBytes = GcmOpen(lenKey, lenNonce, encLength, authId);
            int dataLen = ((lengthBytes[0] & 0xFF) << 8) | (lengthBytes[1] & 0xFF);

            var encPayload = Slice(wire, 42, dataLen + 16);
            var payloadKey = VmessKdf.Kdf16(cmdKey, VmessKdf.LabelVMessHeaderPayloadAEADKey, authId, connectionNonce);
            var payloadNonce = VmessKdf.Kdf12(cmdKey, VmessKdf.LabelVMessHeaderPayloadAEADIV, authId, connectionNonce);
            return GcmOpen(payloadKey, payloadNonce, encPayload, authId);
        }

        // ---- AES-128-GCM helpers (BouncyCastle, pure-managed) ----

        public static byte[] GcmSeal(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
        {
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(true, new AeadParameters(new KeyParameter(key), TagBits, nonce, aad));
            var outBuf = new byte[gcm.GetOutputSize(plaintext.Length)];
            int n = gcm.ProcessBytes(plaintext, 0, plaintext.Length, outBuf, 0);
            n += gcm.DoFinal(outBuf, n);
            if (n != outBuf.Length) Array.Resize(ref outBuf, n);
            return outBuf;
        }

        public static byte[] GcmOpen(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad)
        {
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(false, new AeadParameters(new KeyParameter(key), TagBits, nonce, aad));
            var outBuf = new byte[gcm.GetOutputSize(ciphertext.Length)];
            int n = gcm.ProcessBytes(ciphertext, 0, ciphertext.Length, outBuf, 0);
            n += gcm.DoFinal(outBuf, n);
            if (n != outBuf.Length) Array.Resize(ref outBuf, n);
            return outBuf;
        }

        // Single-block AES-128-ECB encryption (BouncyCastle AesEngine, no padding).
        private static byte[] AesEcbEncryptBlock(byte[] key, byte[] block16)
        {
            var aes = new AesEngine();
            aes.Init(true, new KeyParameter(key));
            var outBuf = new byte[16];
            aes.ProcessBlock(block16, 0, outBuf, 0);
            return outBuf;
        }

        private static byte[] Slice(byte[] src, int offset, int length)
        {
            var outBuf = new byte[length];
            Buffer.BlockCopy(src, offset, outBuf, 0, length);
            return outBuf;
        }
    }

    /// <summary>CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320) — used for the VMess Auth ID.</summary>
    public static class Crc32
    {
        private static readonly uint[] Table = BuildTable();

        private static uint[] BuildTable()
        {
            var table = new uint[256];
            for (uint i = 0; i < 256; i++)
            {
                uint c = i;
                for (int k = 0; k < 8; k++)
                    c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
                table[i] = c;
            }
            return table;
        }

        public static uint Compute(byte[] data, int offset, int length)
        {
            uint crc = 0xFFFFFFFF;
            for (int i = 0; i < length; i++)
                crc = Table[(crc ^ data[offset + i]) & 0xFF] ^ (crc >> 8);
            return crc ^ 0xFFFFFFFF;
        }
    }
}

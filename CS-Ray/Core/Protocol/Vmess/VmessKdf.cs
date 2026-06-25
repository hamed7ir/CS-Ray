using System;
using System.Security.Cryptography;
using System.Text;

namespace CS_Ray.Core.Protocol.Vmess
{
    /// <summary>
    /// VMess AEAD KDF — a recursively nested HMAC-SHA256 construction (NOT HKDF, NOT EVP).
    ///
    /// kdf(key, path...) builds a chain of HMACs: the innermost hash is HMAC-SHA256 keyed with
    /// "VMess AEAD KDF"; each subsequent path label wraps the previous one as the underlying hash
    /// (hmac.New(parent, label)). The final HMAC is then fed <paramref name="key"/> as its message.
    /// Every level's block size is 64 because the leaf hash is always SHA-256.
    /// </summary>
    public static class VmessKdf
    {
        private const int BlockSize = 64; // SHA-256 block size, constant through the nest

        // KDF salt label constants (exact strings from v2ray-core).
        public static readonly byte[] LabelAuthIDEncryptionKey          = Ascii("AES Auth ID Encryption");
        public static readonly byte[] LabelVMessHeaderPayloadAEADKey    = Ascii("VMess Header AEAD Key");
        public static readonly byte[] LabelVMessHeaderPayloadAEADIV     = Ascii("VMess Header AEAD Nonce");
        public static readonly byte[] LabelVMessHeaderPayloadLengthKey  = Ascii("VMess Header AEAD Key_Length");
        public static readonly byte[] LabelVMessHeaderPayloadLengthIV   = Ascii("VMess Header AEAD Nonce_Length");
        public static readonly byte[] LabelAEADRespHeaderLenKey         = Ascii("AEAD Resp Header Len Key");
        public static readonly byte[] LabelAEADRespHeaderLenIV          = Ascii("AEAD Resp Header Len IV");
        public static readonly byte[] LabelAEADRespHeaderPayloadKey     = Ascii("AEAD Resp Header Key");
        public static readonly byte[] LabelAEADRespHeaderPayloadIV      = Ascii("AEAD Resp Header IV");

        private static readonly byte[] RootKey = Ascii("VMess AEAD KDF");

        private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

        /// <summary>Full 32-byte KDF output.</summary>
        public static byte[] Kdf(byte[] key, params byte[][] path)
        {
            Func<byte[], byte[]> h = Sha256;          // leaf hash
            h = MakeHmac(RootKey, h);                 // HMAC(key="VMess AEAD KDF", H=SHA256)
            foreach (var label in path)
                h = MakeHmac(label, h);               // wrap each label as a nested HMAC
            return h(key);                            // feed the key as the final message
        }

        /// <summary>First 16 bytes of the KDF output (AES-128 key).</summary>
        public static byte[] Kdf16(byte[] key, params byte[][] path)
        {
            var full = Kdf(key, path);
            var outBuf = new byte[16];
            Buffer.BlockCopy(full, 0, outBuf, 0, 16);
            return outBuf;
        }

        /// <summary>First 12 bytes of the KDF output (AES-GCM nonce).</summary>
        public static byte[] Kdf12(byte[] key, params byte[][] path)
        {
            var full = Kdf(key, path);
            var outBuf = new byte[12];
            Buffer.BlockCopy(full, 0, outBuf, 0, 12);
            return outBuf;
        }

        // Returns a hash function H'(msg) = HMAC(key, msg) computed over the inner hash H.
        private static Func<byte[], byte[]> MakeHmac(byte[] key, Func<byte[], byte[]> innerHash)
            => msg => HmacWith(innerHash, key, msg);

        // Standard HMAC using an arbitrary underlying hash function H (block size 64 here).
        private static byte[] HmacWith(Func<byte[], byte[]> h, byte[] key, byte[] message)
        {
            if (key.Length > BlockSize)
                key = h(key);

            var k = new byte[BlockSize];
            Buffer.BlockCopy(key, 0, k, 0, key.Length);

            var innerInput = new byte[BlockSize + message.Length];
            var outerPrefix = new byte[BlockSize];
            for (int i = 0; i < BlockSize; i++)
            {
                innerInput[i] = (byte)(k[i] ^ 0x36); // ipad
                outerPrefix[i] = (byte)(k[i] ^ 0x5c); // opad
            }
            Buffer.BlockCopy(message, 0, innerInput, BlockSize, message.Length);
            var inner = h(innerInput);

            var outerInput = new byte[BlockSize + inner.Length];
            Buffer.BlockCopy(outerPrefix, 0, outerInput, 0, BlockSize);
            Buffer.BlockCopy(inner, 0, outerInput, BlockSize, inner.Length);
            return h(outerInput);
        }

        private static byte[] Sha256(byte[] data)
        {
            using (var sha = SHA256.Create())
                return sha.ComputeHash(data);
        }
    }
}

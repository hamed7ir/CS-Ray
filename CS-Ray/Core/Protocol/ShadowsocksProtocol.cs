using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CS_Ray.Core.Protocol
{
    /// <summary>
    /// Shadowsocks AEAD crypto helpers (classic AEAD: chacha20-ietf-poly1305 / aes-gcm).
    ///
    /// Two-stage key schedule (do not mix them up):
    ///   1. Master key  = OpenSSL EVP_BytesToKey(MD5) of the password, truncated to key length.
    ///   2. Per-connection subkey = HKDF-SHA1(ikm=masterKey, salt=randomSalt, info="ss-subkey").
    ///
    /// Wire format per direction: a cleartext salt (saltLen bytes) once at stream start, then
    /// AEAD chunks: [enc 2-byte BE length][16B tag][enc payload][16B tag], payload ≤ 0x3FFF.
    /// Nonce is a 12-byte little-endian counter starting at 0, incremented after EACH AEAD op,
    /// independent per direction.
    /// </summary>
    public static class ShadowsocksProtocol
    {
        public const int NonceLength = 12;
        public const int TagLength = 16;          // 128-bit Poly1305 / GCM tag
        public const int MaxPayload = 0x3FFF;
        private static readonly byte[] SubkeyInfo = Encoding.ASCII.GetBytes("ss-subkey");

        /// <summary>Master key via the legacy OpenSSL EVP_BytesToKey using MD5 (NOT HKDF).</summary>
        public static byte[] EvpBytesToKey(string password, int keyLen)
        {
            var pw = Encoding.UTF8.GetBytes(password ?? string.Empty);
            var result = new List<byte>(keyLen);
            var prev = Array.Empty<byte>();
            using (var md5 = MD5.Create())
            {
                while (result.Count < keyLen)
                {
                    var data = new byte[prev.Length + pw.Length];
                    Buffer.BlockCopy(prev, 0, data, 0, prev.Length);
                    Buffer.BlockCopy(pw, 0, data, prev.Length, pw.Length);
                    prev = md5.ComputeHash(data);
                    result.AddRange(prev);
                }
            }
            return result.GetRange(0, keyLen).ToArray();
        }

        /// <summary>Per-connection subkey = HKDF-SHA1(masterKey, salt, "ss-subkey").</summary>
        public static byte[] DeriveSubkey(byte[] masterKey, byte[] salt, int keyLen)
        {
            var hkdf = new HkdfBytesGenerator(new Sha1Digest());
            hkdf.Init(new HkdfParameters(masterKey, salt, SubkeyInfo));
            var outBuf = new byte[keyLen];
            hkdf.GenerateBytes(outBuf, 0, keyLen);
            return outBuf;
        }

        /// <summary>Shadowsocks target address header in SOCKS5 ATYP form: [ATYP][addr][port BE].</summary>
        public static byte[] BuildAddressHeader(string host, int port)
        {
            using (var ms = new MemoryStream())
            {
                if (IPAddress.TryParse(host, out var ip))
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        ms.WriteByte(0x01);                    // IPv4
                        var b = ip.GetAddressBytes(); ms.Write(b, 0, b.Length);
                    }
                    else
                    {
                        ms.WriteByte(0x04);                    // IPv6
                        var b = ip.GetAddressBytes(); ms.Write(b, 0, b.Length);
                    }
                }
                else
                {
                    var domain = Encoding.ASCII.GetBytes(host);
                    ms.WriteByte(0x03);                        // domain
                    ms.WriteByte((byte)domain.Length);
                    ms.Write(domain, 0, domain.Length);
                }
                ms.WriteByte((byte)(port >> 8));
                ms.WriteByte((byte)(port & 0xFF));
                return ms.ToArray();
            }
        }

        /// <summary>AEAD seal: returns ciphertext||tag. macSize is 128 bits.</summary>
        public static byte[] Seal(IAeadCipher cipher, byte[] key, byte[] nonce, byte[] plaintext, int offset, int length)
        {
            cipher.Init(true, new AeadParameters(new KeyParameter(key), TagLength * 8, nonce));
            var outBuf = new byte[cipher.GetOutputSize(length)];
            int n = cipher.ProcessBytes(plaintext, offset, length, outBuf, 0);
            n += cipher.DoFinal(outBuf, n);
            if (n != outBuf.Length) Array.Resize(ref outBuf, n);
            return outBuf;
        }

        /// <summary>AEAD open: verifies tag and returns plaintext (throws on tag mismatch).</summary>
        public static byte[] Open(IAeadCipher cipher, byte[] key, byte[] nonce, byte[] ciphertext)
        {
            cipher.Init(false, new AeadParameters(new KeyParameter(key), TagLength * 8, nonce));
            var outBuf = new byte[cipher.GetOutputSize(ciphertext.Length)];
            int n = cipher.ProcessBytes(ciphertext, 0, ciphertext.Length, outBuf, 0);
            n += cipher.DoFinal(outBuf, n);
            if (n != outBuf.Length) Array.Resize(ref outBuf, n);
            return outBuf;
        }

        /// <summary>Increment a little-endian nonce counter in place.</summary>
        public static void IncrementNonce(byte[] nonce)
        {
            for (int i = 0; i < nonce.Length; i++)
                if (++nonce[i] != 0) break;
        }

        /// <summary>Cipher parameters + a factory for a fresh AEAD cipher instance.</summary>
        public sealed class AeadCipherSpec
        {
            public int KeyLength { get; }
            public int SaltLength { get; }
            private readonly Func<IAeadCipher> _factory;

            public AeadCipherSpec(int keyLength, int saltLength, Func<IAeadCipher> factory)
            {
                KeyLength = keyLength;
                SaltLength = saltLength;
                _factory = factory;
            }

            public IAeadCipher CreateCipher() => _factory();
        }

        /// <summary>
        /// Resolve a method name to its AEAD spec. Only chacha20-ietf-poly1305 is wired/tested now;
        /// aes-256-gcm / aes-128-gcm are structured to slot in (GcmBlockCipher + AesEngine).
        /// </summary>
        public static AeadCipherSpec GetSpec(string method)
        {
            switch ((method ?? string.Empty).Trim().ToLowerInvariant())
            {
                case "chacha20-ietf-poly1305":
                case "chacha20-poly1305":
                    return new AeadCipherSpec(32, 32, () => new ChaCha20Poly1305());
                case "aes-256-gcm":
                    return new AeadCipherSpec(32, 32, () => new GcmBlockCipher(new AesEngine()));
                case "aes-128-gcm":
                    return new AeadCipherSpec(16, 16, () => new GcmBlockCipher(new AesEngine()));
                default:
                    throw new NotSupportedException("Unsupported Shadowsocks method: " + method);
            }
        }
    }

    /// <summary>
    /// A duplex <see cref="Stream"/> applying Shadowsocks AEAD over an inner transport stream.
    /// Write: sends the salt once, prepends the target address header to the first plaintext, then
    /// emits length+payload AEAD chunks. Read: consumes the server salt once, then decrypts chunks,
    /// retaining partial-chunk payload in a leftover buffer across <see cref="ReadAsync"/> calls.
    /// Independent nonce counters per direction.
    /// </summary>
    public class ShadowsocksStream : Stream
    {
        private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        private readonly Stream _inner;
        private readonly byte[] _masterKey;
        private readonly ShadowsocksProtocol.AeadCipherSpec _spec;
        private readonly byte[] _addressHeader;

        // write / encrypt
        private IAeadCipher _enc;
        private byte[] _encKey;
        private readonly byte[] _encNonce = new byte[ShadowsocksProtocol.NonceLength];
        private bool _started;

        // read / decrypt
        private IAeadCipher _dec;
        private byte[] _decKey;
        private readonly byte[] _decNonce = new byte[ShadowsocksProtocol.NonceLength];
        private bool _serverSaltRead;
        private byte[] _leftover;
        private int _leftoverOffset;
        private int _leftoverCount;

        public ShadowsocksStream(Stream inner, byte[] masterKey, ShadowsocksProtocol.AeadCipherSpec spec, byte[] addressHeader)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _masterKey = masterKey;
            _spec = spec;
            _addressHeader = addressHeader;
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

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (!_started)
            {
                _started = true;

                // 1) cleartext salt, 2) derive encrypt subkey from it
                var salt = new byte[_spec.SaltLength];
                Rng.GetBytes(salt);
                await _inner.WriteAsync(salt, 0, salt.Length, ct).ConfigureAwait(false);
                _encKey = ShadowsocksProtocol.DeriveSubkey(_masterKey, salt, _spec.KeyLength);
                _enc = _spec.CreateCipher();

                // first plaintext = address header || this write's payload
                int dataLen = count > 0 ? count : 0;
                var plain = new byte[_addressHeader.Length + dataLen];
                Buffer.BlockCopy(_addressHeader, 0, plain, 0, _addressHeader.Length);
                if (dataLen > 0) Buffer.BlockCopy(buffer, offset, plain, _addressHeader.Length, dataLen);
                await WriteChunksAsync(plain, 0, plain.Length, ct).ConfigureAwait(false);
                return;
            }

            if (count > 0)
                await WriteChunksAsync(buffer, offset, count, ct).ConfigureAwait(false);
        }

        private async Task WriteChunksAsync(byte[] data, int offset, int count, CancellationToken ct)
        {
            int pos = offset;
            int remaining = count;
            while (remaining > 0)
            {
                int chunk = Math.Min(remaining, ShadowsocksProtocol.MaxPayload);

                var lenBlock = new byte[] { (byte)(chunk >> 8), (byte)(chunk & 0xFF) };
                var encLen = ShadowsocksProtocol.Seal(_enc, _encKey, _encNonce, lenBlock, 0, 2);
                ShadowsocksProtocol.IncrementNonce(_encNonce);

                var encPayload = ShadowsocksProtocol.Seal(_enc, _encKey, _encNonce, data, pos, chunk);
                ShadowsocksProtocol.IncrementNonce(_encNonce);

                await _inner.WriteAsync(encLen, 0, encLen.Length, ct).ConfigureAwait(false);
                await _inner.WriteAsync(encPayload, 0, encPayload.Length, ct).ConfigureAwait(false);

                pos += chunk;
                remaining -= chunk;
            }
            await _inner.FlushAsync(ct).ConfigureAwait(false);
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return 0;

            if (!_serverSaltRead)
            {
                var salt = await ReadFullyAsync(_spec.SaltLength, ct).ConfigureAwait(false);
                if (salt == null) return 0;
                _decKey = ShadowsocksProtocol.DeriveSubkey(_masterKey, salt, _spec.KeyLength);
                _dec = _spec.CreateCipher();
                _serverSaltRead = true;
            }

            while (_leftoverCount == 0)
            {
                var payload = await ReadChunkAsync(ct).ConfigureAwait(false);
                if (payload == null) return 0; // EOF
                _leftover = payload;
                _leftoverOffset = 0;
                _leftoverCount = payload.Length;
            }

            int toCopy = Math.Min(count, _leftoverCount);
            Buffer.BlockCopy(_leftover, _leftoverOffset, buffer, offset, toCopy);
            _leftoverOffset += toCopy;
            _leftoverCount -= toCopy;
            return toCopy;
        }

        private async Task<byte[]> ReadChunkAsync(CancellationToken ct)
        {
            // length block: encrypted 2 bytes + tag
            var encLen = await ReadFullyAsync(2 + ShadowsocksProtocol.TagLength, ct).ConfigureAwait(false);
            if (encLen == null) return null;
            var lenBytes = ShadowsocksProtocol.Open(_dec, _decKey, _decNonce, encLen);
            ShadowsocksProtocol.IncrementNonce(_decNonce);

            int len = ((lenBytes[0] & 0xFF) << 8) | (lenBytes[1] & 0xFF);
            if (len <= 0 || len > ShadowsocksProtocol.MaxPayload)
                throw new InvalidOperationException("Shadowsocks chunk length out of range: " + len);

            var encPayload = await ReadFullyAsync(len + ShadowsocksProtocol.TagLength, ct).ConfigureAwait(false);
            if (encPayload == null) return null;
            var payload = ShadowsocksProtocol.Open(_dec, _decKey, _decNonce, encPayload);
            ShadowsocksProtocol.IncrementNonce(_decNonce);
            return payload;
        }

        private async Task<byte[]> ReadFullyAsync(int n, CancellationToken ct)
        {
            var buf = new byte[n];
            int off = 0;
            while (off < n)
            {
                int r = await _inner.ReadAsync(buf, off, n - off, ct).ConfigureAwait(false);
                if (r <= 0) return null; // EOF (clean or mid-chunk) → end the stream
                off += r;
            }
            return buf;
        }
    }
}

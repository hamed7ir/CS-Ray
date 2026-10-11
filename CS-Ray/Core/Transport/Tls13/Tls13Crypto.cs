using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CS_Ray.Core.Transport.Tls13
{
    /// <summary>A TLS 1.3 cipher suite: AEAD + transcript hash (RFC 8446 §B.4).</summary>
    internal sealed class Tls13Suite
    {
        public readonly ushort Id;
        public readonly int KeyLen;
        public readonly bool Sha384;
        public readonly bool ChaCha;
        private Tls13Suite(ushort id, int keyLen, bool sha384, bool chacha) { Id = id; KeyLen = keyLen; Sha384 = sha384; ChaCha = chacha; }

        public int HashLen => Sha384 ? 48 : 32;

        public static readonly Tls13Suite Aes128Gcm = new Tls13Suite(0x1301, 16, false, false);
        public static readonly Tls13Suite Aes256Gcm = new Tls13Suite(0x1302, 32, true, false);
        public static readonly Tls13Suite ChaCha20 = new Tls13Suite(0x1303, 32, false, true);

        public static Tls13Suite ById(ushort id)
            => id == 0x1301 ? Aes128Gcm : id == 0x1302 ? Aes256Gcm : id == 0x1303 ? ChaCha20 : null;

        public IDigest NewDigest() => Sha384 ? (IDigest)new Sha384Digest() : new Sha256Digest();
    }

    /// <summary>RFC 8446 §7 key schedule primitives (HKDF over the suite hash) — byte-exact, unit-testable.</summary>
    internal static class Tls13Kdf
    {
        public static byte[] Hash(Tls13Suite s, byte[] data)
        {
            var d = s.NewDigest();
            d.BlockUpdate(data, 0, data.Length);
            var o = new byte[d.GetDigestSize()];
            d.DoFinal(o, 0);
            return o;
        }

        public static byte[] Hmac(Tls13Suite s, byte[] key, byte[] data)
        {
            var h = new HMac(s.NewDigest());
            h.Init(new KeyParameter(key));
            h.BlockUpdate(data, 0, data.Length);
            var o = new byte[h.GetMacSize()];
            h.DoFinal(o, 0);
            return o;
        }

        /// <summary>HKDF-Extract(salt, IKM) = HMAC(salt, IKM); a null salt is HashLen zero bytes.</summary>
        public static byte[] Extract(Tls13Suite s, byte[] salt, byte[] ikm)
            => Hmac(s, salt ?? new byte[s.HashLen], ikm ?? new byte[s.HashLen]);

        public static byte[] Expand(Tls13Suite s, byte[] prk, byte[] info, int length)
        {
            var output = new byte[length];
            byte[] t = new byte[0];
            int done = 0;
            for (byte i = 1; done < length; i++)
            {
                var input = new byte[t.Length + info.Length + 1];
                Buffer.BlockCopy(t, 0, input, 0, t.Length);
                Buffer.BlockCopy(info, 0, input, t.Length, info.Length);
                input[input.Length - 1] = i;
                t = Hmac(s, prk, input);
                int n = Math.Min(t.Length, length - done);
                Buffer.BlockCopy(t, 0, output, done, n);
                done += n;
            }
            return output;
        }

        /// <summary>HKDF-Expand-Label(Secret, Label, Context, Length): HkdfLabel = uint16 length || opaque "tls13 "+label
        /// || opaque context.</summary>
        public static byte[] ExpandLabel(Tls13Suite s, byte[] secret, string label, byte[] context, int length)
        {
            byte[] l = Encoding.ASCII.GetBytes("tls13 " + label);
            context = context ?? new byte[0];
            var info = new byte[2 + 1 + l.Length + 1 + context.Length];
            info[0] = (byte)(length >> 8); info[1] = (byte)length;
            info[2] = (byte)l.Length;
            Buffer.BlockCopy(l, 0, info, 3, l.Length);
            info[3 + l.Length] = (byte)context.Length;
            Buffer.BlockCopy(context, 0, info, 4 + l.Length, context.Length);
            return Expand(s, secret, info, length);
        }

        /// <summary>Derive-Secret(Secret, Label, Messages) = Expand-Label(Secret, Label, Transcript-Hash(Messages), HashLen);
        /// <paramref name="transcriptHash"/> is the already-computed hash (empty-messages hash for "derived").</summary>
        public static byte[] DeriveSecret(Tls13Suite s, byte[] secret, string label, byte[] transcriptHash)
            => ExpandLabel(s, secret, label, transcriptHash, s.HashLen);

        public static byte[] EmptyHash(Tls13Suite s) => Hash(s, new byte[0]);
    }

    /// <summary>Per-direction record protection: key + static IV + 64-bit sequence (RFC 8446 §5.3).</summary>
    internal sealed class Tls13RecordKeys
    {
        private readonly Tls13Suite _suite;
        private readonly byte[] _key, _iv;
        public byte[] Secret { get; }
        private ulong _seq;

        public Tls13RecordKeys(Tls13Suite suite, byte[] trafficSecret)
        {
            _suite = suite;
            Secret = trafficSecret;
            _key = Tls13Kdf.ExpandLabel(suite, trafficSecret, "key", null, suite.KeyLen);
            _iv = Tls13Kdf.ExpandLabel(suite, trafficSecret, "iv", null, 12);
        }

        /// <summary>The next generation after a KeyUpdate: application_traffic_secret_N+1.</summary>
        public Tls13RecordKeys Next() => new Tls13RecordKeys(_suite, Tls13Kdf.ExpandLabel(_suite, Secret, "traffic upd", null, _suite.HashLen));

        private byte[] Nonce()
        {
            var n = (byte[])_iv.Clone();
            ulong seq = _seq++;
            for (int i = 0; i < 8; i++) n[11 - i] ^= (byte)(seq >> (8 * i));
            return n;
        }

        private IAeadCipher NewCipher()
            => _suite.ChaCha ? (IAeadCipher)new ChaCha20Poly1305() : new GcmBlockCipher(new AesEngine());

        /// <summary>Encrypt TLSInnerPlaintext (content || type) into a full TLSCiphertext record (header included).</summary>
        public byte[] Seal(byte contentType, byte[] data, int offset, int count)
        {
            int ctLen = count + 1 + 16;
            var record = new byte[5 + ctLen];
            record[0] = 0x17; record[1] = 0x03; record[2] = 0x03;
            record[3] = (byte)(ctLen >> 8); record[4] = (byte)ctLen;
            var inner = new byte[count + 1];
            Buffer.BlockCopy(data, offset, inner, 0, count);
            inner[count] = contentType;
            var aad = new byte[5]; Buffer.BlockCopy(record, 0, aad, 0, 5);
            var c = NewCipher();
            c.Init(true, new AeadParameters(new KeyParameter(_key), 128, Nonce(), aad));
            int n = c.ProcessBytes(inner, 0, inner.Length, record, 5);
            c.DoFinal(record, 5 + n);
            return record;
        }

        /// <summary>Decrypt a TLSCiphertext body; returns the inner content (padding stripped) and its real content type.</summary>
        public byte[] Open(byte[] header5, byte[] body, out byte contentType)
        {
            var c = NewCipher();
            c.Init(false, new AeadParameters(new KeyParameter(_key), 128, Nonce(), header5));
            var plain = new byte[c.GetOutputSize(body.Length)];
            int n = c.ProcessBytes(body, 0, body.Length, plain, 0);
            n += c.DoFinal(plain, n);   // throws InvalidCipherTextException on a bad tag
            int end = n - 1;
            while (end >= 0 && plain[end] == 0) end--;   // strip zero padding
            if (end < 0) throw new Tls13Exception("TLS: record with no content type");
            contentType = plain[end];
            var content = new byte[end];
            Buffer.BlockCopy(plain, 0, content, 0, end);
            return content;
        }
    }

    /// <summary>
    /// Just enough DER to pull the SubjectPublicKeyInfo and signatureValue out of a certificate. Deliberately not a full
    /// X.509 parser: REALITY's per-connection certificate (serial 0, empty names, year-0001 validity) is rejected by
    /// BouncyCastle's X509CertificateParser, and TLS 1.3 only needs the leaf key for CertificateVerify anyway.
    /// </summary>
    internal static class Tls13Der
    {
        /// <param name="spki">the complete SubjectPublicKeyInfo element (tag + length + content)</param>
        /// <param name="signature">the signatureValue BIT STRING content without its unused-bits byte</param>
        public static void SplitCertificate(byte[] der, out byte[] spki, out byte[] signature)
        {
            int p = 0;
            int certEnd = Enter(der, ref p, 0x30);               // Certificate
            int tbsEnd = Enter(der, ref p, 0x30);                // tbsCertificate
            if (der[p] == 0xa0) Skip(der, ref p);                // [0] version
            for (int i = 0; i < 5; i++) Skip(der, ref p);        // serial, signature alg, issuer, validity, subject
            int spkiStart = p;
            Skip(der, ref p);
            spki = Slice(der, spkiStart, p - spkiStart);
            p = tbsEnd;
            Skip(der, ref p);                                    // signatureAlgorithm
            int sigEnd = Enter(der, ref p, 0x03);                // signatureValue BIT STRING
            if (sigEnd > certEnd || p >= sigEnd) throw new Tls13Exception("TLS: malformed certificate");
            signature = Slice(der, p + 1, sigEnd - p - 1);
        }

        // Reads a TLV header at p; returns the content end and leaves p at the content start.
        private static int Header(byte[] d, ref int p, out byte tag)
        {
            if (p + 2 > d.Length) throw new Tls13Exception("TLS: truncated certificate");
            tag = d[p++];
            int len = d[p++];
            if (len >= 0x80)
            {
                int n = len & 0x7f;
                if (n == 0 || n > 3 || p + n > d.Length) throw new Tls13Exception("TLS: malformed certificate length");
                len = 0;
                for (int i = 0; i < n; i++) len = (len << 8) | d[p++];
            }
            if (p + len > d.Length) throw new Tls13Exception("TLS: truncated certificate");
            return p + len;
        }

        private static int Enter(byte[] d, ref int p, byte expectTag)
        {
            int end = Header(d, ref p, out byte tag);
            if (tag != expectTag) throw new Tls13Exception("TLS: unexpected certificate structure");
            return end;
        }

        private static void Skip(byte[] d, ref int p) { p = Header(d, ref p, out _); }

        private static byte[] Slice(byte[] a, int off, int len) { var r = new byte[len]; Buffer.BlockCopy(a, off, r, 0, len); return r; }
    }

    internal sealed class Tls13Exception : Exception
    {
        public Tls13Exception(string message) : base(message) { }
        public Tls13Exception(string message, Exception inner) : base(message, inner) { }
    }
}

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CS_Ray.Core.Transport.Tls13
{
    /// <summary>Browser ClientHello shapes we can emit (uTLS presets as pinned by Xray-core v26.10).</summary>
    internal enum HelloProfile
    {
        /// <summary>uTLS HelloChrome_133 — Xray's "chrome" (and default): X25519MLKEM768 + X25519 shares (independent
        /// x25519 keys, as BoringSSL's ssl_setup_key_shares generates them), ALPS, GREASE-ECH,
        /// shuffled extensions. Required by REALITY servers ≥ Xray v26.9.8.</summary>
        Chrome133,
        /// <summary>uTLS HelloEdge_85 — Xray's "edge": X25519 only, fixed order, padded to 512 bytes. Works with REALITY
        /// servers that predate the hybrid-share rule (and with pre-2025 servers that choke on the hybrid share).</summary>
        Edge85,
    }

    /// <summary>A built ClientHello: the raw handshake message (type+len+body) plus what the handshake needs from it.</summary>
    internal sealed class ClientHelloResult
    {
        public byte[] Raw;                         // handshake message bytes (msg_type 1 + uint24 length + body)
        public byte[] Random;                      // the 32-byte client random
        public int SessionIdOffset;                // offset of the 32-byte legacy_session_id inside Raw (= 39)
        public X25519PrivateKeyParameters X25519;        // the standalone x25519 share's key (REALITY derives AuthKey from it)
        public X25519PrivateKeyParameters X25519Hybrid;  // the X25519MLKEM768 share's x25519 half (independent, like BoringSSL)
        public MLKemPrivateKeyParameters MlKem;          // ML-KEM-768 decapsulation key when an X25519MLKEM768 share was offered
    }

    /// <summary>
    /// Builds browser-shaped TLS 1.3 ClientHellos byte-for-byte like uTLS (GREASE derivation, cipher-suite order,
    /// extension set, Chrome's extension shuffle, BoringSSL padding). Every byte is ours, so REALITY can rewrite the
    /// 32-byte legacy_session_id over the finished hello.
    /// </summary>
    internal static class ClientHelloBuilder
    {
        public const ushort GroupX25519 = 0x001d;
        public const ushort GroupX25519MlKem768 = 0x11ec;

        private static readonly SecureRandom Rng = new SecureRandom();
        private static readonly int[] EchPayloadLens = { 144, 176, 208, 240 };

        /// <summary>Maps an Xray/share-link <c>fp</c> value to the closest profile we implement. Fingerprints whose uTLS
        /// preset sends the hybrid key share map to Chrome133; the rest (x25519-only) map to Edge85 — what matters for
        /// REALITY compatibility is whether the hybrid share is present, exactly as with Xray using that fp.</summary>
        public static HelloProfile ProfileFor(string fp)
        {
            switch ((fp ?? "").Trim().ToLowerInvariant())
            {
                case "edge": case "helloedge_85": case "helloedge_auto": case "helloedge_106":
                case "ios": case "helloios_13": case "helloios_14": case "helloios_auto":
                case "android": case "helloandroid_11_okhttp":
                case "360": case "hello360_auto": case "hello360_7_5": case "hello360_11_0":
                case "qq": case "helloqq_auto": case "helloqq_11_1":
                    return HelloProfile.Edge85;
                default:   // "", chrome, firefox, safari, random, randomized, hellochrome_*: hybrid-share presets
                    return HelloProfile.Chrome133;
            }
        }

        /// <param name="alpn">ALPN ids to offer; null = the browser default (h2, http/1.1).</param>
        public static ClientHelloResult Build(string serverName, string[] alpn, HelloProfile profile)
        {
            var r = new ClientHelloResult();
            r.Random = new byte[32]; Rng.NextBytes(r.Random);
            r.X25519 = new X25519PrivateKeyParameters(Rng);
            byte[] x25519Pub = r.X25519.GeneratePublicKey().GetEncoded();
            if (alpn == null) alpn = new[] { "h2", "http/1.1" };

            // GREASE seeds (BoringSSL/uTLS index map): 0 cipher, 1 group (supported_groups AND key_share), 2 ext1, 3 ext2, 4 version.
            ushort gCipher = Grease(), gGroup = Grease(), gExt1 = Grease(), gExt2 = Grease(), gVer = Grease();
            if (gExt2 == gExt1) gExt2 ^= 0x1010;

            var exts = new List<KeyValuePair<ushort, byte[]>>();
            string sni = SniName(serverName);
            byte[] sniExt = null;
            if (sni != null)
            {
                byte[] host = Encoding.ASCII.GetBytes(sni);
                var sn = new MemoryStream(); W16(sn, host.Length + 3); sn.WriteByte(0); W16(sn, host.Length); sn.Write(host, 0, host.Length);
                sniExt = sn.ToArray();
            }
            byte[] alpnExt = null;
            if (alpn.Length > 0)
            {
                var a = new MemoryStream();
                foreach (var p in alpn) { var pb = Encoding.ASCII.GetBytes(p); a.WriteByte((byte)pb.Length); a.Write(pb, 0, pb.Length); }
                var al = new MemoryStream(); W16(al, (int)a.Length); a.WriteTo(al);
                alpnExt = al.ToArray();
            }
            byte[] sigAlgs = List16(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601);

            if (profile == HelloProfile.Chrome133)
            {
                var kp = new MLKemKeyPairGenerator();
                kp.Init(new MLKemKeyGenerationParameters(Rng, MLKemParameters.ml_kem_768));
                var pair = kp.GenerateKeyPair();
                r.MlKem = (MLKemPrivateKeyParameters)pair.Private;
                byte[] ek = ((MLKemPublicKeyParameters)pair.Public).GetEncoded();   // 1184 bytes
                r.X25519Hybrid = new X25519PrivateKeyParameters(Rng);
                byte[] hybridPub = r.X25519Hybrid.GeneratePublicKey().GetEncoded();

                var ks = new MemoryStream();
                W16(ks, gGroup); W16(ks, 1); ks.WriteByte(0);                                   // GREASE share (1 byte)
                W16(ks, GroupX25519MlKem768); W16(ks, ek.Length + 32);                          // hybrid: ek || x25519 (1216)
                ks.Write(ek, 0, ek.Length); ks.Write(hybridPub, 0, 32);
                W16(ks, GroupX25519); W16(ks, 32); ks.Write(x25519Pub, 0, 32);                  // standalone x25519 (own key)
                var ksl = new MemoryStream(); W16(ksl, (int)ks.Length); ks.WriteTo(ksl);

                if (sniExt != null) Add(exts, 0x0000, sniExt);                                  // server_name
                Add(exts, 0x0017, new byte[0]);                                                 // extended_master_secret
                Add(exts, 0xff01, new byte[] { 0 });                                            // renegotiation_info
                Add(exts, 0x000a, List16(gGroup, GroupX25519MlKem768, GroupX25519, 0x0017, 0x0018)); // supported_groups
                Add(exts, 0x000b, new byte[] { 1, 0 });                                         // ec_point_formats
                Add(exts, 0x0023, new byte[0]);                                                 // session_ticket
                if (alpnExt != null) Add(exts, 0x0010, alpnExt);                                // ALPN
                Add(exts, 0x0005, new byte[] { 1, 0, 0, 0, 0 });                                // status_request
                Add(exts, 0x000d, sigAlgs);                                                     // signature_algorithms
                Add(exts, 0x0012, new byte[0]);                                                 // SCT
                Add(exts, 0x0033, ksl.ToArray());                                               // key_share
                Add(exts, 0x002d, new byte[] { 1, 1 });                                         // psk_key_exchange_modes
                var sv = new MemoryStream(); sv.WriteByte(6); W16(sv, gVer); W16(sv, 0x0304); W16(sv, 0x0303);
                Add(exts, 0x002b, sv.ToArray());                                                // supported_versions
                Add(exts, 0x001b, new byte[] { 2, 0, 2 });                                      // compress_certificate: brotli
                if (Array.IndexOf(alpn, "h2") >= 0) Add(exts, 0x44cd, new byte[] { 0, 3, 2, (byte)'h', (byte)'2' }); // ALPS (new codepoint)
                Add(exts, 0xfe0d, GreaseEch());                                                 // GREASE ECH
                Shuffle(exts);                                                                  // Chrome ≥106: every non-GREASE ext
                exts.Insert(0, new KeyValuePair<ushort, byte[]>(gExt1, new byte[0]));           // GREASE ext1 (first, empty)
                exts.Add(new KeyValuePair<ushort, byte[]>(gExt2, new byte[] { 0 }));            // GREASE ext2 (last, 1 byte)
            }
            else
            {
                var ks = new MemoryStream();
                W16(ks, gGroup); W16(ks, 1); ks.WriteByte(0);
                W16(ks, GroupX25519); W16(ks, 32); ks.Write(x25519Pub, 0, 32);
                var ksl = new MemoryStream(); W16(ksl, (int)ks.Length); ks.WriteTo(ksl);

                Add(exts, gExt1, new byte[0]);
                if (sniExt != null) Add(exts, 0x0000, sniExt);
                Add(exts, 0x0017, new byte[0]);
                Add(exts, 0xff01, new byte[] { 0 });
                Add(exts, 0x000a, List16(gGroup, GroupX25519, 0x0017, 0x0018));
                Add(exts, 0x000b, new byte[] { 1, 0 });
                Add(exts, 0x0023, new byte[0]);
                if (alpnExt != null) Add(exts, 0x0010, alpnExt);
                Add(exts, 0x0005, new byte[] { 1, 0, 0, 0, 0 });
                Add(exts, 0x000d, sigAlgs);
                Add(exts, 0x0012, new byte[0]);
                Add(exts, 0x0033, ksl.ToArray());
                Add(exts, 0x002d, new byte[] { 1, 1 });
                var sv = new MemoryStream(); sv.WriteByte(10); W16(sv, gVer); W16(sv, 0x0304); W16(sv, 0x0303); W16(sv, 0x0302); W16(sv, 0x0301);
                Add(exts, 0x002b, sv.ToArray());
                Add(exts, 0x001b, new byte[] { 2, 0, 2 });
                Add(exts, gExt2, new byte[] { 0 });
            }

            const int suitesLen = 16 * 2;
            int headerLen = 2 + 32 + 1 + 32 + 2 + suitesLen + 1 + 1;   // body bytes before the extensions block
            int extLen = 0;
            foreach (var e in exts) extLen += 4 + e.Value.Length;
            if (profile == HelloProfile.Edge85)
            {
                // BoringPaddingStyle: pad a 256..511-byte hello up to exactly 512 (uTLS UtlsPaddingExtension).
                int unpadded = headerLen + 4 + extLen + 2;
                if (unpadded > 0xff && unpadded < 0x200)
                {
                    int pad = 0x200 - unpadded;
                    pad = pad >= 5 ? pad - 4 : 1;
                    Add(exts, 0x0015, new byte[pad]);
                    extLen += 4 + pad;
                }
            }

            var body = new MemoryStream();
            W16(body, 0x0303);                                         // legacy_version
            body.Write(r.Random, 0, 32);
            body.WriteByte(32); body.Write(new byte[32], 0, 32);       // legacy_session_id placeholder (zeroed)
            ushort[] suites = { gCipher, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035 };
            W16(body, suites.Length * 2);
            foreach (var s in suites) W16(body, s);
            body.WriteByte(1); body.WriteByte(0);                      // compression: null
            W16(body, extLen);
            foreach (var e in exts) { W16(body, e.Key); W16(body, e.Value.Length); body.Write(e.Value, 0, e.Value.Length); }

            byte[] b = body.ToArray();
            r.Raw = new byte[4 + b.Length];
            r.Raw[0] = 1; r.Raw[1] = (byte)(b.Length >> 16); r.Raw[2] = (byte)(b.Length >> 8); r.Raw[3] = (byte)b.Length;
            Buffer.BlockCopy(b, 0, r.Raw, 4, b.Length);
            r.SessionIdOffset = 4 + 2 + 32 + 1;   // = 39
            return r;
        }

        // BoringGREASEECH (uTLS u_ech.go): outer ECH, HKDF-SHA256 / AES-128-GCM, random config id, a real X25519 enc,
        // random payload of 128/160/192/224 + 16 bytes.
        private static byte[] GreaseEch()
        {
            var m = new MemoryStream();
            m.WriteByte(0);                                // ClientHelloOuter
            W16(m, 0x0001); W16(m, 0x0001);                // kdf, aead
            var cid = new byte[1]; Rng.NextBytes(cid); m.WriteByte(cid[0]);
            byte[] enc = new X25519PrivateKeyParameters(Rng).GeneratePublicKey().GetEncoded();
            W16(m, enc.Length); m.Write(enc, 0, enc.Length);
            byte[] payload = new byte[EchPayloadLens[Rng.Next(EchPayloadLens.Length)]];
            Rng.NextBytes(payload);
            W16(m, payload.Length); m.Write(payload, 0, payload.Length);
            return m.ToArray();
        }

        private static void Shuffle(List<KeyValuePair<ushort, byte[]>> list)
        {
            for (int i = list.Count - 1; i > 0; i--)
            {
                int j = Rng.Next(i + 1);
                var t = list[i]; list[i] = list[j]; list[j] = t;
            }
        }

        // SNI is never an IP literal (RFC 6066); IDN → punycode; Go rejects a trailing dot.
        private static string SniName(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            IPAddress ip;
            if (IPAddress.TryParse(name.Trim('[', ']'), out ip)) return null;
            name = name.TrimEnd('.');
            try { return new IdnMapping().GetAscii(name); } catch { return name; }
        }

        private static ushort Grease()
        {
            var b = new byte[1]; Rng.NextBytes(b);
            int v = (b[0] & 0xf0) | 0x0a;   // 0x0A, 0x1A, … 0xFA
            return (ushort)((v << 8) | v);
        }

        private static void Add(List<KeyValuePair<ushort, byte[]>> l, ushort type, byte[] data) => l.Add(new KeyValuePair<ushort, byte[]>(type, data));

        private static void W16(Stream s, int v) { s.WriteByte((byte)(v >> 8)); s.WriteByte((byte)v); }

        private static byte[] List16(params ushort[] items)
        {
            var m = new MemoryStream(); W16(m, items.Length * 2);
            foreach (var i in items) W16(m, i);
            return m.ToArray();
        }
    }
}

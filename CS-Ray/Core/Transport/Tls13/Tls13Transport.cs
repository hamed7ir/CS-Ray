using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace CS_Ray.Core.Transport.Tls13
{
    /// <summary>VLESS <c>security=reality</c> parameters (share link: pbk / sid / sni / fp / spx).</summary>
    public sealed class RealityConfig
    {
        /// <summary>SNI sent in the ClientHello — must be in the server's serverNames. Empty = the dial host.</summary>
        public string ServerName;
        /// <summary>The server's static X25519 public key (32 bytes).</summary>
        public byte[] PublicKey;
        /// <summary>Short id, ≤ 8 bytes (right-padded with zeros on the wire).</summary>
        public byte[] ShortId = new byte[0];
        /// <summary>uTLS fingerprint name (Xray <c>fp</c>); empty = chrome.</summary>
        public string Fingerprint;

        /// <summary>Xray's version triple sent in the sealed session id. Servers only check it if minClientVer/maxClientVer
        /// is configured; we report the Xray release whose wire behaviour we follow.</summary>
        internal static readonly byte[] XrayVersion = { 26, 10, 10 };

        /// <summary>Parses a pbk value: base64url without padding (Xray), tolerating standard base64 / padding.</summary>
        public static byte[] ParsePublicKey(string pbk)
        {
            if (string.IsNullOrWhiteSpace(pbk)) return null;
            string s = pbk.Trim().Replace('-', '+').Replace('_', '/').TrimEnd('=');
            s = s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=');
            try { var k = Convert.FromBase64String(s); return k.Length == 32 ? k : null; }
            catch (FormatException) { return null; }
        }

        /// <summary>Parses a sid value: 0–16 hex chars, even length. Returns null when invalid.</summary>
        public static byte[] ParseShortId(string sid)
        {
            sid = (sid ?? "").Trim();
            if (sid.Length > 16 || sid.Length % 2 != 0) return null;
            var b = new byte[sid.Length / 2];
            for (int i = 0; i < b.Length; i++)
                if (!byte.TryParse(sid.Substring(2 * i, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out b[i])) return null;
            return b;
        }
    }

    /// <summary>
    /// Xray REALITY client authentication on top of <see cref="Tls13Stream"/> (Xray-core transport/internet/reality):
    /// the 32-byte legacy_session_id carries AES-256-GCM(AuthKey, nonce = Random[20:], AAD = the ClientHello with a
    /// zeroed session id) of {xray version, 0, unix time, shortId}, where AuthKey = HKDF-SHA256(X25519(our key-share
    /// private key, server pbk), salt = Random[:20], info "REALITY"). The server proves it holds the private key by
    /// presenting an ed25519 certificate whose signatureValue is HMAC-SHA512(AuthKey, ed25519 public key) — anything
    /// else means the server treated us as a stranger and spliced us to its camouflage target.
    /// </summary>
    internal sealed class RealityAuth
    {
        private readonly RealityConfig _cfg;
        private byte[] _authKey;

        public RealityAuth(RealityConfig cfg) { _cfg = cfg; }

        public Tls13ClientOptions Options(string serverName) => new Tls13ClientOptions
        {
            ServerName = serverName,
            Alpn = null,   // the browser default (h2, http/1.1) — REALITY's server never selects one
            Profile = ClientHelloBuilder.ProfileFor(_cfg.Fingerprint),
            PatchHello = Seal,
            VerifyCertificates = Verify,
            CompressedCertificateError = "REALITY: the server answered with its camouflage target's real (compressed) certificate" + RejectedHint,
        };

        private const string RejectedHint = " — authentication was rejected (wrong pbk/sid, SNI not in the server's serverNames, clock skew, "
                                          + "or the server needs the other key-share shape: try fp=chrome or fp=edge)";

        private void Seal(ClientHelloResult hello)
        {
            var suite = Tls13Suite.Aes128Gcm;   // its hash is SHA-256 — Tls13Kdf doubles as plain HKDF-SHA256 here
            byte[] shared = new byte[32];
            try { hello.X25519.GenerateSecret(new X25519PublicKeyParameters(_cfg.PublicKey, 0), shared, 0); }
            catch (Exception ex) { throw new Tls13Exception("REALITY: the public key (pbk) is not a valid X25519 key", ex); }
            byte[] salt = Tls13Stream.Slice(hello.Random, 0, 20);
            _authKey = Tls13Kdf.Expand(suite, Tls13Kdf.Extract(suite, salt, shared), System.Text.Encoding.ASCII.GetBytes("REALITY"), 32);

            var plain = new byte[16];
            Buffer.BlockCopy(RealityConfig.XrayVersion, 0, plain, 0, 3);
            uint now = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            plain[4] = (byte)(now >> 24); plain[5] = (byte)(now >> 16); plain[6] = (byte)(now >> 8); plain[7] = (byte)now;
            Buffer.BlockCopy(_cfg.ShortId, 0, plain, 8, Math.Min(8, _cfg.ShortId.Length));

            // AAD = the whole hello with the session id still zeroed (the builder leaves it zeroed).
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(true, new AeadParameters(new KeyParameter(_authKey), 128, Tls13Stream.Slice(hello.Random, 20, 12), hello.Raw));
            var sid = new byte[32];
            int n = gcm.ProcessBytes(plain, 0, 16, sid, 0);
            gcm.DoFinal(sid, n);
            Buffer.BlockCopy(sid, 0, hello.Raw, hello.SessionIdOffset, 32);
        }

        private string Verify(IList<byte[]> certs)
        {
            byte[] spki, signature;
            try { Tls13Der.SplitCertificate(certs[0], out spki, out signature); }
            catch (Tls13Exception) { return "REALITY: unparseable server certificate"; }
            Ed25519PublicKeyParameters ed = null;
            try { ed = PublicKeyFactory.CreateKey(spki) as Ed25519PublicKeyParameters; } catch (Exception) { }
            if (ed == null) return "REALITY: the server answered with the real certificate of " + SubjectOf(certs[0]) + RejectedHint;
            var h = new HMac(new Sha512Digest());
            h.Init(new KeyParameter(_authKey));
            byte[] pub = ed.GetEncoded();
            h.BlockUpdate(pub, 0, pub.Length);
            var expect = new byte[64];
            h.DoFinal(expect, 0);
            if (!Tls13Stream.FixedEquals(expect, signature))
                return "REALITY: the server's temporary certificate does not match our auth key (wrong pbk, or not a REALITY server)";
            return null;   // authenticated; Tls13Stream still checks CertificateVerify (ed25519) and Finished
        }

        private static string SubjectOf(byte[] der)
        {
            try { return new X509CertificateParser().ReadCertificate(der).SubjectDN.ToString(); }
            catch (Exception) { return "its target"; }
        }
    }

    /// <summary>
    /// A TLS 1.3 connection over <see cref="Tls13Stream"/>: REALITY when a <see cref="RealityConfig"/> is given, else
    /// ordinary certificate-validated TLS (browser-shaped hello; used by tests and for <c>fp</c>-fingerprinted TLS).
    /// Same contract as <see cref="BcTlsTransport"/>: cancellation tears the socket down at once.
    /// </summary>
    public sealed class Tls13Transport : ITransport
    {
        private readonly RealityConfig _reality;
        private readonly string _sni;
        private readonly string _fingerprint;
        private readonly string[] _alpn;
        private readonly TcpTransport _tcp = new TcpTransport();
        private Tls13Stream _stream;

        /// <summary>REALITY transport.</summary>
        public Tls13Transport(RealityConfig reality) { _reality = reality; _sni = reality.ServerName; _fingerprint = reality.Fingerprint; }

        /// <summary>Plain validated TLS 1.3 with a browser-shaped hello.</summary>
        public Tls13Transport(string sni, string fingerprint, string[] alpn) { _sni = sni; _fingerprint = fingerprint; _alpn = alpn; }

        public ushort CipherSuite => _stream?.CipherSuite ?? 0;
        public string NegotiatedAlpn => _stream?.NegotiatedAlpn;

        public async Task ConnectAsync(string host, int port, CancellationToken ct)
        {
            await _tcp.ConnectAsync(host, port, ct).ConfigureAwait(false);
            string serverName = string.IsNullOrEmpty(_sni) ? host : _sni;
            Tls13ClientOptions opt;
            if (_reality != null) opt = new RealityAuth(_reality).Options(serverName);
            else opt = new Tls13ClientOptions
            {
                ServerName = serverName, Alpn = _alpn, Profile = ClientHelloBuilder.ProfileFor(_fingerprint),
                VerifyCertificates = certs =>
                {
                    var inter = new List<byte[]>();
                    for (int i = 1; i < certs.Count; i++) inter.Add(certs[i]);
                    return TlsCertificateValidator.Validate(certs[0], inter, serverName);
                },
            };
            var stream = new Tls13Stream(_tcp.GetStream(), opt);
            using (ct.Register(() => { Close(); try { stream.Dispose(); } catch { } }))
            {
                try { await stream.HandshakeAsync(ct).ConfigureAwait(false); }
                catch (Exception) when (ct.IsCancellationRequested) { throw new OperationCanceledException(ct); }
            }
            ct.ThrowIfCancellationRequested();
            _stream = stream;
        }

        public Stream GetStream()
        {
            if (_stream == null) throw new InvalidOperationException("Tls13Transport is not connected.");
            return _stream;
        }

        public void Close()
        {
            try { _stream?.Dispose(); } catch { }
            _stream = null;
            _tcp.Close();
        }
    }
}

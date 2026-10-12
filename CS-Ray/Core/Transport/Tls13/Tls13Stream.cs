using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace CS_Ray.Core.Transport.Tls13
{
    /// <summary>Hooks that make the generic TLS 1.3 client do REALITY (or plain validated TLS).</summary>
    internal sealed class Tls13ClientOptions
    {
        public string ServerName;                 // SNI (omitted for IP literals)
        public string[] Alpn;                     // offered ALPN ids (null = the profile's browser default)
        public HelloProfile Profile = HelloProfile.Chrome133;
        /// <summary>Called with the finished ClientHello BEFORE it is hashed/sent; may rewrite bytes in Raw (REALITY's
        /// session id). Runs once.</summary>
        public Action<ClientHelloResult> PatchHello;
        /// <summary>Validates the server certificate list (DER, leaf first). Return null to accept, else a reason.</summary>
        public Func<IList<byte[]>, string> VerifyCertificates;
        /// <summary>Error text when the server sends a CompressedCertificate (we offer brotli for browser parity but can't
        /// decode it yet). REALITY overrides it: a REALITY server never compresses, only its camouflage target does.</summary>
        public string CompressedCertificateError;
        /// <summary>Appended to handshake failures that happen before the server's certificate was accepted (REALITY: a
        /// rejected client is spliced to the camouflage target, which can fail in many shapes).</summary>
        public string FailureHint;
    }

    /// <summary>
    /// A minimal, strict TLS 1.3 client (RFC 8446) over an async socket stream: 1-RTT x25519, suites 0x1301/2/3, no
    /// resumption / 0-RTT / HelloRetryRequest. We own every ClientHello byte (needed for REALITY and browser-shaped
    /// fingerprints). CertificateVerify is checked with the leaf key (ed25519 / ECDSA / RSA-PSS); acceptance of the leaf
    /// is delegated to <see cref="Tls13ClientOptions.VerifyCertificates"/>. After the handshake it is a duplex Stream with
    /// the same concurrency model as BcTlsStream: single reader, gated writers, the reader never waits on the write gate.
    /// </summary>
    internal sealed class Tls13Stream : Stream
    {
        private static readonly byte[] HrrRandom = Hex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

        private readonly Stream _net;
        private readonly Tls13ClientOptions _opt;
        private readonly SemaphoreSlim _writeGate = new SemaphoreSlim(1, 1);
        private Tls13Suite _suite;
        private Tls13RecordKeys _readKeys, _writeKeys;
        private byte[] _plain = new byte[0]; private int _plainOff;   // decrypted app data not yet returned
        private bool _eof;
        // XTLS Vision "direct copy": after the peer's Direct frame (read) / our Direct frame (write) that direction carries
        // the inner TLS stream raw on the socket — no more outer records, and never a close_notify / KeyUpdate again.
        private volatile bool _rawRead, _rawWrite;
        // Set as soon as our Direct frame is on the wire: the peer reads our side raw from then on, so no outer record
        // (close_notify, KeyUpdate reply) may follow even before the next write flips _rawWrite (Xray #6794).
        private volatile bool _quiet;

        private const int MaxHandshakeMessage = 65536;   // Go crypto/tls maxHandshake

        // Raw-read filter for Xray servers built before 2026-09-27 (XTLS/Xray-core #6794): after its Direct switch such a
        // server still seals an outer close_notify (17 03 03 00 13 + 19 bytes) onto the raw socket when it closes, which
        // the inner TLS client would read as a corrupt record ("bad record MAC"). We follow the inner TLS record framing
        // and drop a 24-byte record only if it AUTHENTICATES under our outer read key as close_notify — a genuine inner
        // record can't, so nothing real is ever dropped.
        private int _rawRecLeft;                       // bytes left of the current inner record (0 = at a boundary)
        private bool _rawUntracked;                    // framing didn't look like TLS: plain pass-through from here
        private byte[] _rawHold = new byte[0];         // an incomplete header / candidate record awaiting more bytes
        private byte[] _rawOut = new byte[0];          // scanned bytes ready for the caller
        private int _rawOutOff;
        private readonly byte[] _rawBuf = new byte[16384];
        private static readonly SecureRandom Rng = new SecureRandom();
        private int _disposed;

        public string NegotiatedAlpn { get; private set; }

        // ALPS (application-layer protocol settings, the Chrome extension we offer with h2): when the server accepts it in
        // EncryptedExtensions, BoringSSL expects the client's own settings in a client EncryptedExtensions message before
        // its Finished — without it the server aborts with unexpected_message. 0 = not negotiated.
        private int _alpsCodepoint;
        public ushort CipherSuite => _suite != null ? _suite.Id : (ushort)0;

        public Tls13Stream(Stream net, Tls13ClientOptions options) { _net = net; _opt = options; }

        /// <summary>Diagnostics hook (test harnesses): handshake progress lines. Null in the app.</summary>
        internal static Action<string> Trace { get; set; }

        // ───────────────────────── handshake ─────────────────────────

        public async Task HandshakeAsync(CancellationToken ct)
        {
            try { await HandshakeCoreAsync(ct).ConfigureAwait(false); }
            catch (Tls13Exception ex) when (_opt.FailureHint != null && !_certificateSeen && !ex.Message.EndsWith(_opt.FailureHint, StringComparison.Ordinal))
            {
                throw new Tls13Exception(ex.Message + _opt.FailureHint, ex);
            }
        }

        private bool _certificateSeen;

        private async Task HandshakeCoreAsync(CancellationToken ct)
        {
            var hello = ClientHelloBuilder.Build(_opt.ServerName, _opt.Alpn, _opt.Profile);
            if (_opt.PatchHello == null)
            {
                // A browser's middlebox-compat session id is 32 random bytes (the builder leaves zeros for REALITY's seal).
                var rnd = new byte[32];
                lock (Rng) Rng.NextBytes(rnd);
                Buffer.BlockCopy(rnd, 0, hello.Raw, hello.SessionIdOffset, 32);
            }
            else _opt.PatchHello(hello);
            byte[] sessionId = new byte[32];
            Buffer.BlockCopy(hello.Raw, hello.SessionIdOffset, sessionId, 0, 32);

            var transcript = new MemoryStream();
            transcript.Write(hello.Raw, 0, hello.Raw.Length);
            await WritePlainRecordAsync(0x16, hello.Raw, 0x0301, ct).ConfigureAwait(false);

            // ServerHello (plaintext handshake record)
            byte[] sh = await ReadPlainHandshakeAsync(ct).ConfigureAwait(false);
            if (sh[0] != 2) throw new Tls13Exception("TLS: expected ServerHello, got handshake type " + sh[0]);
            ParseServerHello(sh, sessionId, hello.MlKem != null, out int group, out byte[] serverShare);
            transcript.Write(sh, 0, sh.Length);
            byte[] shared = SharedSecret(hello, group, serverShare);
            Trace?.Invoke("ServerHello: suite 0x" + _suite.Id.ToString("x4") + " group 0x" + group.ToString("x4"));

            var s = _suite;
            byte[] early = Tls13Kdf.Extract(s, null, null);
            byte[] hsSecret = Tls13Kdf.Extract(s, Tls13Kdf.DeriveSecret(s, early, "derived", Tls13Kdf.EmptyHash(s)), shared);
            byte[] th = Tls13Kdf.Hash(s, transcript.ToArray());
            byte[] cHs = Tls13Kdf.DeriveSecret(s, hsSecret, "c hs traffic", th);
            byte[] sHs = Tls13Kdf.DeriveSecret(s, hsSecret, "s hs traffic", th);
            _readKeys = new Tls13RecordKeys(s, sHs);
            var clientHsKeys = new Tls13RecordKeys(s, cHs);

            // Encrypted server flight, strictly in order and each exactly once (RFC 8446 §4.4; no client auth, no PSK):
            // EncryptedExtensions → Certificate → CertificateVerify → Finished. Finished alone only proves knowledge of the
            // (EC)DHE secret, which an on-path attacker picks — the certificate key's signature is what binds the session.
            const int ExpectEE = 0, ExpectCert = 1, ExpectCv = 2, ExpectFinished = 3;
            int state = ExpectEE;
            List<byte[]> certs = null;
            byte[] leafKeyDer = null;
            bool cvOk = false;
            bool done = false;
            var hsQueue = new MemoryStream();
            while (!done)
            {
                foreach (var msg in await ReadEncryptedHandshakeAsync(hsQueue, ct).ConfigureAwait(false))
                {
                    byte type = msg[0];
                    Trace?.Invoke("handshake message " + type + " (" + msg.Length + " bytes)");
                    switch (type)
                    {
                        case 8:   // EncryptedExtensions
                            if (state != ExpectEE) throw new Tls13Exception("TLS: unexpected EncryptedExtensions");
                            ParseEncryptedExtensions(msg);
                            transcript.Write(msg, 0, msg.Length);
                            state = ExpectCert;
                            break;
                        case 13:  // CertificateRequest
                            throw new Tls13Exception("TLS: the server requires a client certificate (unsupported)");
                        case 11:  // Certificate
                            if (state != ExpectCert) throw new Tls13Exception("TLS: unexpected Certificate");
                            _certificateSeen = true;   // from here the verifier's own message explains a failure
                            certs = ParseCertificate(msg);
                            if (certs.Count == 0) throw new Tls13Exception("TLS: server sent an empty certificate list");
                            string why = _opt.VerifyCertificates != null ? _opt.VerifyCertificates(certs) : "no certificate verifier configured";
                            Trace?.Invoke("certificates (" + certs.Count + "): " + (why ?? "accepted"));
                            if (why != null) throw new Tls13Exception("TLS: " + why);
                            leafKeyDer = certs[0];
                            transcript.Write(msg, 0, msg.Length);
                            state = ExpectCv;
                            break;
                        case 15:  // CertificateVerify — signs the transcript up to (and incl.) Certificate
                            if (state != ExpectCv || leafKeyDer == null) throw new Tls13Exception("TLS: unexpected CertificateVerify");
                            VerifyCertificateVerify(msg, leafKeyDer, Tls13Kdf.Hash(s, transcript.ToArray()));
                            cvOk = true;
                            transcript.Write(msg, 0, msg.Length);
                            state = ExpectFinished;
                            break;
                        case 20:  // Finished
                            if (state != ExpectFinished || !cvOk) throw new Tls13Exception("TLS: server Finished without a verified CertificateVerify");
                            byte[] fk = Tls13Kdf.ExpandLabel(s, sHs, "finished", null, s.HashLen);
                            byte[] expect = Tls13Kdf.Hmac(s, fk, Tls13Kdf.Hash(s, transcript.ToArray()));
                            if (!FixedEquals(expect, Slice(msg, 4, msg.Length - 4))) throw new Tls13Exception("TLS: server Finished verify_data mismatch");
                            transcript.Write(msg, 0, msg.Length);
                            done = true;
                            break;
                        case 25:  // CompressedCertificate (RFC 8879)
                            if (_opt.CompressedCertificateError != null) { _certificateSeen = true; throw new Tls13Exception(_opt.CompressedCertificateError); }
                            throw new Tls13Exception("TLS: the server sent a brotli-compressed certificate, which this client can't decode yet");
                        default:
                            throw new Tls13Exception("TLS: unexpected handshake message " + type + " in the server flight");
                    }
                    if (done) break;
                }
            }

            // Application secrets (transcript through server Finished)
            byte[] thServerFin = Tls13Kdf.Hash(s, transcript.ToArray());
            byte[] master = Tls13Kdf.Extract(s, Tls13Kdf.DeriveSecret(s, hsSecret, "derived", Tls13Kdf.EmptyHash(s)), null);
            byte[] cAp = Tls13Kdf.DeriveSecret(s, master, "c ap traffic", thServerFin);
            byte[] sAp = Tls13Kdf.DeriveSecret(s, master, "s ap traffic", thServerFin);

            // Client flight under the handshake keys: ChangeCipherSpec (middlebox compat — we sent a session id), then the
            // client EncryptedExtensions if ALPS was negotiated (our settings: empty), then Finished over the transcript so far.
            var flight = new MemoryStream();
            flight.Write(new byte[] { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 }, 0, 6);
            byte[] thClientFin = thServerFin;
            if (_alpsCodepoint != 0)
            {
                var ee = new byte[] { 8, 0, 0, 6, 0, 4, (byte)(_alpsCodepoint >> 8), (byte)_alpsCodepoint, 0, 0 };
                transcript.Write(ee, 0, ee.Length);
                thClientFin = Tls13Kdf.Hash(s, transcript.ToArray());
                var eeRecord = clientHsKeys.Seal(0x16, ee, 0, ee.Length);
                flight.Write(eeRecord, 0, eeRecord.Length);
            }
            byte[] cfk = Tls13Kdf.ExpandLabel(s, cHs, "finished", null, s.HashLen);
            byte[] verify = Tls13Kdf.Hmac(s, cfk, thClientFin);
            var fin = new byte[4 + verify.Length];
            fin[0] = 20; fin[3] = (byte)verify.Length;
            Buffer.BlockCopy(verify, 0, fin, 4, verify.Length);
            var finRecord = clientHsKeys.Seal(0x16, fin, 0, fin.Length);
            flight.Write(finRecord, 0, finRecord.Length);
            var flightBytes = flight.ToArray();
            await _net.WriteAsync(flightBytes, 0, flightBytes.Length, ct).ConfigureAwait(false);

            _readKeys = new Tls13RecordKeys(s, sAp);
            _writeKeys = new Tls13RecordKeys(s, cAp);
            // hsQueue may already hold bytes of post-handshake messages that arrived in the same record — none expected.
        }

        // x25519 → 32-byte DH output; X25519MLKEM768 → mlkem_ss(32) || x25519_ss(32) (draft-ietf-tls-ecdhe-mlkem §4.1).
        private static byte[] SharedSecret(ClientHelloResult hello, int group, byte[] share)
        {
            byte[] x = new byte[32];
            bool hybrid = group != ClientHelloBuilder.GroupX25519;
            var key = hybrid ? hello.X25519Hybrid : hello.X25519;
            try { key.GenerateSecret(new X25519PublicKeyParameters(share, hybrid ? 1088 : 0), x, 0); }
            catch (Exception ex) { throw new Tls13Exception("TLS: invalid server x25519 share", ex); }
            if (!hybrid) return x;
            var kem = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
            kem.Init(hello.MlKem);
            var ss = new byte[64];
            kem.Decapsulate(share, 0, 1088, ss, 0, 32);
            Buffer.BlockCopy(x, 0, ss, 32, 32);
            return ss;
        }

        private void ParseServerHello(byte[] m, byte[] ourSessionId, bool offeredHybrid, out int group, out byte[] serverShare)
        {
            var r = new Reader(m, 4);
            r.U16();                                   // legacy_version
            byte[] random = r.Bytes(32);
            byte[] sid = r.Bytes(r.U8());
            ushort suite = (ushort)r.U16();
            int compression = r.U8();
            serverShare = null; group = 0;
            bool tls13 = false;
            int keyLen = -1;
            int extEnd = r.U16() + r.Pos;
            while (r.Pos < extEnd)
            {
                int type = r.U16(), len = r.U16(), end = r.Pos + len;
                if (type == 0x002b && len == 2) tls13 = r.U16() == 0x0304;
                else if (type == 0x0033 && len >= 4)
                {
                    group = r.U16(); keyLen = r.U16();
                    if (keyLen == len - 4) serverShare = r.Bytes(keyLen);
                }
                r.Pos = end;
            }
            if (r.Pos != m.Length) throw new Tls13Exception("TLS: malformed ServerHello");
            // Checks in the order that gives the most useful message.
            if (!tls13) throw new Tls13Exception("TLS: server did not negotiate TLS 1.3");
            if (FixedEquals(random, HrrRandom)) throw new Tls13Exception("TLS: server asked for HelloRetryRequest (unsupported)");
            if (!FixedEquals(sid, ourSessionId)) throw new Tls13Exception("TLS: ServerHello session id echo mismatch");
            _suite = Tls13Suite.ById(suite);
            if (_suite == null) throw new Tls13Exception("TLS: server chose an unsupported cipher suite 0x" + suite.ToString("x4"));
            if (compression != 0) throw new Tls13Exception("TLS: server chose compression");
            if (serverShare == null) throw new Tls13Exception("TLS: ServerHello without a usable key share");
            bool shareOk = (group == ClientHelloBuilder.GroupX25519 && keyLen == 32)
                        || (offeredHybrid && group == ClientHelloBuilder.GroupX25519MlKem768 && keyLen == 1120);
            if (!shareOk) throw new Tls13Exception("TLS: server key share (group 0x" + group.ToString("x4") + ", " + keyLen + " bytes) was not offered");
        }

        private void ParseEncryptedExtensions(byte[] m)
        {
            var r = new Reader(m, 4);
            int end = r.U16() + r.Pos;
            while (r.Pos < end)
            {
                int type = r.U16(), len = r.U16(), e = r.Pos + len;
                if (type == 0x0010 && len >= 3) { r.U16(); int n = r.U8(); NegotiatedAlpn = Encoding.ASCII.GetString(r.Bytes(n)); }
                else if (type == 0x44cd || type == 0x4469) _alpsCodepoint = type;
                r.Pos = e;
            }
        }

        private static List<byte[]> ParseCertificate(byte[] m)
        {
            var r = new Reader(m, 4);
            r.Bytes(r.U8());                           // certificate_request_context
            int end = r.U24() + r.Pos;
            var list = new List<byte[]>();
            while (r.Pos < end)
            {
                list.Add(r.Bytes(r.U24()));
                r.Bytes(r.U16());                      // per-entry extensions
            }
            return list;
        }

        internal static void VerifyCertificateVerify(byte[] m, byte[] leafDer, byte[] transcriptHash)
        {
            var r = new Reader(m, 4);
            int scheme = r.U16();
            byte[] sig = r.Bytes(r.U16());
            var content = new byte[64 + 33 + 1 + transcriptHash.Length];
            for (int i = 0; i < 64; i++) content[i] = 0x20;
            Encoding.ASCII.GetBytes("TLS 1.3, server CertificateVerify").CopyTo(content, 64);
            content[64 + 33] = 0;
            Buffer.BlockCopy(transcriptHash, 0, content, 64 + 34, transcriptHash.Length);

            AsymmetricKeyParameter key;
            try { Tls13Der.SplitCertificate(leafDer, out byte[] spki, out _); key = PublicKeyFactory.CreateKey(spki); }
            catch (Exception ex) when (!(ex is Tls13Exception)) { throw new Tls13Exception("TLS: unsupported server public key", ex); }
            ISigner signer;
            switch (scheme)
            {
                case 0x0807: signer = new Ed25519Signer(); break;
                case 0x0403: signer = SignerUtilities.GetSigner("SHA-256withECDSA"); break;
                case 0x0503: signer = SignerUtilities.GetSigner("SHA-384withECDSA"); break;
                case 0x0603: signer = SignerUtilities.GetSigner("SHA-512withECDSA"); break;
                case 0x0804: case 0x0809: signer = SignerUtilities.GetSigner("SHA-256withRSAandMGF1"); break;
                case 0x0805: case 0x080a: signer = SignerUtilities.GetSigner("SHA-384withRSAandMGF1"); break;
                case 0x0806: case 0x080b: signer = SignerUtilities.GetSigner("SHA-512withRSAandMGF1"); break;
                default: throw new Tls13Exception("TLS: unsupported CertificateVerify scheme 0x" + scheme.ToString("x4"));
            }
            bool valid;
            try
            {
                signer.Init(false, key);   // throws when the scheme doesn't match the certificate's key type
                signer.BlockUpdate(content, 0, content.Length);
                valid = signer.VerifySignature(sig);
            }
            catch (Exception ex) { throw new Tls13Exception("TLS: CertificateVerify scheme 0x" + scheme.ToString("x4") + " doesn't fit the certificate key", ex); }
            if (!valid) throw new Tls13Exception("TLS: CertificateVerify signature is invalid");
        }

        // ───────────────────────── record I/O ─────────────────────────

        private readonly byte[] _hdr = new byte[5];

        private async Task<byte[]> ReadRecordAsync(CancellationToken ct)   // returns body; header in _hdr
        {
            if (!await ReadExactAsync(_hdr, 5, ct).ConfigureAwait(false)) return null;
            int len = (_hdr[3] << 8) | _hdr[4];
            if (len > (1 << 14) + 256) throw new Tls13Exception("TLS: record too long");
            var body = new byte[len];
            if (!await ReadExactAsync(body, len, ct).ConfigureAwait(false)) throw new Tls13Exception("TLS: connection closed inside a record");
            return body;
        }

        private async Task<bool> ReadExactAsync(byte[] buf, int n, CancellationToken ct)
        {
            int got = 0;
            while (got < n)
            {
                int r = await _net.ReadAsync(buf, got, n - got, ct).ConfigureAwait(false);
                if (r <= 0) { if (got == 0) return false; throw new Tls13Exception("TLS: connection closed mid-record"); }
                got += r;
            }
            return true;
        }

        private async Task<byte[]> ReadPlainHandshakeAsync(CancellationToken ct)
        {
            var acc = new MemoryStream();
            while (true)
            {
                var body = await ReadRecordAsync(ct).ConfigureAwait(false);
                if (body == null) throw new Tls13Exception("TLS: the server closed the connection during the handshake");
                if (_hdr[0] == 0x15) throw new Tls13Exception("TLS: server alert " + Alert(body));
                if (_hdr[0] != 0x16) throw new Tls13Exception("TLS: unexpected record type " + _hdr[0] + " before ServerHello");
                acc.Write(body, 0, body.Length);
                var a = acc.ToArray();
                if (a.Length >= 1 && a[0] != 2) throw new Tls13Exception("TLS: expected ServerHello, got handshake type " + a[0]);
                if (a.Length >= 4)
                {
                    int need = 4 + ((a[1] << 16) | (a[2] << 8) | a[3]);
                    if (need > 4 + MaxHandshakeMessage) throw new Tls13Exception("TLS: oversized ServerHello");
                    if (a.Length >= need) return Slice(a, 0, need);   // (a coalesced extra message would be a protocol error)
                }
            }
        }

        // Decrypt handshake records until at least one complete message is queued; returns all complete messages.
        private async Task<List<byte[]>> ReadEncryptedHandshakeAsync(MemoryStream queue, CancellationToken ct)
        {
            while (true)
            {
                var msgs = TakeMessages(queue);
                if (msgs.Count > 0) return msgs;
                var body = await ReadRecordAsync(ct).ConfigureAwait(false);
                if (body == null) throw new Tls13Exception("TLS: the server closed the connection during the handshake");
                if (_hdr[0] == 0x14) continue;                         // middlebox-compat ChangeCipherSpec
                if (_hdr[0] == 0x15) throw new Tls13Exception("TLS: server alert " + Alert(body));
                if (_hdr[0] != 0x17) throw new Tls13Exception("TLS: unexpected plaintext record " + _hdr[0] + " after ServerHello");
                byte[] content = _readKeys.Open((byte[])_hdr.Clone(), body, out byte type);
                if (type == 0x15) throw new Tls13Exception("TLS: server alert " + Alert(content));
                if (type != 0x16) throw new Tls13Exception("TLS: unexpected content type " + type + " during the handshake");
                queue.Seek(0, SeekOrigin.End);
                queue.Write(content, 0, content.Length);
            }
        }

        private static List<byte[]> TakeMessages(MemoryStream q)
        {
            var list = new List<byte[]>();
            var a = q.ToArray(); int off = 0;
            while (a.Length - off >= 4)
            {
                int need = 4 + ((a[off + 1] << 16) | (a[off + 2] << 8) | a[off + 3]);
                if (need > 4 + MaxHandshakeMessage) throw new Tls13Exception("TLS: oversized handshake message");
                if (a.Length - off < need) break;
                list.Add(Slice(a, off, need)); off += need;
            }
            q.SetLength(0); q.Write(a, off, a.Length - off);
            return list;
        }

        private async Task WritePlainRecordAsync(byte type, byte[] data, int version, CancellationToken ct)
        {
            var rec = new byte[5 + data.Length];
            rec[0] = type; rec[1] = (byte)(version >> 8); rec[2] = (byte)version;
            rec[3] = (byte)(data.Length >> 8); rec[4] = (byte)data.Length;
            Buffer.BlockCopy(data, 0, rec, 5, data.Length);
            await _net.WriteAsync(rec, 0, rec.Length, ct).ConfigureAwait(false);
        }

        // ───────────────────────── application data ─────────────────────────

        /// <summary>Reads stop decrypting: leftover plaintext of the current record is returned first, then raw socket
        /// bytes (Xray VisionReader: content, then the TLS conn's input, then rawInput, then the raw conn). We never read
        /// past a record, so there is no buffered ciphertext to hand over. Call from the (single) reader only.</summary>
        internal void SwitchReadToRaw() => _rawRead = true;

        /// <summary>Writes stop encrypting: everything after this goes to the socket as-is (Xray UnwrapRawConn).</summary>
        internal void SwitchWriteToRaw() => _rawWrite = true;

        /// <summary>Our Direct frame is on the wire: from now on we may write no further outer record (the next app write
        /// goes raw via <see cref="SwitchWriteToRaw"/>), and teardown must not send close_notify.</summary>
        internal void SuppressOuterRecords() => _quiet = true;

        /// <summary>True once either direction went raw (or our Direct frame was sent) — the outer TLS session must stay silent.</summary>
        internal bool IsRaw => _rawRead || _rawWrite || _quiet;

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return 0;
            if (_rawRead && _plainOff >= _plain.Length) return await RawReadAsync(buffer, offset, count, ct).ConfigureAwait(false);
            while (_plainOff >= _plain.Length)
            {
                if (_eof) return 0;
                var body = await ReadRecordAsync(ct).ConfigureAwait(false);
                if (body == null) { _eof = true; return 0; }
                if (_hdr[0] == 0x14) continue;
                if (_hdr[0] != 0x17) throw new IOException("TLS: unexpected record type " + _hdr[0]);
                byte[] content;
                byte type;
                try { content = _readKeys.Open((byte[])_hdr.Clone(), body, out type); }
                catch (InvalidCipherTextException ex) { throw new IOException("TLS: record authentication failed", ex); }
                if (type == 0x17) { _plain = content; _plainOff = 0; }
                else if (type == 0x15)
                {
                    if (content.Length >= 2 && content[1] == 0) { _eof = true; return 0; }   // close_notify
                    throw new IOException("TLS: server alert " + Alert(content));
                }
                else if (type == 0x16) HandlePostHandshake(content);
            }
            int n = Math.Min(count, _plain.Length - _plainOff);
            Buffer.BlockCopy(_plain, _plainOff, buffer, offset, n);
            _plainOff += n;
            if (_rawRead) Track(buffer, offset, n);   // leftover plaintext after a Direct switch is inner stream too
            return n;
        }

        private async Task<int> RawReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            while (true)
            {
                if (_rawOutOff < _rawOut.Length)
                {
                    int n = Math.Min(count, _rawOut.Length - _rawOutOff);
                    Buffer.BlockCopy(_rawOut, _rawOutOff, buffer, offset, n);
                    _rawOutOff += n;
                    return n;
                }
                if (_eof) return 0;
                int r = await _net.ReadAsync(_rawBuf, 0, _rawBuf.Length, ct).ConfigureAwait(false);
                byte[] data;
                if (r <= 0)
                {
                    _eof = true;
                    data = _rawHold; _rawHold = new byte[0];   // an unfinished record at EOF: pass it on as-is
                }
                else
                {
                    data = new byte[_rawHold.Length + r];
                    Buffer.BlockCopy(_rawHold, 0, data, 0, _rawHold.Length);
                    Buffer.BlockCopy(_rawBuf, 0, data, _rawHold.Length, r);
                    _rawHold = new byte[0];
                    data = Scan(data);
                }
                _rawOut = data; _rawOutOff = 0;
            }
        }

        // Advances the inner record tracker over bytes already delivered.
        private void Track(byte[] b, int off, int len)
        {
            int p = off, end = off + len;
            while (p < end && !_rawUntracked)
            {
                if (_rawRecLeft > 0) { int k = Math.Min(_rawRecLeft, end - p); p += k; _rawRecLeft -= k; continue; }
                if (end - p < 5) { _rawUntracked = true; break; }   // a header split across the switch: stop filtering
                if (!LooksLikeRecordHeader(b, p)) { _rawUntracked = true; break; }
                _rawRecLeft = (b[p + 3] << 8) | b[p + 4];
                p += 5;
            }
        }

        // Splits freshly read raw bytes into "deliver now" (returned) and "hold" (_rawHold: an incomplete header or an
        // incomplete 24-byte candidate). Drops a candidate that authenticates as our peer's outer close_notify.
        private byte[] Scan(byte[] d)
        {
            if (_rawUntracked) return d;
            var outBuf = new MemoryStream(d.Length);
            int p = 0, start = 0;
            while (p < d.Length)
            {
                if (_rawRecLeft > 0) { int k = Math.Min(_rawRecLeft, d.Length - p); p += k; _rawRecLeft -= k; continue; }
                if (d.Length - p < 5) { _rawHold = Slice(d, p, d.Length - p); break; }
                if (!LooksLikeRecordHeader(d, p)) { _rawUntracked = true; p = d.Length; break; }
                int len = (d[p + 3] << 8) | d[p + 4];
                if (d[p] == 0x17 && len == 0x13 && _readKeys != null)
                {
                    if (d.Length - p < 24) { _rawHold = Slice(d, p, d.Length - p); break; }
                    byte type; byte[] content;
                    if (_readKeys.TryOpen(Slice(d, p, 5), Slice(d, p + 5, 19), out type, out content) && type == 0x15)
                    {
                        // The server's stray outer alert: deliver what came before, drop it, and end the stream.
                        outBuf.Write(d, start, p - start);
                        Trace?.Invoke("dropped a stray outer TLS alert after the XTLS direct switch (pre-2026-09 Xray server)");
                        _eof = true;
                        return outBuf.ToArray();
                    }
                }
                _rawRecLeft = len;
                p += 5;
            }
            int deliverEnd = Math.Min(p, d.Length - _rawHold.Length);
            outBuf.Write(d, start, deliverEnd - start);
            return outBuf.ToArray();
        }

        private static bool LooksLikeRecordHeader(byte[] b, int p)
            => b[p] >= 0x14 && b[p] <= 0x18 && b[p + 1] == 0x03 && b[p + 2] <= 0x04;

        // NewSessionTicket → ignored (no resumption). KeyUpdate → rotate read keys; answer if the peer asked.
        private void HandlePostHandshake(byte[] content)
        {
            int off = 0;
            while (content.Length - off >= 4)
            {
                byte type = content[off];
                int len = (content[off + 1] << 16) | (content[off + 2] << 8) | content[off + 3];
                if (off + 4 + len > content.Length) throw new IOException("TLS: truncated post-handshake message");
                if (type == 24)
                {
                    if (len != 1) throw new IOException("TLS: malformed KeyUpdate");
                    bool requested = content[off + 4] == 1;
                    _readKeys = _readKeys.Next();
                    if (requested && !_rawWrite && !_quiet) Task.Run(SendKeyUpdateAsync);   // never block the reader on the write gate
                }
                off += 4 + len;
            }
        }

        private async Task SendKeyUpdateAsync()
        {
            try
            {
                await _writeGate.WaitAsync().ConfigureAwait(false);
                try
                {
                    if (_rawWrite || _quiet) return;   // the peer reads us raw now: an outer record would corrupt the stream
                    var ku = new byte[] { 24, 0, 0, 1, 0 };   // update_not_requested
                    var rec = _writeKeys.Seal(0x16, ku, 0, ku.Length);
                    await _net.WriteAsync(rec, 0, rec.Length).ConfigureAwait(false);
                    _writeKeys = _writeKeys.Next();
                }
                finally { _writeGate.Release(); }
            }
            catch { }
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            await _writeGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_rawWrite)
                {
                    if (count > 0) await _net.WriteAsync(buffer, offset, count, ct).ConfigureAwait(false);
                    return;
                }
                while (count > 0)
                {
                    int n = Math.Min(count, 1 << 14);
                    var rec = _writeKeys.Seal(0x17, buffer, offset, n);
                    await _net.WriteAsync(rec, 0, rec.Length, ct).ConfigureAwait(false);
                    offset += n; count -= n;
                }
            }
            finally { _writeGate.Release(); }
        }

        public override Task FlushAsync(CancellationToken ct) => _net.FlushAsync(ct);
        public override void Flush() => _net.Flush();
        public override int Read(byte[] b, int o, int c) => ReadAsync(b, o, c, CancellationToken.None).GetAwaiter().GetResult();
        public override void Write(byte[] b, int o, int c) => WriteAsync(b, o, c, CancellationToken.None).GetAwaiter().GetResult();
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
        public override void SetLength(long v) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            if (disposing)
            {
                // Best-effort close_notify, never blocking (same rule as BcTlsStream) — and never once either direction
                // went raw: the peer would read those 24 bytes as inner TLS data (Xray SuppressOuterCloseNotify, #6794).
                if (_writeKeys != null && !IsRaw && _writeGate.Wait(0))
                {
                    try
                    {
                        var rec = _writeKeys.Seal(0x15, new byte[] { 1, 0 }, 0, 2);
                        _net.WriteAsync(rec, 0, rec.Length).ContinueWith(t => { var _ = t.Exception; }, TaskScheduler.Default);
                    }
                    catch { }
                    finally { _writeGate.Release(); }
                }
                try { _net.Dispose(); } catch { }
            }
            base.Dispose(disposing);
        }

        // ───────────────────────── helpers ─────────────────────────

        private static string Alert(byte[] b) => b.Length >= 2 ? "level " + b[0] + " description " + b[1] : "(short)";

        internal static byte[] Slice(byte[] a, int off, int len) { var r = new byte[len]; Buffer.BlockCopy(a, off, r, 0, len); return r; }

        internal static bool FixedEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int d = 0;
            for (int i = 0; i < a.Length; i++) d |= a[i] ^ b[i];
            return d == 0;
        }

        internal static byte[] Hex(string h)
        {
            var b = new byte[h.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(h.Substring(2 * i, 2), 16);
            return b;
        }

        private sealed class Reader
        {
            private readonly byte[] _b;
            public int Pos;
            public Reader(byte[] b, int pos) { _b = b; Pos = pos; }
            private void Need(int n) { if (Pos + n > _b.Length) throw new Tls13Exception("TLS: truncated handshake message"); }
            public int U8() { Need(1); return _b[Pos++]; }
            public int U16() { Need(2); int v = (_b[Pos] << 8) | _b[Pos + 1]; Pos += 2; return v; }
            public int U24() { Need(3); int v = (_b[Pos] << 16) | (_b[Pos + 1] << 8) | _b[Pos + 2]; Pos += 3; return v; }
            public byte[] Bytes(int n) { Need(n); var r = new byte[n]; Buffer.BlockCopy(_b, Pos, r, 0, n); Pos += n; return r; }
        }
    }
}

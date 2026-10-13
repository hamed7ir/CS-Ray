using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Protocol.Vmess
{
    /// <summary>
    /// VMess AEAD (security=3, AES-128-GCM) post-handshake body stream over the transport, with the request's options —
    /// Xray's default 0x0D: ChunkStream + ChunkMasking + GlobalPadding (the server mirrors them on the response).
    ///
    /// One chunk, per direction: [2-byte BE (|C| + pad) ^ mask][C = AES-128-GCM(key, nonce, P), |P|+16][pad random bytes].
    /// pad = next() % 64 is drawn BEFORE mask = next(), both from that direction's SHAKE128(body IV) stream (Xray
    /// common/crypto/auth.go seal / readSize + vmess ShakeSizeParser). Size == 16 + pad (an empty P) ends a direction.
    /// Writes cut P at <see cref="MaxPayload"/> (8110, as Xray writes them); reads take any size.
    /// Read (server→client): on the FIRST read, consume + verify the AEAD response header
    ///   (lazily — the server sends it prepended to the first response data, so doing it here
    ///   runs concurrently with the client→server pump and avoids a handshake deadlock), then
    ///   decrypt body chunks with the SHA256-derived response key / IV.
    ///
    /// Per-chunk nonce (per direction) = [2-byte BE counter][IV[2..12]], counter from 0.
    /// </summary>
    public class VmessBodyStream : Stream, IHalfClosable
    {
        /// <summary>Largest payload per chunk (Xray: buffer 8192 - size 2 - tag 16 - max padding 64).</summary>
        public const int MaxPayload = 8192 - 2 - 16 - 64;
        private const int MaxPad = 63;
        private static readonly RNGCryptoServiceProvider Rng = new RNGCryptoServiceProvider();

        private readonly bool _masking, _padding;
        private readonly ShakeSizeParser _writeShake, _readShake;   // null when masking is off
        private bool _readEnded;

        private readonly Stream _inner;
        private readonly byte[] _reqKey, _reqIV;     // request (client→server) body
        private readonly byte[] _respKey, _respIV;   // response (server→client) body (SHA256-derived)
        private readonly byte _expectedV;
        private readonly Action<string> _log;

        private ushort _writeCounter;
        private bool _writeClosed;
        private ushort _readCounter;
        private bool _respHeaderRead;
        private byte[] _leftover;
        private int _leftoverOffset;
        private int _leftoverCount;

        public VmessBodyStream(Stream inner, byte[] reqKey, byte[] reqIV, byte[] respKey, byte[] respIV,
                               byte expectedV, Action<string> log, byte option = VmessRequest.OptionDefault)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _reqKey = reqKey; _reqIV = reqIV;
            _respKey = respKey; _respIV = respIV;
            _expectedV = expectedV;
            _log = log;
            _masking = (option & VmessRequest.OptionChunkMasking) != 0;
            _padding = _masking && (option & VmessRequest.OptionGlobalPadding) != 0;   // Xray refuses padding without masking
            if (_masking) { _writeShake = new ShakeSizeParser(reqIV); _readShake = new ShakeSizeParser(respIV); }
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
            // Every chunk of the call is sealed into one buffer and written once: VMess chunks are self-delimiting, and a
            // message-shaped transport (one XHTTP packet-up POST / one ws frame per write) then carries the call whole.
            int chunks = (count + MaxPayload - 1) / MaxPayload;
            var wire = new byte[count + chunks * (2 + 16 + MaxPad)];
            int pos = offset, remaining = count, o = 0;
            while (remaining > 0)   // a zero-length write emits nothing: an empty chunk would END the request
            {
                int chunk = Math.Min(remaining, MaxPayload);
                var plain = new byte[chunk];
                Buffer.BlockCopy(buffer, pos, plain, 0, chunk);
                o = SealChunk(plain, wire, o);
                pos += chunk; remaining -= chunk;
            }
            if (o > 0) await _inner.WriteAsync(wire, 0, o, ct).ConfigureAwait(false);
            await _inner.FlushAsync(ct).ConfigureAwait(false);
        }

        // Appends one chunk for `plain` at wire[o..]; returns the new end. Draw order matters: padding, then mask.
        private int SealChunk(byte[] plain, byte[] wire, int o)
        {
            int pad = _padding ? _writeShake.Next() % 64 : 0;
            int mask = _masking ? _writeShake.Next() : 0;
            var sealed_ = VmessAead.GcmSeal(_reqKey, ChunkNonce(_reqIV, _writeCounter++), plain, null); // |P| + 16
            int size = (sealed_.Length + pad) ^ mask;
            wire[o] = (byte)(size >> 8);
            wire[o + 1] = (byte)(size & 0xFF);
            Buffer.BlockCopy(sealed_, 0, wire, o + 2, sealed_.Length);
            o += 2 + sealed_.Length;
            if (pad > 0)
            {
                var p = new byte[pad];
                Rng.GetBytes(p);   // sent in clear: never a predictable PRNG (Xray uses crypto/rand)
                Buffer.BlockCopy(p, 0, wire, o, pad);
                o += pad;
            }
            return o;
        }

        /// <summary>Xray's end-of-request signal (proxy/vmess/outbound): one empty chunk — just the 16-byte tag — after which
        /// the server half-closes the target. Reading continues. Idempotent.</summary>
        public async Task CloseWriteAsync(CancellationToken ct)
        {
            if (_writeClosed) return;
            _writeClosed = true;
            var frame = new byte[2 + 16 + MaxPad];
            int n = SealChunk(new byte[0], frame, 0);   // draws padding + mask too, like any chunk
            await _inner.WriteAsync(frame, 0, n, ct).ConfigureAwait(false);
            await _inner.FlushAsync(ct).ConfigureAwait(false);
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return 0;

            if (!_respHeaderRead)
            {
                await ReadAndVerifyResponseHeaderAsync(ct).ConfigureAwait(false);
                _respHeaderRead = true;
            }

            while (_leftoverCount == 0)
            {
                var payload = await ReadChunkAsync(ct).ConfigureAwait(false);
                if (payload == null) return 0; // EOF / terminal chunk
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

        private async Task ReadAndVerifyResponseHeaderAsync(CancellationToken ct)
        {
            // Length AEAD: 2 bytes + 16-byte tag, keyed by KDF over the response body key, no AAD.
            var encLen = await ReadFullyAsync(18, ct, throwOnEof: true, what: "response header length").ConfigureAwait(false);
            // Header KEY derives from the response body key; header IV derives from the response body IV.
            var lenKey = VmessKdf.Kdf16(_respKey, VmessKdf.LabelAEADRespHeaderLenKey);
            var lenIV = VmessKdf.Kdf12(_respIV, VmessKdf.LabelAEADRespHeaderLenIV);
            byte[] lenPlain;
            try { lenPlain = VmessAead.GcmOpen(lenKey, lenIV, encLen, null); }
            catch (Exception ex)
            {
                throw new IOException("VMess response header LENGTH decrypt failed (" + ex.Message +
                                      "). Raw 18B: " + Hex(encLen, 0, encLen.Length));
            }
            int headerLen = ((lenPlain[0] & 0xFF) << 8) | (lenPlain[1] & 0xFF);

            var encHeader = await ReadFullyAsync(headerLen + 16, ct, throwOnEof: true, what: "response header payload").ConfigureAwait(false);
            var hdrKey = VmessKdf.Kdf16(_respKey, VmessKdf.LabelAEADRespHeaderPayloadKey);
            var hdrIV = VmessKdf.Kdf12(_respIV, VmessKdf.LabelAEADRespHeaderPayloadIV);
            byte[] header;
            try { header = VmessAead.GcmOpen(hdrKey, hdrIV, encHeader, null); }
            catch (Exception ex)
            {
                throw new IOException("VMess response header PAYLOAD decrypt failed (" + ex.Message +
                                      "). Raw len18: " + Hex(encLen, 0, encLen.Length) +
                                      " payload" + (headerLen + 16) + "B: " + Hex(encHeader, 0, encHeader.Length));
            }

            if (header.Length < 1 || header[0] != _expectedV)
                throw new IOException("VMess response auth V mismatch: expected " + _expectedV +
                                      ", got " + (header.Length > 0 ? header[0].ToString() : "<empty>") +
                                      ". Decrypted header: " + Hex(header, 0, header.Length));

            _log?.Invoke("VMess response header verified (V=" + _expectedV + ", header len=" + headerLen + ").");
        }

        internal async Task<byte[]> ReadChunkAsync(CancellationToken ct)
        {
            if (_readEnded) return null;
            var sizeBuf = await ReadFullyAsync(2, ct, throwOnEof: false, what: "chunk size").ConfigureAwait(false);
            if (sizeBuf == null) { _readEnded = true; return null; } // clean EOF
            int pad = _padding ? _readShake.Next() % 64 : 0;          // same draw order as the writer
            int size = (((sizeBuf[0] & 0xFF) << 8) | (sizeBuf[1] & 0xFF)) ^ (_masking ? _readShake.Next() : 0);
            if (size == 16 + pad) { _readEnded = true; return null; } // the empty terminal chunk
            if (size < 16 + pad) throw new IOException("VMess: invalid chunk size " + size + " (padding " + pad + ")");

            var enc = await ReadFullyAsync(size, ct, throwOnEof: false, what: "chunk body").ConfigureAwait(false);
            if (enc == null) { _readEnded = true; return null; }
            if (pad > 0) { var c = new byte[size - pad]; Buffer.BlockCopy(enc, 0, c, 0, c.Length); enc = c; }   // drop the padding

            var nonce = ChunkNonce(_respIV, _readCounter++);
            try { return VmessAead.GcmOpen(_respKey, nonce, enc, null); }
            catch (Exception ex)
            {
                throw new IOException("VMess body chunk decrypt failed at counter " + (_readCounter - 1) +
                                      " (" + ex.Message + ").");
            }
        }

        // Nonce = [2-byte BE counter][IV[2..12]] (10 IV bytes), counter from 0, per direction.
        private static byte[] ChunkNonce(byte[] iv, ushort counter)
        {
            var nonce = new byte[12];
            nonce[0] = (byte)(counter >> 8);
            nonce[1] = (byte)(counter & 0xFF);
            Buffer.BlockCopy(iv, 2, nonce, 2, 10);
            return nonce;
        }

        private async Task<byte[]> ReadFullyAsync(int n, CancellationToken ct, bool throwOnEof, string what)
        {
            var buf = new byte[n];
            int off = 0;
            while (off < n)
            {
                int r = await _inner.ReadAsync(buf, off, n - off, ct).ConfigureAwait(false);
                if (r <= 0)
                {
                    // Nothing at all before the response header: the server gave up on the target (as VLESS reports it).
                    if (throwOnEof && off == 0 && !_respHeaderRead) throw new IOException(VlessProtocol.NoAnswerMessage);
                    if (throwOnEof)
                        throw new IOException("VMess: stream closed reading " + what + " after " + off + "/" + n +
                                              " bytes. Raw: " + Hex(buf, 0, off));
                    return null;
                }
                off += r;
            }
            return buf;
        }

        /// <summary>Xray's ShakeSizeParser: SHAKE128 absorbs one body IV, then is squeezed 2 bytes at a time (big-endian).</summary>
        internal sealed class ShakeSizeParser
        {
            private readonly Org.BouncyCastle.Crypto.Digests.ShakeDigest _xof = new Org.BouncyCastle.Crypto.Digests.ShakeDigest(128);
            private readonly byte[] _buf = new byte[256];   // even, so a 2-byte draw never straddles a refill
            private int _pos = 256;

            public ShakeSizeParser(byte[] seed) { _xof.BlockUpdate(seed, 0, seed.Length); }

            public int Next()
            {
                if (_pos >= _buf.Length) { _xof.Output(_buf, 0, _buf.Length); _pos = 0; }
                int v = (_buf[_pos] << 8) | _buf[_pos + 1];
                _pos += 2;
                return v;
            }
        }

        private static string Hex(byte[] b, int offset, int length)
        {
            var sb = new StringBuilder(length * 2);
            for (int i = 0; i < length; i++) sb.Append(b[offset + i].ToString("x2"));
            return sb.ToString();
        }
    }
}

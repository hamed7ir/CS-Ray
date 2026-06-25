using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Protocol.Vmess
{
    /// <summary>
    /// VMess AEAD (security=3, AES-128-GCM) post-handshake body stream over the transport.
    ///
    /// Write (client→server): chunk the plaintext into ≤8KB pieces, each emitted as
    ///   [2-byte BE size = |P|+16][AES-128-GCM(reqKey, nonce, P)]   (size includes the 16-byte tag).
    /// Read (server→client): on the FIRST read, consume + verify the AEAD response header
    ///   (lazily — the server sends it prepended to the first response data, so doing it here
    ///   runs concurrently with the client→server pump and avoids a handshake deadlock), then
    ///   decrypt body chunks the same way with the SHA256-derived response key.
    ///
    /// Per-chunk nonce (per direction) = [2-byte BE counter][IV[2..12]], counter from 0.
    /// Options = 0x01 (standard chunk stream): plain 2-byte size, no masking/global padding.
    /// </summary>
    public class VmessBodyStream : Stream
    {
        private const int MaxPayload = 8192;

        private readonly Stream _inner;
        private readonly byte[] _reqKey, _reqIV;     // request (client→server) body
        private readonly byte[] _respKey, _respIV;   // response (server→client) body (SHA256-derived)
        private readonly byte _expectedV;
        private readonly Action<string> _log;

        private ushort _writeCounter;
        private ushort _readCounter;
        private bool _respHeaderRead;
        private byte[] _leftover;
        private int _leftoverOffset;
        private int _leftoverCount;

        public VmessBodyStream(Stream inner, byte[] reqKey, byte[] reqIV, byte[] respKey, byte[] respIV,
                               byte expectedV, Action<string> log)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _reqKey = reqKey; _reqIV = reqIV;
            _respKey = respKey; _respIV = respIV;
            _expectedV = expectedV;
            _log = log;
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
            int pos = offset, remaining = count;
            while (remaining > 0)
            {
                int chunk = Math.Min(remaining, MaxPayload);
                var plain = new byte[chunk];
                Buffer.BlockCopy(buffer, pos, plain, 0, chunk);

                var nonce = ChunkNonce(_reqIV, _writeCounter++);
                var sealed_ = VmessAead.GcmSeal(_reqKey, nonce, plain, null); // chunk + 16-byte tag
                int size = sealed_.Length;                                    // |P| + 16

                var frame = new byte[2 + size];
                frame[0] = (byte)(size >> 8);
                frame[1] = (byte)(size & 0xFF);
                Buffer.BlockCopy(sealed_, 0, frame, 2, size);
                await _inner.WriteAsync(frame, 0, frame.Length, ct).ConfigureAwait(false);

                pos += chunk; remaining -= chunk;
            }
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

        private async Task<byte[]> ReadChunkAsync(CancellationToken ct)
        {
            var sizeBuf = await ReadFullyAsync(2, ct, throwOnEof: false, what: "chunk size").ConfigureAwait(false);
            if (sizeBuf == null) return null; // clean EOF
            int size = ((sizeBuf[0] & 0xFF) << 8) | (sizeBuf[1] & 0xFF);
            if (size <= 16) return null; // size==16 → empty terminal chunk; <16 → end

            var enc = await ReadFullyAsync(size, ct, throwOnEof: false, what: "chunk body").ConfigureAwait(false);
            if (enc == null) return null;

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
                    if (throwOnEof)
                        throw new IOException("VMess: stream closed reading " + what + " after " + off + "/" + n +
                                              " bytes. Raw: " + Hex(buf, 0, off));
                    return null;
                }
                off += r;
            }
            return buf;
        }

        private static string Hex(byte[] b, int offset, int length)
        {
            var sb = new StringBuilder(length * 2);
            for (int i = 0; i < length; i++) sb.Append(b[offset + i].ToString("x2"));
            return sb.ToString();
        }
    }
}

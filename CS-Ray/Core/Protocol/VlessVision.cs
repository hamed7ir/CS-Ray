using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CS_Ray.Core.Transport.Tls13;
using Org.BouncyCastle.Security;

namespace CS_Ray.Core.Protocol
{
    /// <summary>
    /// XTLS Vision traffic state for one client connection — Xray proxy.TrafficState with only the client ("Outbound")
    /// half. The TLS filter fields are shared by the uplink writer and the downlink reader (one counter for both
    /// directions, as in Xray); <see cref="VisionStream"/> guards them with one lock.
    /// </summary>
    internal sealed class VisionState
    {
        public readonly byte[] UserUuid;
        public int NumberOfPacketToFilter = 8;
        public bool EnableXtls;
        public bool IsTls12OrAbove;
        public bool IsTls;
        public int Cipher;
        public int RemainingServerHello = -1;

        // downlink reader
        public bool WithinPaddingBuffers = true;
        public bool DownlinkReaderDirectCopy;
        public int RemainingCommand = -1, RemainingContent = -1, RemainingPadding = -1;
        public int CurrentCommand;

        // uplink writer
        public bool IsPadding = true;
        public bool UplinkWriterDirectCopy;

        public VisionState(byte[] userUuid) { UserUuid = userUuid; }
    }

    /// <summary>
    /// XTLS Vision framing and TLS sniffing, transliterated from Xray-core proxy/proxy.go (XtlsPadding, XtlsUnpadding,
    /// XtlsFilterTls, IsCompleteRecord, ReshapeMultiBuffer). A "buffer" is one Xray buf.Buffer: at most 8192 bytes.
    /// </summary>
    internal static class Vision
    {
        public const byte CommandContinue = 0x00;
        public const byte CommandEnd = 0x01;
        public const byte CommandDirect = 0x02;

        /// <summary>Xray buf.Size — frame and read-chunk size; a frame (UUID + 5-byte header + content + padding) never
        /// exceeds it.</summary>
        public const int BufSize = 8192;

        // testseed defaults {900, 500, 900, 256}: long padding brings content+padding to 900..1399 bytes.
        private const int LongThreshold = 900, LongRandom = 500, LongBase = 900, ShortRandom = 256;

        private static readonly byte[] Tls13SupportedVersions = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };
        private static readonly SecureRandom Rng = new SecureRandom();

        /// <summary>XtlsFilterTls: sniffs the inner TLS ClientHello / ServerHello to learn whether the tunnelled traffic is
        /// TLS, TLS ≥ 1.2, and TLS 1.3 with a cipher Vision may copy directly (EnableXtls).</summary>
        public static void FilterTls(IList<ArraySegment<byte>> buffers, VisionState s)
        {
            foreach (var seg in buffers)
            {
                if (seg.Array == null) continue;
                byte[] a = seg.Array; int o = seg.Offset, n = seg.Count;
                s.NumberOfPacketToFilter--;
                if (n >= 6)
                {
                    if (a[o] == 0x16 && a[o + 1] == 0x03 && a[o + 2] == 0x03 && a[o + 5] == 0x02)          // ServerHello
                    {
                        s.RemainingServerHello = ((a[o + 3] << 8) | a[o + 4]) + 5;
                        s.IsTls12OrAbove = true;
                        s.IsTls = true;
                        if (n >= 79 && s.RemainingServerHello >= 79)
                        {
                            int sidLen = a[o + 43];
                            if (45 + sidLen < n) s.Cipher = (a[o + 44 + sidLen] << 8) | a[o + 45 + sidLen];
                        }
                    }
                    else if (a[o] == 0x16 && a[o + 1] == 0x03 && a[o + 5] == 0x01)                          // ClientHello
                    {
                        s.IsTls = true;
                    }
                }
                if (s.RemainingServerHello > 0)
                {
                    int end = Math.Min(s.RemainingServerHello, n);
                    s.RemainingServerHello -= n;
                    if (Contains(a, o, end, Tls13SupportedVersions))
                    {
                        // Tls13CipherSuiteDic minus TLS_AES_128_CCM_8_SHA256 (0x1305); an unparsed cipher (0) stays off.
                        if (s.Cipher >= 0x1301 && s.Cipher <= 0x1304) s.EnableXtls = true;
                        s.NumberOfPacketToFilter = 0;
                        return;
                    }
                    if (s.RemainingServerHello <= 0)   // TLS 1.2 or older
                    {
                        s.NumberOfPacketToFilter = 0;
                        return;
                    }
                }
            }
        }

        /// <summary>IsCompleteRecord: the data is one or more whole TLS application_data records (17 03 03 len body),
        /// ending exactly on a record boundary. A zero-length record makes it false; empty input is true.</summary>
        public static bool IsCompleteRecord(byte[] b, int off, int count)
        {
            int headerLen = 5, recordLen = 0;
            int i = off, total = off + count;
            while (i < total)
            {
                if (headerLen > 0)
                {
                    byte data = b[i++];
                    switch (headerLen)
                    {
                        case 5: if (data != 0x17) return false; break;
                        case 4: if (data != 0x03) return false; break;
                        case 3: if (data != 0x03) return false; break;
                        case 2: recordLen = data << 8; break;
                        case 1: recordLen |= data; break;
                    }
                    headerLen--;
                }
                else if (recordLen > 0)
                {
                    if (total - i < recordLen) return false;
                    i += recordLen;
                    recordLen = 0;
                    headerLen = 5;
                }
                else return false;
            }
            return headerLen == 5 && recordLen == 0;
        }

        /// <summary>ReshapeMultiBuffer: a buffer of ≥ 8171 bytes can't take the 21-byte frame overhead, so it is split
        /// once — at its last 17 03 03 if that lies in [21, 8171], else in the middle (4096).</summary>
        public static List<ArraySegment<byte>> Reshape(List<ArraySegment<byte>> mb)
        {
            bool need = false;
            foreach (var b in mb) if (b.Count >= BufSize - 21) { need = true; break; }
            if (!need) return mb;
            var r = new List<ArraySegment<byte>>(mb.Count + 2);
            foreach (var b in mb)
            {
                if (b.Count < BufSize - 21) { r.Add(b); continue; }
                int index = LastIndexOfAppData(b.Array, b.Offset, b.Count);
                if (index < 21 || index > BufSize - 21) index = BufSize / 2;
                r.Add(new ArraySegment<byte>(b.Array, b.Offset, index));
                r.Add(new ArraySegment<byte>(b.Array, b.Offset + index, b.Count - index));
            }
            return r;
        }

        /// <summary>XtlsPadding: [UUID, first frame only] [cmd] [contentLen u16] [paddingLen u16] content zeros.</summary>
        public static byte[] Pad(ArraySegment<byte> content, byte command, ref byte[] uuidOnce, bool longPadding)
        {
            int contentLen = content.Array != null ? content.Count : 0;
            int paddingLen;
            lock (Rng)
            {
                paddingLen = contentLen < LongThreshold && longPadding
                    ? Rng.Next(LongRandom) + LongBase - contentLen
                    : Rng.Next(ShortRandom);
            }
            if (paddingLen > BufSize - 21 - contentLen) paddingLen = BufSize - 21 - contentLen;
            int uuidLen = uuidOnce != null ? 16 : 0;
            var f = new byte[uuidLen + 5 + contentLen + paddingLen];   // padding bytes stay zero (buf.Extend clears)
            if (uuidOnce != null) { Buffer.BlockCopy(uuidOnce, 0, f, 0, 16); uuidOnce = null; }
            f[uuidLen] = command;
            f[uuidLen + 1] = (byte)(contentLen >> 8); f[uuidLen + 2] = (byte)contentLen;
            f[uuidLen + 3] = (byte)(paddingLen >> 8); f[uuidLen + 4] = (byte)paddingLen;
            if (contentLen > 0) Buffer.BlockCopy(content.Array, content.Offset, f, uuidLen + 5, contentLen);
            return f;
        }

        /// <summary>XtlsUnpadding for one received buffer: appends the de-framed content to <paramref name="output"/>.
        /// In the initial state a buffer that doesn't start with our UUID (or is shorter than 21 bytes) passes through
        /// untouched; after an End/Direct frame the state resets and any trailing bytes are passed through.</summary>
        public static void Unpad(byte[] b, int off, int len, VisionState s, MemoryStream output)
        {
            int p = off, end = off + len;
            if (s.RemainingCommand == -1 && s.RemainingContent == -1 && s.RemainingPadding == -1)   // initial state
            {
                if (len >= 21 && StartsWith(b, off, s.UserUuid))
                {
                    p += 16;
                    s.RemainingCommand = 5;
                }
                else
                {
                    output.Write(b, off, len);
                    return;
                }
            }
            while (p < end)
            {
                if (s.RemainingCommand > 0)
                {
                    byte data = b[p++];
                    switch (s.RemainingCommand)
                    {
                        case 5: s.CurrentCommand = data; break;
                        case 4: s.RemainingContent = data << 8; break;
                        case 3: s.RemainingContent |= data; break;
                        case 2: s.RemainingPadding = data << 8; break;
                        case 1: s.RemainingPadding |= data; break;
                    }
                    s.RemainingCommand--;
                }
                else if (s.RemainingContent > 0)
                {
                    int n = Math.Min(s.RemainingContent, end - p);
                    output.Write(b, p, n);
                    p += n;
                    s.RemainingContent -= n;
                }
                else
                {
                    int n = Math.Min(s.RemainingPadding, end - p);
                    p += n;
                    s.RemainingPadding -= n;
                }
                if (s.RemainingCommand <= 0 && s.RemainingContent <= 0 && s.RemainingPadding <= 0)   // this block done
                {
                    if (s.CurrentCommand == 0)
                    {
                        s.RemainingCommand = 5;
                    }
                    else
                    {
                        s.RemainingCommand = s.RemainingContent = s.RemainingPadding = -1;   // back to the initial state
                        if (p < end) output.Write(b, p, end - p);                          // "shouldn't happen"
                        break;
                    }
                }
            }
        }

        public static bool StartsWithAppData(ArraySegment<byte> b)
            => b.Count >= 6 && b.Array[b.Offset] == 0x17 && b.Array[b.Offset + 1] == 0x03 && b.Array[b.Offset + 2] == 0x03;

        private static bool StartsWith(byte[] b, int off, byte[] prefix)
        {
            for (int i = 0; i < prefix.Length; i++) if (b[off + i] != prefix[i]) return false;
            return true;
        }

        private static bool Contains(byte[] a, int off, int len, byte[] needle)
        {
            for (int i = off; i + needle.Length <= off + len; i++)
            {
                int k = 0;
                while (k < needle.Length && a[i + k] == needle[k]) k++;
                if (k == needle.Length) return true;
            }
            return false;
        }

        private static int LastIndexOfAppData(byte[] a, int off, int len)
        {
            for (int i = len - 3; i >= 0; i--)
                if (a[off + i] == 0x17 && a[off + i + 1] == 0x03 && a[off + i + 2] == 0x03) return i;
            return -1;
        }
    }

    /// <summary>
    /// The client side of VLESS flow "xtls-rprx-vision" over our TLS 1.3 / REALITY stream (Xray VisionWriter +
    /// VisionReader + the vless outbound's header handling). The tunnelled stream's first packets are wrapped in padded
    /// frames so their lengths don't betray TLS-in-TLS; once the inner traffic is TLS 1.3 application data, each direction
    /// sends a Direct frame and switches its side of <see cref="Tls13Stream"/> to raw: the inner TLS records then travel
    /// on the socket without a second encryption layer.
    /// <para>Concurrency: one reader (downlink pump) and any number of serialized writers (uplink pump + the 500 ms idle
    /// frame). The filter state they share is guarded by one lock that is never held across I/O.</para>
    /// </summary>
    internal sealed class VisionStream : Stream
    {
        private const int IdleFirstFrameMs = 500;   // Xray: ReadMultiBufferTimeout(500 ms), then an empty padded frame

        private readonly Tls13Stream _outer;
        private readonly VisionState _s;
        private readonly object _sync = new object();
        private readonly SemaphoreSlim _writeGate = new SemaphoreSlim(1, 1);
        private readonly CancellationTokenSource _idle = new CancellationTokenSource();
        private byte[] _header;      // VLESS request header: goes out with the first frame, then null
        private byte[] _uuidOnce;    // the writer's UUID copy: prefixes the first uplink frame only

        // reader
        private bool _responseRead;
        private readonly byte[] _chunk = new byte[Vision.BufSize];
        private byte[] _out = new byte[0];
        private int _outOff, _outLen;
        private int _disposed;

        public VisionStream(Tls13Stream outer, byte[] uuid, byte[] requestHeader)
        {
            _outer = outer;
            _s = new VisionState((byte[])uuid.Clone());
            _uuidOnce = (byte[])uuid.Clone();
            _header = requestHeader;
        }

        /// <summary>Diagnostics: did each direction reach raw direct copy? (Uplink: our Direct frame went out; the raw
        /// switch itself happens on the next write.)</summary>
        public bool UplinkDirect { get; private set; }
        public bool DownlinkDirect { get; private set; }
        /// <summary>Diagnostics: the uplink actually switched to raw (a write followed our Direct frame).</summary>
        public bool UplinkRaw { get; private set; }

        /// <summary>Diagnostics hook (test harnesses): one line per framed write / processed read. Null in the app.</summary>
        internal static Action<string> Trace { get; set; }

        private string StateText() => "tls=" + (_s.IsTls ? 1 : 0) + " tls12+=" + (_s.IsTls12OrAbove ? 1 : 0) + " xtls=" + (_s.EnableXtls ? 1 : 0)
                                    + " cipher=" + _s.Cipher.ToString("x4") + " filter=" + _s.NumberOfPacketToFilter;

        /// <summary>Arms the idle timer: if the local app hasn't written within 500 ms (server-speaks-first protocols),
        /// the request header goes out with an empty long-padded frame so the server can start.</summary>
        public void Start() => Task.Run(IdleFirstFrameAsync);

        private async Task IdleFirstFrameAsync()
        {
            try { await Task.Delay(IdleFirstFrameMs, _idle.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }
            try
            {
                await _writeGate.WaitAsync(_idle.Token).ConfigureAwait(false);
                try
                {
                    if (_header == null) return;   // the app wrote first
                    byte[] frame;
                    lock (_sync) frame = Vision.Pad(default(ArraySegment<byte>), Vision.CommandContinue, ref _uuidOnce, true);
                    await SendAsync(new List<byte[]> { frame }, CancellationToken.None).ConfigureAwait(false);
                }
                finally { _writeGate.Release(); }
            }
            catch { }   // a dead connection surfaces through the relay's read pump
        }

        // ───────────────────────── uplink (VisionWriter.WriteMultiBuffer) ─────────────────────────

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return;
            await _writeGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                List<byte[]> frames;
                lock (_sync)
                {
                    if (_s.UplinkWriterDirectCopy)
                    {
                        // The previous write ended with our Direct frame: from here on the uplink is raw TCP.
                        _outer.SwitchWriteToRaw();
                        _s.UplinkWriterDirectCopy = false;
                        UplinkRaw = true;
                    }
                    if (!_s.IsPadding && _s.NumberOfPacketToFilter <= 0) frames = null;   // plain pass-through
                    else frames = Frame(buffer, offset, count);
                    if (_s.UplinkWriterDirectCopy) { UplinkDirect = true; _outer.SuppressOuterRecords(); }   // peer reads us raw after this frame
                    Trace?.Invoke("up   " + count + " bytes -> " + (frames == null ? "pass-through" : frames.Count + " write(s)") + " padding=" + (_s.IsPadding ? 1 : 0) + " " + StateText());
                }
                if (frames == null) await _outer.WriteAsync(buffer, offset, count, ct).ConfigureAwait(false);
                else await SendAsync(frames, ct).ConfigureAwait(false);
            }
            finally { _writeGate.Release(); }
        }

        // Splits one app write into ≤ 8192-byte buffers (Xray's MultiBuffer), filters, and pads while padding lasts.
        // Returns the byte arrays to put on the wire, one outer TLS record each. Runs under _sync.
        private List<byte[]> Frame(byte[] buffer, int offset, int count)
        {
            var mb = new List<ArraySegment<byte>>((count + Vision.BufSize - 1) / Vision.BufSize);
            var copy = new byte[count];
            Buffer.BlockCopy(buffer, offset, copy, 0, count);
            for (int o = 0; o < count; o += Vision.BufSize)
                mb.Add(new ArraySegment<byte>(copy, o, Math.Min(Vision.BufSize, count - o)));

            if (_s.NumberOfPacketToFilter > 0) Vision.FilterTls(mb, _s);

            var frames = new List<byte[]>(mb.Count + 2);
            if (!_s.IsPadding)
            {
                foreach (var b in mb) frames.Add(Slice(b));
                return frames;
            }

            bool isComplete = Vision.IsCompleteRecord(copy, 0, count);
            mb = Vision.Reshape(mb);
            bool longPadding = _s.IsTls;
            for (int i = 0; i < mb.Count; i++)
            {
                var b = mb[i];
                bool last = i == mb.Count - 1;
                if (_s.IsTls && Vision.StartsWithAppData(b) && isComplete)
                {
                    if (_s.EnableXtls) _s.UplinkWriterDirectCopy = true;
                    byte command = Vision.CommandContinue;
                    if (last) command = _s.EnableXtls ? Vision.CommandDirect : Vision.CommandEnd;
                    frames.Add(Vision.Pad(b, command, ref _uuidOnce, true));
                    _s.IsPadding = false;   // padding going to end
                    longPadding = false;
                    continue;
                }
                if (!_s.IsTls12OrAbove && _s.NumberOfPacketToFilter <= 1)
                {
                    // Non-TLS (or unrecognized) traffic: end padding one packet early, as Xray does for older receivers.
                    _s.IsPadding = false;
                    frames.Add(Vision.Pad(b, Vision.CommandEnd, ref _uuidOnce, longPadding));
                    for (int j = i + 1; j < mb.Count; j++) frames.Add(Slice(mb[j]));   // the rest of this write, unframed
                    break;
                }
                byte cmd = Vision.CommandContinue;
                if (last && !_s.IsPadding) cmd = _s.EnableXtls ? Vision.CommandDirect : Vision.CommandEnd;
                frames.Add(Vision.Pad(b, cmd, ref _uuidOnce, longPadding));
            }
            return frames;
        }

        // The first send carries the request header in front of the first frame(s), cut into 8192-byte outer writes
        // (Xray's BufferedWriter), so the server's first read sees the header plus ≥ 21 bytes of framing. Later sends:
        // one outer TLS record per frame, like Xray's per-buffer writes. Caller holds _writeGate.
        private async Task SendAsync(List<byte[]> frames, CancellationToken ct)
        {
            if (_header != null)
            {
                int total = _header.Length;
                foreach (var f in frames) total += f.Length;
                var all = new byte[total];
                Buffer.BlockCopy(_header, 0, all, 0, _header.Length);
                int p = _header.Length;
                foreach (var f in frames) { Buffer.BlockCopy(f, 0, all, p, f.Length); p += f.Length; }
                _header = null;
                _idle.Cancel();
                for (int o = 0; o < all.Length; o += Vision.BufSize)
                    await _outer.WriteAsync(all, o, Math.Min(Vision.BufSize, all.Length - o), ct).ConfigureAwait(false);
                return;
            }
            foreach (var f in frames) await _outer.WriteAsync(f, 0, f.Length, ct).ConfigureAwait(false);
        }

        private static byte[] Slice(ArraySegment<byte> b)
        {
            var r = new byte[b.Count];
            Buffer.BlockCopy(b.Array, b.Offset, r, 0, b.Count);
            return r;
        }

        // ───────────────────────── downlink (VisionReader.ReadMultiBuffer) ─────────────────────────

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return 0;
            while (true)
            {
                if (_outLen > 0)
                {
                    int n = Math.Min(count, _outLen);
                    Buffer.BlockCopy(_out, _outOff, buffer, offset, n);
                    _outOff += n; _outLen -= n;
                    return n;
                }
                if (!_responseRead) { await ReadResponseHeaderAsync(ct).ConfigureAwait(false); _responseRead = true; }
                if (DownlinkDirect) return await _outer.ReadAsync(buffer, offset, count, ct).ConfigureAwait(false);

                // One outer read = one Xray buffer: ≤ 8192 bytes, never spanning two TLS records.
                int got = await _outer.ReadAsync(_chunk, 0, _chunk.Length, ct).ConfigureAwait(false);
                if (got <= 0) return 0;
                Process(got);
            }
        }

        private void Process(int got)
        {
            byte[] data; int len;
            lock (_sync)
            {
                if (_s.WithinPaddingBuffers || _s.NumberOfPacketToFilter > 0)
                {
                    var ms = new MemoryStream(got);
                    Vision.Unpad(_chunk, 0, got, _s, ms);
                    data = ms.GetBuffer(); len = (int)ms.Length;
                    if (_s.RemainingContent > 0 || _s.RemainingPadding > 0 || _s.CurrentCommand == 0) _s.WithinPaddingBuffers = true;
                    else if (_s.CurrentCommand == 1) _s.WithinPaddingBuffers = false;
                    else if (_s.CurrentCommand == 2) { _s.WithinPaddingBuffers = false; _s.DownlinkReaderDirectCopy = true; }
                }
                else
                {
                    data = new byte[got];
                    Buffer.BlockCopy(_chunk, 0, data, 0, got);
                    len = got;
                }
                if (_s.NumberOfPacketToFilter > 0 && len > 0)
                    Vision.FilterTls(new[] { new ArraySegment<byte>(data, 0, len) }, _s);
                if (_s.DownlinkReaderDirectCopy && !DownlinkDirect)
                {
                    // Everything after the Direct frame is raw: first the rest of the current outer record's plaintext
                    // (Tls13Stream returns it first), then the socket.
                    _outer.SwitchReadToRaw();
                    DownlinkDirect = true;
                }
                Trace?.Invoke("down " + got + " bytes -> " + len + " content cmd=" + _s.CurrentCommand + " rem=" + _s.RemainingCommand + "/" + _s.RemainingContent + "/" + _s.RemainingPadding
                              + " within=" + (_s.WithinPaddingBuffers ? 1 : 0) + " direct=" + (DownlinkDirect ? 1 : 0) + " " + StateText());
            }
            _out = data; _outOff = 0; _outLen = len;
        }

        // VLESS response header: version (must echo 0) + addons length + addons.
        private async Task ReadResponseHeaderAsync(CancellationToken ct)
        {
            var b = new byte[255];
            await ReadExactAsync(b, 2, ct).ConfigureAwait(false);
            if (b[0] != 0) throw new IOException("VLESS: unexpected response version " + b[0]);
            if (b[1] > 0) await ReadExactAsync(b, b[1], ct).ConfigureAwait(false);
        }

        private async Task ReadExactAsync(byte[] b, int n, CancellationToken ct)
        {
            int got = 0;
            while (got < n)
            {
                int r = await _outer.ReadAsync(b, got, n - got, ct).ConfigureAwait(false);
                if (r <= 0) throw new IOException(VlessProtocol.NoAnswerMessage);
                got += r;
            }
        }

        // ───────────────────────── Stream plumbing ─────────────────────────

        public override Task FlushAsync(CancellationToken ct) => _outer.FlushAsync(ct);
        public override void Flush() => _outer.Flush();
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
                try { _idle.Cancel(); } catch { }
                try { _outer.Dispose(); } catch { }   // silent once raw (no outer close_notify)
            }
            base.Dispose(disposing);
        }
    }
}

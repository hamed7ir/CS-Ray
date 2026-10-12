using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Transport.Http2
{
    internal sealed class Http2Exception : IOException
    {
        public Http2Exception(string message) : base(message) { }
    }

    /// <summary>
    /// A minimal HTTP/2 client connection (RFC 9113) over an already-secured duplex stream (our TLS 1.3 / REALITY stream):
    /// client-initiated request streams only — no server push, no priorities, no 0-RTT. One reader loop dispatches frames;
    /// frame writes are serialized. Flow control both ways: we respect the peer's connection/stream windows when sending
    /// DATA, and replenish ours with WINDOW_UPDATE as the app consumes data (so a slow consumer bounds buffering to one
    /// stream window). Initial values follow Go's x/net/http2 Transport, which is what Xray's XHTTP client uses.
    /// </summary>
    internal sealed class Http2Connection : IDisposable
    {
        // ── our side (what we advertise) ──
        internal const int OurInitialStreamWindow = 4 << 20;    // SETTINGS_INITIAL_WINDOW_SIZE
        internal const int OurConnectionWindow = 1 << 30;       // after the initial WINDOW_UPDATE on stream 0
        internal const int OurMaxHeaderListSize = 10 << 20;     // SETTINGS_MAX_HEADER_LIST_SIZE
        internal const int OurHeaderTableSize = 4096;           // default (not sent)
        internal const int OurMaxFrameSize = 1 << 20;           // SETTINGS_MAX_FRAME_SIZE (Go: defaultMaxReadFrameSize)

        // Keepalive like Go's ReadIdleTimeout/PingTimeout as Xray sets them (hKeepAlivePeriod 0 → 45 s): after this long
        // without any frame from the server, PING; no ACK (or any frame) within PingTimeout → the connection is dead.
        internal const int ReadIdleMs = 45000, PingTimeoutMs = 15000;

        private static readonly byte[] Preface = Encoding.ASCII.GetBytes("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        private const byte FrData = 0, FrHeaders = 1, FrPriority = 2, FrRstStream = 3, FrSettings = 4, FrPushPromise = 5,
                           FrPing = 6, FrGoAway = 7, FrWindowUpdate = 8, FrContinuation = 9;
        private const byte FlEndStream = 0x1, FlAck = 0x1, FlEndHeaders = 0x4, FlPadded = 0x8, FlPriority = 0x20;

        private readonly Stream _io;
        private readonly SemaphoreSlim _writeLock = new SemaphoreSlim(1, 1);
        private readonly object _sync = new object();
        private readonly Dictionary<int, Http2Stream> _streams = new Dictionary<int, Http2Stream>();
        private readonly HpackDecoder _hpack = new HpackDecoder(OurHeaderTableSize, 256 << 10);   // decoded list ≤ 256 KiB
        private readonly byte[] _hdr = new byte[9];
        private int _nextStreamId = 1;
        private long _connSendWindow = 65535;       // the peer's connection receive window
        private int _peerInitialWindow = 65535;     // the peer's SETTINGS_INITIAL_WINDOW_SIZE (our stream send windows)
        private int _peerMaxFrame = 16384;
        private int _peerMaxConcurrent = int.MaxValue;
        private int _connRecvConsumed;              // bytes consumed since our last connection WINDOW_UPDATE
        private TaskCompletionSource<bool> _windowChanged = NewTcs();
        private volatile bool _closed;
        private volatile bool _goAway;
        private string _closeReason;
        private int _disposed;
        private Timer _keepalive;
        private long _lastFrameTicks = System.Diagnostics.Stopwatch.GetTimestamp();
        private long _pingSentTicks;   // 0 = no outstanding keepalive PING

        public Task ReaderTask { get; private set; }

        private static long MsSince(long ticks) => (System.Diagnostics.Stopwatch.GetTimestamp() - ticks) * 1000 / System.Diagnostics.Stopwatch.Frequency;

        private void KeepaliveTick(object _)
        {
            if (_closed) { try { _keepalive?.Dispose(); } catch { } return; }
            long sent = Interlocked.Read(ref _pingSentTicks);
            if (sent != 0)
            {
                if (MsSince(sent) > PingTimeoutMs) { _closeReason = "keepalive PING timed out"; try { _io.Dispose(); } catch { } }
                return;
            }
            if (MsSince(Interlocked.Read(ref _lastFrameTicks)) > ReadIdleMs)
            {
                Interlocked.Exchange(ref _pingSentTicks, System.Diagnostics.Stopwatch.GetTimestamp());
                var data = new byte[8]; data[0] = 0x43; data[1] = 0x53;   // opaque
                SendControl(FrPing, 0, 0, data);
            }
        }

        /// <summary>Raised once when the connection dies (reader loop ends); the argument is the reason.</summary>
        public event Action<string> Closed;

        private Http2Connection(Stream io) { _io = io; }

        /// <summary>Sends the client preface + SETTINGS + connection WINDOW_UPDATE (one write, like Go) and starts the
        /// reader loop. The server's SETTINGS arrive asynchronously; requests may be sent right away (RFC 9113 §3.4).</summary>
        public static async Task<Http2Connection> StartAsync(Stream io, CancellationToken ct)
        {
            var c = new Http2Connection(io);
            var m = new MemoryStream();
            m.Write(Preface, 0, Preface.Length);
            var settings = new MemoryStream();
            WriteSetting(settings, 0x2, 0);                          // ENABLE_PUSH = 0
            WriteSetting(settings, 0x4, OurInitialStreamWindow);     // INITIAL_WINDOW_SIZE
            WriteSetting(settings, 0x5, OurMaxFrameSize);            // MAX_FRAME_SIZE
            WriteSetting(settings, 0x6, OurMaxHeaderListSize);       // MAX_HEADER_LIST_SIZE
            WriteFrameTo(m, FrSettings, 0, 0, settings.ToArray(), 0, (int)settings.Length);
            var inc = new byte[4]; PutUInt31(inc, 0, OurConnectionWindow - 65535);
            WriteFrameTo(m, FrWindowUpdate, 0, 0, inc, 0, 4);
            var bytes = m.ToArray();
            await io.WriteAsync(bytes, 0, bytes.Length, ct).ConfigureAwait(false);
            await io.FlushAsync(ct).ConfigureAwait(false);
            c.ReaderTask = Task.Run(c.ReadLoopAsync);
            c._keepalive = new Timer(c.KeepaliveTick, null, 5000, 5000);
            return c;
        }

        public bool IsClosed => _closed;
        public string CloseReason => _closeReason;

        /// <summary>Streams currently open on this connection.</summary>
        public int ActiveStreams { get { lock (_sync) return _streams.Count; } }

        /// <summary>True when a new stream may be opened (not closed, no GOAWAY, under the peer's concurrency limit).</summary>
        public bool CanOpenStream
        {
            get { lock (_sync) return !_closed && !_goAway && _streams.Count < _peerMaxConcurrent && _nextStreamId < int.MaxValue - 2; }
        }

        /// <summary>Closed, or the server sent GOAWAY: no new streams ever (unlike a momentarily full connection).</summary>
        public bool IsDraining => _closed || _goAway;

        /// <summary>Opens a request stream: sends HEADERS (without END_STREAM — the body follows on the returned stream).</summary>
        public async Task<Http2Stream> OpenStreamAsync(IList<HeaderField> headers, CancellationToken ct)
        {
            byte[] block = HpackEncoder.Encode(headers);
            Http2Stream s;
            await _writeLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                lock (_sync)
                {
                    if (_closed) throw new Http2Exception("HTTP/2: connection closed" + (_closeReason != null ? " (" + _closeReason + ")" : ""));
                    if (_goAway) throw new Http2Exception("HTTP/2: the server sent GOAWAY");
                    int id = _nextStreamId; _nextStreamId += 2;   // ids must be sent in increasing order: allocated under the write lock
                    s = new Http2Stream(this, id, _peerInitialWindow, OurInitialStreamWindow);
                    _streams[id] = s;
                }
                // HEADERS (+ CONTINUATION if the block exceeds the peer's max frame size).
                int first = Math.Min(block.Length, _peerMaxFrame);
                await WriteFrameAsync(FrHeaders, (byte)(first == block.Length ? FlEndHeaders : 0), s.Id, block, 0, first, ct).ConfigureAwait(false);
                for (int off = first; off < block.Length;)
                {
                    int n = Math.Min(block.Length - off, _peerMaxFrame);
                    await WriteFrameAsync(FrContinuation, (byte)(off + n == block.Length ? FlEndHeaders : 0), s.Id, block, off, n, ct).ConfigureAwait(false);
                    off += n;
                }
                await _io.FlushAsync(ct).ConfigureAwait(false);
            }
            finally { _writeLock.Release(); }
            return s;
        }

        // ───────────────────────── sending (used by Http2Stream) ─────────────────────────

        internal async Task SendDataAsync(Http2Stream s, byte[] buf, int off, int count, bool endStream, CancellationToken ct)
        {
            while (count > 0 || endStream)
            {
                int n;
                Task wait = null;
                lock (_sync)
                {
                    if (_closed) throw new Http2Exception("HTTP/2: connection closed" + (_closeReason != null ? " (" + _closeReason + ")" : ""));
                    var rc = s.ResetCode;
                    if (rc.HasValue) throw new Http2Exception("HTTP/2: stream " + (rc.Value == 0 ? "closed" : "reset") + " by the server (" + ErrorName(rc.Value) + ")");
                    if (s.Dead) throw new Http2Exception("HTTP/2: stream closed");
                    long allowed = Math.Min(Math.Min(_connSendWindow, s.SendWindow), _peerMaxFrame);
                    if (count > 0 && allowed <= 0) { n = 0; wait = _windowChanged.Task; }
                    else
                    {
                        n = (int)Math.Max(0, Math.Min(count, allowed));
                        _connSendWindow -= n; s.SendWindow -= n;
                    }
                }
                if (wait != null)
                {
                    if (ct.CanBeCanceled)
                    {
                        var cancelled = new TaskCompletionSource<bool>();
                        using (ct.Register(() => cancelled.TrySetResult(true)))
                            await Task.WhenAny(wait, cancelled.Task).ConfigureAwait(false);
                        ct.ThrowIfCancellationRequested();
                    }
                    else await wait.ConfigureAwait(false);
                    continue;
                }
                bool last = endStream && n == count;
                await _writeLock.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    await WriteFrameAsync(FrData, (byte)(last ? FlEndStream : 0), s.Id, buf, off, n, ct).ConfigureAwait(false);
                    await _io.FlushAsync(ct).ConfigureAwait(false);
                }
                finally { _writeLock.Release(); }
                off += n; count -= n;
                if (last) break;
            }
        }

        internal void SendWindowUpdate(int streamId, int increment)
        {
            var p = new byte[4]; PutUInt31(p, 0, increment);
            SendControl(FrWindowUpdate, 0, streamId, p);
        }

        /// <summary>The app consumed `n` DATA bytes of stream `s`: replenish the stream and connection receive windows
        /// once half of each has been used (Go's transport does the same).</summary>
        internal void Consumed(Http2Stream s, int n)
        {
            int streamInc = 0, connInc = 0;
            lock (_sync)
            {
                s.RecvConsumed += n;
                if (!s.RemoteEnded && s.RecvConsumed >= OurInitialStreamWindow / 2) { streamInc = s.RecvConsumed; s.RecvConsumed = 0; }
                _connRecvConsumed += n;
                if (_connRecvConsumed >= OurConnectionWindow / 2 || _connRecvConsumed >= 4 << 20) { connInc = _connRecvConsumed; _connRecvConsumed = 0; }
            }
            if (streamInc > 0) SendWindowUpdate(s.Id, streamInc);
            if (connInc > 0) SendWindowUpdate(0, connInc);
        }

        internal void ResetStream(Http2Stream s, uint errorCode)
        {
            lock (_sync) { if (!_streams.Remove(s.Id)) return; }
            var p = new byte[4]; PutUInt32(p, 0, errorCode);
            SendControl(FrRstStream, 0, s.Id, p);
        }

        internal void Forget(Http2Stream s) { lock (_sync) _streams.Remove(s.Id); }

        /// <summary>A stream died (reset, GOAWAY, local dispose): wake writers parked on flow control so they re-check.</summary>
        internal void WakeWriters() { lock (_sync) PulseWindow(); }

        /// <summary>Gives back connection-window credit for DATA that will never be read (a torn-down stream's buffer),
        /// as Go's Close does — else aborted streams slowly starve a long-lived shared connection.</summary>
        internal void Refund(int n) { if (n > 0) Consumed0(n); }

        // Caller holds _writeLock.
        private Task WriteFrameAsync(byte type, byte flags, int streamId, byte[] payload, int off, int len, CancellationToken ct)
        {
            var f = new byte[9 + len];
            f[0] = (byte)(len >> 16); f[1] = (byte)(len >> 8); f[2] = (byte)len;
            f[3] = type; f[4] = flags;
            PutUInt31(f, 5, streamId);
            if (len > 0) Buffer.BlockCopy(payload, off, f, 9, len);
            return _io.WriteAsync(f, 0, f.Length, ct);
        }

        private static void WriteFrameTo(Stream m, byte type, byte flags, int streamId, byte[] payload, int off, int len)
        {
            var h = new byte[9];
            h[0] = (byte)(len >> 16); h[1] = (byte)(len >> 8); h[2] = (byte)len; h[3] = type; h[4] = flags;
            PutUInt31(h, 5, streamId);
            m.Write(h, 0, 9);
            if (len > 0) m.Write(payload, off, len);
        }

        private static void WriteSetting(Stream m, int id, int value)
        {
            m.WriteByte((byte)(id >> 8)); m.WriteByte((byte)id);
            m.WriteByte((byte)(value >> 24)); m.WriteByte((byte)(value >> 16)); m.WriteByte((byte)(value >> 8)); m.WriteByte((byte)value);
        }

        // ───────────────────────── reader loop ─────────────────────────

        private async Task ReadLoopAsync()
        {
            string reason = "connection closed by the server";
            try
            {
                int headerStream = 0;                 // a header block in progress (CONTINUATION expected), else 0
                byte headerFlags = 0;
                MemoryStream headerBlock = null;
                while (true)
                {
                    if (!await ReadExactAsync(_hdr, 9).ConfigureAwait(false)) break;
                    int len = (_hdr[0] << 16) | (_hdr[1] << 8) | _hdr[2];
                    byte type = _hdr[3], flags = _hdr[4];
                    int sid = ((_hdr[5] & 0x7F) << 24) | (_hdr[6] << 16) | (_hdr[7] << 8) | _hdr[8];
                    if (len > OurMaxFrameSize) throw new Http2Exception("HTTP/2: frame larger than our max frame size");
                    Interlocked.Exchange(ref _lastFrameTicks, System.Diagnostics.Stopwatch.GetTimestamp());
                    Interlocked.Exchange(ref _pingSentTicks, 0);   // any frame proves the connection alive
                    var payload = new byte[len];
                    if (len > 0 && !await ReadExactAsync(payload, len).ConfigureAwait(false)) throw new Http2Exception("HTTP/2: connection closed inside a frame");

                    if (headerStream != 0 && (type != FrContinuation || sid != headerStream))
                        throw new Http2Exception("HTTP/2: expected CONTINUATION");

                    switch (type)
                    {
                        case FrData:
                            OnData(sid, flags, payload);
                            break;
                        case FrHeaders:
                        {
                            if (sid == 0) throw new Http2Exception("HTTP/2: HEADERS on stream 0");
                            int p = 0, end = len;
                            if ((flags & FlPadded) != 0) { if (len < 1) throw new Http2Exception("HTTP/2: bad padding"); end -= payload[0]; p = 1; }
                            if ((flags & FlPriority) != 0) p += 5;
                            if (p > end) throw new Http2Exception("HTTP/2: bad HEADERS frame");
                            headerBlock = new MemoryStream();
                            headerBlock.Write(payload, p, end - p);
                            headerFlags = flags;
                            if ((flags & FlEndHeaders) != 0) { OnHeaderBlock(sid, headerFlags, headerBlock.ToArray()); headerBlock = null; }
                            else headerStream = sid;
                            break;
                        }
                        case FrContinuation:
                            if (headerStream == 0 || sid != headerStream) throw new Http2Exception("HTTP/2: unexpected CONTINUATION");
                            headerBlock.Write(payload, 0, len);
                            if (headerBlock.Length > OurMaxHeaderListSize) throw new Http2Exception("HTTP/2: header block too large");
                            if ((flags & FlEndHeaders) != 0) { OnHeaderBlock(sid, headerFlags, headerBlock.ToArray()); headerBlock = null; headerStream = 0; }
                            break;
                        case FrPriority:
                            break;
                        case FrRstStream:
                        {
                            if (len != 4) throw new Http2Exception("HTTP/2: bad RST_STREAM");
                            uint code = GetUInt32(payload, 0);
                            Http2Stream s;
                            lock (_sync) { _streams.TryGetValue(sid, out s); _streams.Remove(sid); }
                            s?.OnReset(code);
                            break;
                        }
                        case FrSettings:
                            if ((flags & FlAck) != 0) break;
                            if (len % 6 != 0) throw new Http2Exception("HTTP/2: bad SETTINGS");
                            ApplySettings(payload);
                            SendControl(FrSettings, FlAck, 0, new byte[0]);
                            break;
                        case FrPushPromise:
                            throw new Http2Exception("HTTP/2: PUSH_PROMISE although push is disabled");
                        case FrPing:
                            if (len != 8) throw new Http2Exception("HTTP/2: bad PING");
                            if ((flags & FlAck) == 0) SendControl(FrPing, FlAck, 0, payload);
                            break;
                        case FrGoAway:
                        {
                            if (len < 8) throw new Http2Exception("HTTP/2: bad GOAWAY");
                            int last = (int)(GetUInt32(payload, 0) & 0x7FFFFFFF);
                            uint code = GetUInt32(payload, 4);
                            List<Http2Stream> dead = new List<Http2Stream>();
                            lock (_sync)
                            {
                                _goAway = true;
                                foreach (var kv in _streams) if (kv.Key > last) dead.Add(kv.Value);
                                foreach (var d in dead) _streams.Remove(d.Id);
                                _closeReason = "GOAWAY " + ErrorName(code);
                            }
                            foreach (var d in dead) d.OnReset(7 /* REFUSED_STREAM */);
                            break;
                        }
                        case FrWindowUpdate:
                        {
                            if (len != 4) throw new Http2Exception("HTTP/2: bad WINDOW_UPDATE");
                            int inc = (int)(GetUInt32(payload, 0) & 0x7FFFFFFF);
                            lock (_sync)
                            {
                                if (sid == 0) _connSendWindow += inc;
                                else if (_streams.TryGetValue(sid, out var s)) s.SendWindow += inc;
                                PulseWindow();
                            }
                            break;
                        }
                        default:
                            break;   // unknown frame types are ignored (RFC 9113 §4.1)
                    }
                }
            }
            catch (Exception ex) { reason = ex.Message; }
            try { _keepalive?.Dispose(); } catch { }
            Shutdown(reason);
        }

        private void OnData(int sid, byte flags, byte[] payload)
        {
            if (sid == 0) throw new Http2Exception("HTTP/2: DATA on stream 0");
            int p = 0, end = payload.Length;
            if ((flags & FlPadded) != 0) { if (end < 1 || payload[0] >= end) throw new Http2Exception("HTTP/2: bad padding"); end -= payload[0]; p = 1; }
            Http2Stream s;
            lock (_sync) _streams.TryGetValue(sid, out s);
            // Flow control counts the whole frame payload, padding included (RFC 9113 §6.9.1).
            int padOverhead = payload.Length - (end - p);
            if (s == null)
            {
                // A stream we already reset/forgot: still give the connection window back.
                if (payload.Length > 0) Consumed0(payload.Length);
                return;
            }
            if (end > p) s.OnData(payload, p, end - p);
            if (padOverhead > 0) Consumed(s, padOverhead);
            if ((flags & FlEndStream) != 0) s.OnRemoteEnd();
        }

        private void Consumed0(int n)
        {
            int connInc = 0;
            lock (_sync) { _connRecvConsumed += n; if (_connRecvConsumed >= 4 << 20) { connInc = _connRecvConsumed; _connRecvConsumed = 0; } }
            if (connInc > 0) SendWindowUpdate(0, connInc);
        }

        private void OnHeaderBlock(int sid, byte flags, byte[] block)
        {
            var fields = _hpack.Decode(block, 0, block.Length);   // always decode: keeps the HPACK table in sync
            Http2Stream s;
            lock (_sync) _streams.TryGetValue(sid, out s);
            if (s == null) return;
            s.OnHeaders(fields, (flags & FlEndStream) != 0);
        }

        private void ApplySettings(byte[] p)
        {
            lock (_sync)
            {
                for (int i = 0; i < p.Length; i += 6)
                {
                    int id = (p[i] << 8) | p[i + 1];
                    uint v = GetUInt32(p, i + 2);
                    switch (id)
                    {
                        case 0x3: _peerMaxConcurrent = (int)Math.Min(v, int.MaxValue); break;   // MAX_CONCURRENT_STREAMS
                        case 0x4:                                                              // INITIAL_WINDOW_SIZE
                            if (v > 0x7FFFFFFF) throw new Http2Exception("HTTP/2: bad INITIAL_WINDOW_SIZE");
                            int delta = (int)v - _peerInitialWindow;
                            _peerInitialWindow = (int)v;
                            foreach (var s in _streams.Values) s.SendWindow += delta;
                            break;
                        case 0x5:                                                              // MAX_FRAME_SIZE
                            if (v < 16384 || v > 16777215) throw new Http2Exception("HTTP/2: bad MAX_FRAME_SIZE");
                            _peerMaxFrame = (int)v;
                            break;
                    }
                }
                PulseWindow();
            }
        }

        // Control replies (SETTINGS/PING ACK, WINDOW_UPDATE, RST_STREAM) are queued off the reader loop: the reader must never
        // wait for the write lock, or two peers both blocked on full send buffers would deadlock.
        private void SendControl(byte type, byte flags, int sid, byte[] payload)
        {
            if (_closed) return;
            Task.Run(async () =>
            {
                try
                {
                    await _writeLock.WaitAsync().ConfigureAwait(false);
                    try { await WriteFrameAsync(type, flags, sid, payload, 0, payload.Length, CancellationToken.None).ConfigureAwait(false); await _io.FlushAsync().ConfigureAwait(false); }
                    finally { _writeLock.Release(); }
                }
                catch { }
            });
        }

        // Caller holds _sync.
        private void PulseWindow()
        {
            var old = _windowChanged;
            _windowChanged = NewTcs();
            old.TrySetResult(true);
        }

        private void Shutdown(string reason)
        {
            List<Http2Stream> all;
            lock (_sync)
            {
                if (_closed) return;
                _closed = true;
                if (_closeReason == null) _closeReason = reason;
                all = new List<Http2Stream>(_streams.Values);
                _streams.Clear();
                PulseWindow();
            }
            foreach (var s in all) s.OnConnectionClosed(_closeReason);
            try { Closed?.Invoke(_closeReason); } catch { }
        }

        private async Task<bool> ReadExactAsync(byte[] b, int n)
        {
            int got = 0;
            while (got < n)
            {
                int r = await _io.ReadAsync(b, got, n - got).ConfigureAwait(false);
                if (r <= 0) { if (got == 0) return false; throw new Http2Exception("HTTP/2: connection closed mid-frame"); }
                got += r;
            }
            return true;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            try { _keepalive?.Dispose(); } catch { }
            Shutdown("closed locally");
            try { _io.Dispose(); } catch { }
        }

        // ───────────────────────── helpers ─────────────────────────

        private static TaskCompletionSource<bool> NewTcs() => new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        private static void PutUInt31(byte[] b, int o, int v)
        {
            b[o] = (byte)((v >> 24) & 0x7F); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v;
        }

        private static void PutUInt32(byte[] b, int o, uint v)
        {
            b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v;
        }

        private static uint GetUInt32(byte[] b, int o) => (uint)((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]);

        internal static string ErrorName(uint code)
        {
            switch (code)
            {
                case 0: return "NO_ERROR"; case 1: return "PROTOCOL_ERROR"; case 2: return "INTERNAL_ERROR";
                case 3: return "FLOW_CONTROL_ERROR"; case 4: return "SETTINGS_TIMEOUT"; case 5: return "STREAM_CLOSED";
                case 6: return "FRAME_SIZE_ERROR"; case 7: return "REFUSED_STREAM"; case 8: return "CANCEL";
                case 9: return "COMPRESSION_ERROR"; case 10: return "CONNECT_ERROR"; case 11: return "ENHANCE_YOUR_CALM";
                case 12: return "INADEQUATE_SECURITY"; case 13: return "HTTP_1_1_REQUIRED";
                default: return "error " + code;
            }
        }
    }

    /// <summary>
    /// One HTTP/2 request stream as a duplex Stream: Write sends request-body DATA (flow-controlled), Read returns the
    /// response body. <see cref="ResponseHeadersAsync"/> completes when the response HEADERS arrive. Dispose ends the
    /// request body (END_STREAM) if still open and cancels the stream if the response hasn't finished.
    /// </summary>
    internal sealed class Http2Stream : Stream
    {
        private readonly Http2Connection _c;
        private readonly object _sync = new object();
        private readonly Queue<byte[]> _data = new Queue<byte[]>();
        private byte[] _cur; private int _curOff;
        private TaskCompletionSource<bool> _dataSignal = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<List<HeaderField>> _headers = new TaskCompletionSource<List<HeaderField>>(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly SemaphoreSlim _writeGate = new SemaphoreSlim(1, 1);
        private bool _localEnded;
        private string _failure;
        private int _disposed;

        internal readonly int Id;
        internal long SendWindow;           // guarded by the connection's lock
        internal int RecvConsumed;          // guarded by the connection's lock
        internal volatile bool RemoteEnded;
        internal volatile bool Dead;        // failed / reset / disposed: writers must stop
        internal uint? ResetCode { get; private set; }

        internal Http2Stream(Http2Connection c, int id, int sendWindow, int recvWindow) { _c = c; Id = id; SendWindow = sendWindow; }

        /// <summary>The response HEADERS (":status" etc.). Faults if the stream or connection fails first.</summary>
        public Task<List<HeaderField>> ResponseHeadersAsync => _headers.Task;

        public static string Get(List<HeaderField> h, string name)
        {
            foreach (var f in h) if (f.Name == name) return f.Value;
            return null;
        }

        // ── called by the connection's reader loop ──
        internal void OnHeaders(List<HeaderField> fields, bool endStream)
        {
            if (!_headers.Task.IsCompleted)
            {
                string status = Get(fields, ":status");
                if (status != null && status.Length == 3 && status[0] == '1') { if (!endStream) return; }   // 1xx informational: wait for the final one
                else _headers.TrySetResult(fields);
            }
            if (endStream) OnRemoteEnd();   // trailers (or a header-only response)
        }

        internal void OnData(byte[] b, int off, int len)
        {
            var copy = new byte[len];
            Buffer.BlockCopy(b, off, copy, 0, len);
            TaskCompletionSource<bool> sig;
            lock (_sync) { _data.Enqueue(copy); sig = _dataSignal; }
            sig.TrySetResult(true);
        }

        internal void OnRemoteEnd()
        {
            _headers.TrySetException(new Http2Exception("HTTP/2: the stream ended before the response headers"));   // no-op once set
            RemoteEnded = true;
            TaskCompletionSource<bool> sig;
            lock (_sync) sig = _dataSignal;
            sig.TrySetResult(true);
            if (_localEnded) _c.Forget(this);
        }

        internal void OnReset(uint code)
        {
            ResetCode = code;
            if (code == 0) { OnRemoteEnd(); return; }   // NO_ERROR: the server is done (Go sends it after a full response)
            Fail("HTTP/2: stream reset by the server (" + Http2Connection.ErrorName(code) + ")");
        }

        internal void OnConnectionClosed(string reason) => Fail("HTTP/2: connection closed (" + reason + ")");

        private void Fail(string why)
        {
            TaskCompletionSource<bool> sig;
            lock (_sync) { if (_failure == null) _failure = why; sig = _dataSignal; }
            Dead = true;
            _headers.TrySetException(new Http2Exception(why));
            sig.TrySetResult(true);
            _c.WakeWriters();
        }

        // Unread buffered DATA of a stream that is going away.
        private int DropUnread()
        {
            lock (_sync)
            {
                int n = _cur != null ? _cur.Length - _curOff : 0;
                foreach (var b in _data) n += b.Length;
                _data.Clear(); _cur = null;
                return n;
            }
        }

        // ── Stream ──
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return 0;
            while (true)
            {
                Task wait;
                int n = 0;
                lock (_sync)
                {
                    if (_cur == null && _data.Count > 0) { _cur = _data.Dequeue(); _curOff = 0; }
                    if (_cur != null)
                    {
                        n = Math.Min(count, _cur.Length - _curOff);
                        Buffer.BlockCopy(_cur, _curOff, buffer, offset, n);
                        _curOff += n;
                        if (_curOff == _cur.Length) _cur = null;
                    }
                }
                if (n > 0) { _c.Consumed(this, n); return n; }
                lock (_sync)
                {
                    if (_cur != null || _data.Count > 0) continue;
                    if (RemoteEnded) return 0;
                    if (_failure != null) throw new Http2Exception(_failure);
                    if (_dataSignal.Task.IsCompleted) _dataSignal = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    wait = _dataSignal.Task;
                }
                if (ct.CanBeCanceled)
                {
                    var tcs = new TaskCompletionSource<bool>();
                    using (ct.Register(() => tcs.TrySetCanceled()))
                        await Task.WhenAny(wait, tcs.Task).ConfigureAwait(false);
                    ct.ThrowIfCancellationRequested();
                }
                else await wait.ConfigureAwait(false);
            }
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return;
            await _writeGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_localEnded) throw new IOException("HTTP/2: request body already ended");
                if (_failure != null) throw new Http2Exception(_failure);
                await _c.SendDataAsync(this, buffer, offset, count, false, ct).ConfigureAwait(false);
            }
            finally { _writeGate.Release(); }
        }

        /// <summary>Ends the request body (empty DATA with END_STREAM) — a half-close; the response keeps flowing.</summary>
        public async Task EndRequestAsync(CancellationToken ct)
        {
            await _writeGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (_localEnded || _failure != null) return;
                _localEnded = true;
                await _c.SendDataAsync(this, new byte[0], 0, 0, true, ct).ConfigureAwait(false);
            }
            finally { _writeGate.Release(); }
            if (RemoteEnded) _c.Forget(this);
        }

        public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
        public override void Flush() { }
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
                if (!RemoteEnded || !_localEnded) _c.ResetStream(this, 8 /* CANCEL */);
                else _c.Forget(this);
                Fail("stream disposed");
                _c.Refund(DropUnread());
            }
            base.Dispose(disposing);
        }
    }
}

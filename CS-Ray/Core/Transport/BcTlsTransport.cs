using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace CS_Ray.Core.Transport
{
    /// <summary>
    /// Managed TLS 1.3 (falls back to 1.2) transport on BouncyCastle — the drop-in alternative to
    /// <see cref="TlsTransport"/> (SslStream, TLS 1.2 only on the target OSes). Pure managed (BC 2.x net461: no
    /// P/Invoke), so it JITs to ARM32 like the rest of the engine; it's the foundation the REALITY / VLESS-encryption
    /// work builds on. Same contract as TlsTransport: SNI (falls back to the dial host), certificate validation ON
    /// unless <c>allowInsecure</c>, no ALPN offered (parity), cancellation tears the socket down.
    /// </summary>
    public sealed class BcTlsTransport : ITransport
    {
        private readonly string _sni;
        private readonly bool _allowInsecure;
        private readonly TcpTransport _tcp = new TcpTransport();
        private BcTlsStream _stream;

        public BcTlsTransport(string sni, bool allowInsecure)
        {
            _sni = sni;
            _allowInsecure = allowInsecure;
        }

        /// <summary>Negotiated protocol after connect (e.g. "TLS 1.3"), for diagnostics.</summary>
        public string NegotiatedVersion => _stream?.NegotiatedVersion;

        public async Task ConnectAsync(string host, int port, CancellationToken ct)
        {
            await _tcp.ConnectAsync(host, port, ct).ConfigureAwait(false);
            string serverName = string.IsNullOrEmpty(_sni) ? host : _sni;
            var stream = new BcTlsStream(_tcp.GetStream(), serverName, _allowInsecure);
            // Cancel = close the socket FIRST (unblocks the handshake's pending read at once); the stream's own Dispose
            // never waits on the protocol lock, so the cancelling (UI) thread can't stall behind certificate validation.
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
            if (_stream == null)
                throw new InvalidOperationException("BcTlsTransport is not connected.");
            return _stream;
        }

        public void Close()
        {
            try { _stream?.Dispose(); } catch { }
            _stream = null;
            _tcp.Close();
        }
    }

    /// <summary>
    /// A duplex Stream over BouncyCastle's NON-BLOCKING <see cref="TlsClientProtocol"/>, driven by async socket I/O —
    /// so a relay pump awaiting a read holds no thread (BC's blocking mode would park one thread-pool thread per pump;
    /// with dozens of TUN flows that starves the pool on ARM32). Every protocol call happens under one lock (the read
    /// pump's OfferInput and the write pump's WriteApplicationData run concurrently); draining protocol output to the
    /// socket is serialized by <see cref="_sendGate"/> so TLS records always leave in sequence order. Single reader at a
    /// time (the downlink pump), any number of writers.
    /// </summary>
    internal sealed class BcTlsStream : Stream
    {
        private readonly Stream _net;
        private readonly TlsClientProtocol _tls = new TlsClientProtocol();   // no stream → non-blocking mode
        private readonly CsRayTlsClient _client;
        private readonly object _sync = new object();
        private readonly SemaphoreSlim _sendGate = new SemaphoreSlim(1, 1);
        private readonly byte[] _netBuf = new byte[(1 << 14) + 2048];       // ≥ one max TLS record
        private bool _eof;
        private int _disposed;

        public BcTlsStream(Stream net, string serverName, bool allowInsecure)
        {
            _net = net;
            _client = new CsRayTlsClient(serverName, allowInsecure);
        }

        public string NegotiatedVersion => _client.NegotiatedVersion;

        public async Task HandshakeAsync(CancellationToken ct)
        {
            try
            {
                lock (_sync) _tls.Connect(_client);          // queues the ClientHello
                await FlushOutputAsync(ct).ConfigureAwait(false);
                while (true)
                {
                    lock (_sync) { if (!_tls.IsHandshaking) break; }
                    int n = await _net.ReadAsync(_netBuf, 0, _netBuf.Length, ct).ConfigureAwait(false);
                    if (n <= 0) throw new IOException("TLS: the server closed the connection during the handshake.");
                    lock (_sync) _tls.OfferInput(_netBuf, 0, n);   // runs the handshake (incl. certificate validation)
                    await FlushOutputAsync(ct).ConfigureAwait(false);
                }
            }
            catch (TlsException ex)
            {
                await TryFlushQuietlyAsync().ConfigureAwait(false);   // let a queued alert reach the server
                throw new IOException("TLS handshake failed: " + Describe(ex), ex);
            }
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return 0;
            while (true)
            {
                lock (_sync)
                {
                    int avail = _tls.GetAvailableInputBytes();
                    if (avail > 0) return _tls.ReadInput(buffer, offset, Math.Min(avail, count));
                    if (_eof || _tls.IsClosed) return 0;
                }
                int n = await _net.ReadAsync(_netBuf, 0, _netBuf.Length, ct).ConfigureAwait(false);
                if (n <= 0) { _eof = true; continue; }      // TCP EOF (with or without close_notify) → end of stream
                bool replies;
                try
                {
                    lock (_sync) { _tls.OfferInput(_netBuf, 0, n); replies = _tls.GetAvailableOutputBytes() > 0; }
                }
                catch (TlsException ex)
                {
                    await TryFlushQuietlyAsync().ConfigureAwait(false);
                    throw new IOException("TLS: " + Describe(ex), ex);
                }
                // Post-handshake replies (KeyUpdate, close_notify) are flushed in the BACKGROUND: the reader must never
                // wait on the send gate — a writer can hold it while blocked on a full socket buffer that only drains
                // once the peer's echo is read by us (full-duplex deadlock).
                if (replies) KickFlush();
            }
        }

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        {
            if (count <= 0) return;
            try
            {
                lock (_sync) _tls.WriteApplicationData(buffer, offset, count);   // encrypts into ≤ 2^14-byte records
            }
            catch (TlsException ex) { throw new IOException("TLS: " + Describe(ex), ex); }
            await FlushOutputAsync(ct).ConfigureAwait(false);
        }

        public override Task FlushAsync(CancellationToken ct) => _net.FlushAsync(ct);

        // Move every queued TLS byte to the socket, in order. Holding the gate across extract+write keeps records from
        // two threads from interleaving out of sequence. Output queued by another thread after our last check but before
        // we release is caught by the re-check after release (we go round again) — nothing is ever stranded.
        private async Task FlushOutputAsync(CancellationToken ct)
        {
            while (true)
            {
                await _sendGate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    while (true)
                    {
                        byte[] chunk;
                        lock (_sync)
                        {
                            int n = _tls.GetAvailableOutputBytes();
                            if (n <= 0) break;
                            chunk = new byte[n];
                            _tls.ReadOutput(chunk, 0, n);
                        }
                        await _net.WriteAsync(chunk, 0, chunk.Length, ct).ConfigureAwait(false);
                    }
                }
                finally { _sendGate.Release(); }
                lock (_sync) { if (_tls.GetAvailableOutputBytes() <= 0) return; }
            }
        }

        // Fire-and-forget flush for the read path; errors surface on the next read/write instead.
        private void KickFlush()
        {
            Task.Run(async () =>
            {
                try { await FlushOutputAsync(CancellationToken.None).ConfigureAwait(false); } catch { }
            });
        }

        private async Task TryFlushQuietlyAsync()
        {
            try
            {
                using (var cts = new CancellationTokenSource(2000)) await FlushOutputAsync(cts.Token).ConfigureAwait(false);
            }
            catch { }
        }

        private static string Describe(TlsException ex)
        {
            var alert = ex as TlsFatalAlert;
            string name = alert != null ? AlertDescription.GetText(alert.AlertDescription) : null;
            return string.IsNullOrEmpty(ex.Message) || (name != null && ex.Message == name) ? (name ?? ex.GetType().Name) : ex.Message;
        }

        // ── sync API (consumers use the async one; kept correct for completeness) ──
        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
        public override void Flush() => _net.Flush();

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            if (disposing)
            {
                // Teardown NEVER waits: not on the protocol lock (a handshake may hold it through certificate chain
                // building), not on the peer (a stalled peer would block a synchronous send forever). close_notify is
                // best-effort: queued only if the lock is free, sent as a fire-and-forget async write — data the OS
                // accepted still goes out before the FIN on the graceful close; a stalled send is simply dropped.
                byte[] chunk = null;
                if (Monitor.TryEnter(_sync))
                {
                    try
                    {
                        if (!_tls.IsClosed) _tls.Close();
                        int n = _tls.GetAvailableOutputBytes();
                        if (n > 0) { chunk = new byte[n]; _tls.ReadOutput(chunk, 0, n); }
                    }
                    catch { }
                    finally { Monitor.Exit(_sync); }
                }
                if (chunk != null && _sendGate.Wait(0))
                {
                    try { _net.WriteAsync(chunk, 0, chunk.Length).ContinueWith(t => { var _ = t.Exception; }, TaskScheduler.Default); }
                    catch { }
                    finally { _sendGate.Release(); }
                }
                try { _net.Dispose(); } catch { }
            }
            base.Dispose(disposing);
        }
    }

    /// <summary>The BouncyCastle client: TLS 1.3 → 1.2, BC's default suites/groups (AES-GCM / ChaCha20-Poly1305,
    /// X25519 / P-256 / P-384), SNI = the server name (not for IP literals, per RFC 6066), no ALPN, Windows-trust
    /// certificate validation via <see cref="TlsCertificateValidator"/>.</summary>
    internal sealed class CsRayTlsClient : DefaultTlsClient
    {
        private readonly string _serverName;
        private readonly bool _allowInsecure;

        public CsRayTlsClient(string serverName, bool allowInsecure) : base(new BcTlsCrypto(new SecureRandom()))
        {
            _serverName = serverName ?? "";
            _allowInsecure = allowInsecure;
        }

        public string NegotiatedVersion { get; private set; }

        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv13.DownTo(ProtocolVersion.TLSv12);

        protected override IList<ServerName> GetSniServerNames()
        {
            IPAddress ip;
            if (string.IsNullOrEmpty(_serverName) || IPAddress.TryParse(_serverName.Trim('[', ']'), out ip)) return null;
            string ascii;
            try { ascii = new IdnMapping().GetAscii(_serverName.TrimEnd('.')); } catch { ascii = _serverName; }
            return new List<ServerName> { new ServerName(NameType.host_name, Encoding.ASCII.GetBytes(ascii)) };
        }

        public override TlsAuthentication GetAuthentication() => new ServerCertCheck(_serverName, _allowInsecure);

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();
            var v = m_context?.ServerVersion;
            NegotiatedVersion = v == null ? null : v.Equals(ProtocolVersion.TLSv13) ? "TLS 1.3" : v.Equals(ProtocolVersion.TLSv12) ? "TLS 1.2" : v.ToString();
        }

        private sealed class ServerCertCheck : TlsAuthentication
        {
            private readonly string _host;
            private readonly bool _allowInsecure;

            public ServerCertCheck(string host, bool allowInsecure) { _host = host; _allowInsecure = allowInsecure; }

            public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                var chain = serverCertificate?.Certificate;
                if (chain == null || chain.IsEmpty) throw new TlsFatalAlert(AlertDescription.bad_certificate, "server sent no certificate");
                if (_allowInsecure) return;   // explicit opt-out only (same rule as TlsTransport)

                byte[] leaf = chain.GetCertificateAt(0).GetEncoded();
                var intermediates = new List<byte[]>();
                for (int i = 1; i < chain.Length; i++) intermediates.Add(chain.GetCertificateAt(i).GetEncoded());

                string error = TlsCertificateValidator.Validate(leaf, intermediates, _host);
                if (error != null) throw new TlsFatalAlert(AlertDescription.certificate_unknown, error);
            }

            public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest) => null;   // no client auth
        }
    }
}

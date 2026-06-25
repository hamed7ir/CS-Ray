using System;
using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CS_Ray.Core.Protocol;
using CS_Ray.Core.Protocol.Vmess;
using CS_Ray.Core.Transport;

namespace CS_Ray.Core
{
    /// <summary>Outcome of one real-delay test. Always terminal: Ok+ms, or !Ok with "timeout"/"dead".</summary>
    public sealed class DelayResult
    {
        public bool Ok;
        public int ConnectMs;   // time to establish the proxied outbound transport (secondary)
        public int TotalMs;     // start → first response byte through the full chain (the "real delay")
        public string Error;    // "timeout" / "dead" / message when !Ok
    }

    /// <summary>
    /// Standalone "real delay" tester — round-trip of a real request THROUGH a server's full outbound chain
    /// (transport → protocol → exit → target → back), like v2rayN. Builds a THROWAWAY outbound (same classes
    /// the engine uses, never the running engine), dials cfg.ServerHost:Port directly, then issues a minimal
    /// HTTP(S) GET to a configurable target (default cp.cloudflare.com/204 — but ISPs may filter it, so the
    /// user can set their own reachable URL). Supports http and https targets.
    ///
    /// net47 note: TcpClient.ConnectAsync ignores the token, so we DON'T rely on cancellation — every phase is
    /// raced against Task.Delay and on timeout we FORCE-CLOSE the socket (Close() disposes it, faulting the
    /// stuck op). Raw-TCP reachability gate ≤3s (dead fast); whole test ≤10s (high-RTT chains safe).
    /// </summary>
    public static class DelayTester
    {
        public const string DefaultUrl = "http://cp.cloudflare.com/generate_204";
        private const int ConnectTimeoutMs = 3000;  // raw-TCP reachability gate (dead host fails fast)
        private const int TotalTimeoutMs = 10000;   // whole path: gate + TCP + TLS + proxied round-trip

        private sealed class Holder
        {
            public ITransport Outbound;
            public void CloseQuiet() { try { Outbound?.Close(); } catch { } }
        }

        public static async Task<DelayResult> TestAsync(VlessConfig cfg, string targetUrl, CancellationToken outerCt)
        {
            if (cfg == null || string.IsNullOrWhiteSpace(cfg.ServerHost))
                return new DelayResult { Ok = false, Error = "dead" };

            // Parse the target URL (fall back to the default on anything malformed).
            if (!Uri.TryCreate((targetUrl ?? "").Trim(), UriKind.Absolute, out var uri) ||
                (uri.Scheme != "http" && uri.Scheme != "https"))
                Uri.TryCreate(DefaultUrl, UriKind.Absolute, out uri);
            string tHost = uri.Host;
            int tPort = uri.Port; // Uri fills the scheme default (80/443)
            string tPath = string.IsNullOrEmpty(uri.PathAndQuery) ? "/" : uri.PathAndQuery;
            bool tHttps = uri.Scheme == "https";

            var holder = new Holder();
            var test = RunOnceAsync(cfg, tHost, tPort, tPath, tHttps, holder);
            var winner = await Task.WhenAny(test, Task.Delay(TotalTimeoutMs, outerCt)).ConfigureAwait(false);
            if (winner != test)
            {
                holder.CloseQuiet();   // abandon: force-close so any stuck connect/handshake/read unblocks
                Observe(test);
                return new DelayResult { Ok = false, Error = "timeout" };
            }
            return await test.ConfigureAwait(false);
        }

        private static async Task<DelayResult> RunOnceAsync(VlessConfig cfg, string tHost, int tPort, string tPath, bool tHttps, Holder holder)
        {
            var r = new DelayResult();
            var sw = Stopwatch.StartNew();
            try
            {
                string proto = (cfg.Protocol ?? "vless").Trim().ToLowerInvariant();
                Stream tunnel; // clean bidirectional tunnel to tHost:tPort through the proxy

                if (proto == "shadowsocks")
                {
                    var spec = ShadowsocksProtocol.GetSpec(cfg.SsMethod);
                    var key = ShadowsocksProtocol.EvpBytesToKey(cfg.SsPassword, spec.KeyLength);
                    var tcp = new TcpTransport(); holder.Outbound = tcp;
                    await ConnectBudgeted(tcp, cfg.ServerHost, cfg.ServerPort, holder).ConfigureAwait(false);
                    r.ConnectMs = (int)sw.ElapsedMilliseconds;
                    tunnel = new ShadowsocksStream(tcp.GetStream(), key, spec, ShadowsocksProtocol.BuildAddressHeader(tHost, tPort));
                }
                else if (proto == "vmess")
                {
                    var uuid = VlessProtocol.ParseUuid(cfg.VmessId);
                    var tcp = new TcpTransport(); holder.Outbound = tcp;
                    await ConnectBudgeted(tcp, cfg.ServerHost, cfg.ServerPort, holder).ConfigureAwait(false);
                    r.ConnectMs = (int)sw.ElapsedMilliseconds;
                    tunnel = await VmessProtocol.EstablishAsync(
                        tcp.GetStream(), uuid, tHost, tPort, VmessRequest.CommandTcp, null, CancellationToken.None).ConfigureAwait(false);
                }
                else if (proto == "socks" || proto == "http" || proto == "https")
                {
                    bool https = proto == "https";
                    ITransport o = https
                        ? (ITransport)new TlsTransport(string.IsNullOrEmpty(cfg.Sni) ? cfg.ServerHost : cfg.Sni, cfg.AllowInsecure)
                        : new TcpTransport();
                    holder.Outbound = o;
                    await ConnectBudgeted(o, cfg.ServerHost, cfg.ServerPort, holder).ConfigureAwait(false);
                    r.ConnectMs = (int)sw.ElapsedMilliseconds;
                    var st = o.GetStream();
                    if (proto == "socks")
                        await SocksClient.HandshakeAsync(st, tHost, tPort, cfg.ProxyUser, cfg.ProxyPass, CancellationToken.None).ConfigureAwait(false);
                    else
                        await HttpConnectClient.ConnectAsync(st, tHost, tPort, cfg.ProxyUser, cfg.ProxyPass, CancellationToken.None).ConfigureAwait(false);
                    tunnel = st;
                }
                else // vless
                {
                    var uuid = VlessProtocol.ParseUuid(cfg.Uuid);
                    await TcpReachableGate(cfg.ServerHost, cfg.ServerPort).ConfigureAwait(false); // raw-TCP liveness (≤3s)
                    sw.Restart(); // time the real chain, not the throwaway probe

                    string netName = (cfg.Network ?? "").Trim().ToLowerInvariant();
                    bool xhttp = netName == "xhttp" || netName == "splithttp";
                    bool ws = netName == "ws";
                    string hostHdr = !string.IsNullOrEmpty(cfg.WsHost) ? cfg.WsHost
                        : (!string.IsNullOrEmpty(cfg.Sni) ? cfg.Sni : cfg.ServerHost);
                    ITransport o;
                    if (xhttp) o = new XhttpTransport(cfg.Sni, cfg.AllowInsecure, cfg.WsPath, hostHdr);
                    else { o = new TlsTransport(cfg.Sni, cfg.AllowInsecure); if (ws) o = new WebSocketTransport(o, cfg.WsPath, hostHdr); }
                    holder.Outbound = o;
                    await o.ConnectAsync(cfg.ServerHost, cfg.ServerPort, CancellationToken.None).ConfigureAwait(false);
                    r.ConnectMs = (int)sw.ElapsedMilliseconds;
                    var header = VlessProtocol.BuildRequestHeader(uuid, tHost, tPort);
                    await o.GetStream().WriteAsync(header, 0, header.Length, CancellationToken.None).ConfigureAwait(false);
                    tunnel = new VlessStripStream(o.GetStream()); // strips the VLESS response header on first read
                }

                // For an https target, do TLS to the target THROUGH the tunnel (cert not validated — we only
                // measure RTT, not the target's identity).
                Stream app = tunnel;
                if (tHttps)
                {
                    var ssl = new SslStream(tunnel, false, (s, c, ch, e) => true);
                    await ssl.AuthenticateAsClientAsync(tHost, null, SslProtocols.Tls12, false).ConfigureAwait(false);
                    app = ssl;
                }

                var req = Encoding.ASCII.GetBytes(
                    "GET " + tPath + " HTTP/1.1\r\nHost: " + tHost +
                    "\r\nUser-Agent: CS-Ray\r\nAccept: */*\r\nConnection: close\r\n\r\n");
                await app.WriteAsync(req, 0, req.Length, CancellationToken.None).ConfigureAwait(false);
                await app.FlushAsync(CancellationToken.None).ConfigureAwait(false);

                var buf = new byte[256];
                int n = await app.ReadAsync(buf, 0, buf.Length, CancellationToken.None).ConfigureAwait(false);
                r.TotalMs = (int)sw.ElapsedMilliseconds;
                if (n <= 0) { r.Ok = false; r.Error = "dead"; return r; }

                r.Ok = true;
                return r;
            }
            catch (Exception ex) { r.Ok = false; r.Error = Classify(ex); return r; }
            finally { holder.CloseQuiet(); }
        }

        // Connect with a hard budget that does NOT depend on token cancellation.
        private static async Task ConnectBudgeted(ITransport o, string host, int port, Holder holder)
        {
            var connect = o.ConnectAsync(host, port, CancellationToken.None);
            if (await Task.WhenAny(connect, Task.Delay(ConnectTimeoutMs)).ConfigureAwait(false) != connect)
            {
                holder.CloseQuiet();
                Observe(connect);
                throw new TimeoutException("connect timeout");
            }
            await connect.ConfigureAwait(false); // surface a real connect error (refused, DNS, …)
        }

        // Throwaway raw-TCP reachability probe — bounds ONLY TCP establishment (dead host fails in ≤3s) without
        // timing out a live server's slower TLS handshake.
        private static async Task TcpReachableGate(string host, int port)
        {
            var probe = new TcpTransport();
            var h = new Holder { Outbound = probe };
            try { await ConnectBudgeted(probe, host, port, h).ConfigureAwait(false); }
            finally { h.CloseQuiet(); }
        }

        private static string Classify(Exception ex)
        {
            while (ex is AggregateException ae && ae.InnerException != null) ex = ae.InnerException;
            if (ex is TimeoutException || ex is OperationCanceledException) return "timeout";
            return "dead";
        }

        private static void Observe(Task t)
        {
            t.ContinueWith(x => { var _ = x.Exception; },
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
        }

        // Wraps a VLESS server stream and strips the response header (1 ver + 1 addonLen + addons) on the first
        // read, so the remainder is a clean tunnel to the target (usable directly or under an SslStream).
        private sealed class VlessStripStream : Stream
        {
            private readonly Stream _inner;
            private bool _stripped;
            public VlessStripStream(Stream inner) { _inner = inner; }

            public override bool CanRead => true;
            public override bool CanWrite => true;
            public override bool CanSeek => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
            public override void SetLength(long v) => throw new NotSupportedException();
            public override void Flush() => _inner.Flush();
            public override Task FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);
            public override void Write(byte[] b, int o, int c) => _inner.Write(b, o, c);
            public override Task WriteAsync(byte[] b, int o, int c, CancellationToken ct) => _inner.WriteAsync(b, o, c, ct);
            public override int Read(byte[] b, int o, int c) => ReadAsync(b, o, c, CancellationToken.None).GetAwaiter().GetResult();

            public override async Task<int> ReadAsync(byte[] b, int o, int c, CancellationToken ct)
            {
                if (!_stripped)
                {
                    var head = await ReadExact(2, ct).ConfigureAwait(false);
                    int addon = head[1];
                    if (addon > 0) await ReadExact(addon, ct).ConfigureAwait(false);
                    _stripped = true;
                }
                return await _inner.ReadAsync(b, o, c, ct).ConfigureAwait(false);
            }

            private async Task<byte[]> ReadExact(int n, CancellationToken ct)
            {
                var buf = new byte[n]; int off = 0;
                while (off < n)
                {
                    int r = await _inner.ReadAsync(buf, off, n - off, ct).ConfigureAwait(false);
                    if (r <= 0) throw new IOException("VLESS response header truncated.");
                    off += r;
                }
                return buf;
            }
        }
    }
}

using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using CS_Ray.Core.Inbound;
using CS_Ray.Core.Protocol;
using CS_Ray.Core.Transport;

namespace CS_Ray.Core
{
    /// <summary>Configuration for a single proxy outbound (VLESS, Shadowsocks, or VMess).</summary>
    public class VlessConfig
    {
        public string Protocol = "vless"; // "vless" | "shadowsocks" | "vmess"

        public string ServerHost;     // address to dial the server (hostname or IP)
        public int ServerPort;

        /// <summary>Pre-resolved server IPv4 to DIAL (set at full-tunnel start, reusing the loop-guard's resolution).
        /// When set, transports connect to this IP while SNI/WS-Host stay ServerHost — so there is zero per-connection
        /// DNS for the server (loop-proof under a physical-DNS override). Null/empty = dial ServerHost (today's path).</summary>
        public string ServerIp;

        // VLESS
        public string Uuid;           // VLESS user id
        public string Sni;            // TLS server name (defaults to ServerHost if empty)
        public bool AllowInsecure;    // skip certificate validation when true
        public string Network = "tcp"; // "tcp" (VLESS straight over TLS) or "ws" (VLESS over WebSocket-over-TLS)
        public string WsPath = "/";    // WebSocket request path (network=ws)
        public string WsHost;          // WebSocket Host header (network=ws); defaults to Sni ?? ServerHost

        // Shadowsocks (AEAD over raw TCP, no TLS)
        public string SsMethod = "chacha20-ietf-poly1305";
        public string SsPassword;

        // VMess (AEAD, alterId=0, over raw TCP for this test)
        public string VmessId;            // VMess user UUID
        public string VmessSecurity = "auto"; // "auto" → AES-128-GCM body

        // SOCKS5 / HTTP(S) outbound proxy (Protocol = "socks" | "http" | "https"); optional auth.
        public string ProxyUser;
        public string ProxyPass;

        // Local SOCKS5 inbound
        public string ListenAddress = "127.0.0.1";
        public int ListenPort = 10810;
    }

    /// <summary>
    /// Wires the local SOCKS5 inbound to a VLESS-over-TLS outbound: for each accepted
    /// CONNECT it dials the server over TLS, sends the VLESS request header for the
    /// requested target, then relays bytes both directions.
    /// </summary>
    public class ProxyEngine
    {
        private readonly VlessConfig _config;
        private readonly string _protocol;

        // VLESS
        private readonly byte[] _uuid;
        // Shadowsocks
        private readonly ShadowsocksProtocol.AeadCipherSpec _ssSpec;
        private readonly byte[] _ssMasterKey;
        // VMess
        private readonly byte[] _vmessUuid;

        private MixedInbound _inbound;
        private CancellationTokenSource _cts;

        public event Action<string> Log;

        /// <summary>When false (default), suppress per-connection logging (high-frequency under load).</summary>
        public bool Verbose;

        public ProxyEngine(VlessConfig config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _protocol = (config.Protocol ?? "vless").Trim().ToLowerInvariant();

            switch (_protocol)
            {
                case "shadowsocks":
                    _ssSpec = ShadowsocksProtocol.GetSpec(config.SsMethod);                    // validates method early
                    _ssMasterKey = ShadowsocksProtocol.EvpBytesToKey(config.SsPassword, _ssSpec.KeyLength);
                    break;
                case "vmess":
                    _vmessUuid = VlessProtocol.ParseUuid(config.VmessId);                      // validates UUID early
                    break;
                case "socks":
                case "http":
                case "https":
                    break;                                                                    // plain proxies — no keys
                default:
                    _protocol = "vless";
                    _uuid = VlessProtocol.ParseUuid(config.Uuid);                              // validates UUID early
                    break;
            }
        }

        public void Start()
        {
            _cts = new CancellationTokenSource();

            var addr = IPAddress.Parse(_config.ListenAddress);
            _inbound = new MixedInbound(addr, _config.ListenPort) { Verbose = Verbose };
            _inbound.Log += s => Log?.Invoke(s);
            _inbound.ConnectRequested += HandleConnectAsync;
            _inbound.Start();

            Log?.Invoke("Engine started. Mixed SOCKS5+HTTP listening on " + _config.ListenAddress + ":" + _config.ListenPort);
            if (_protocol == "shadowsocks")
                Log?.Invoke("Outbound: Shadowsocks (" + _config.SsMethod + ") over raw TCP to " +
                            _config.ServerHost + ":" + _config.ServerPort);
            else if (_protocol == "vmess")
                Log?.Invoke("Outbound: VMess (AEAD, security=" + _config.VmessSecurity + ") over raw TCP to " +
                            _config.ServerHost + ":" + _config.ServerPort);
            else if (_protocol == "socks" || _protocol == "http" || _protocol == "https")
                Log?.Invoke("Outbound: " + _protocol.ToUpperInvariant() + " proxy to " + _config.ServerHost + ":" + _config.ServerPort +
                            (string.IsNullOrEmpty(_config.ProxyUser) ? "" : " (auth)") +
                            " — TCP-carry only (DNS via engine; non-DNS UDP → TCP fallback).");
            else
                Log?.Invoke("Outbound: VLESS network=" + (IsXhttp ? "xhttp(packet-up)" : IsWebSocket ? "ws" : "tcp") + "+TLS to " +
                            _config.ServerHost + ":" + _config.ServerPort +
                            " (SNI=" + (string.IsNullOrEmpty(_config.Sni) ? _config.ServerHost : _config.Sni) +
                            ", allowInsecure=" + _config.AllowInsecure +
                            ((IsWebSocket || IsXhttp) ? ", path=" + _config.WsPath + ", host=" + WsHostHeader : "") + ")");
        }

        public void Stop()
        {
            try { _cts?.Cancel(); } catch { }
            try { _inbound?.Stop(); } catch { }
            _inbound = null;
            Log?.Invoke("Engine stopped.");
        }

        private bool IsWebSocket =>
            string.Equals(_config.Network?.Trim(), "ws", StringComparison.OrdinalIgnoreCase);

        private bool IsXhttp
        {
            get
            {
                var n = _config.Network?.Trim();
                return string.Equals(n, "xhttp", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(n, "splithttp", StringComparison.OrdinalIgnoreCase);
            }
        }

        private string WsHostHeader =>
            !string.IsNullOrEmpty(_config.WsHost) ? _config.WsHost
            : (!string.IsNullOrEmpty(_config.Sni) ? _config.Sni : _config.ServerHost);

        // Host to DIAL the server: the pre-resolved IP when pinned (full tunnel), else the hostname (today's path).
        // SNI / WS-Host always stay the hostname, so TLS cert validation is unaffected.
        private string DialHost =>
            !string.IsNullOrEmpty(_config.ServerIp) ? _config.ServerIp : _config.ServerHost;

        private Task HandleConnectAsync(InboundConnection conn)
        {
            switch (_protocol)
            {
                case "shadowsocks": return HandleShadowsocksAsync(conn);
                case "vmess": return HandleVmessAsync(conn);
                case "socks": return HandleSocksAsync(conn);
                case "http":
                case "https": return HandleHttpAsync(conn);
                default: return HandleVlessAsync(conn);
            }
        }

        private async Task HandleVlessAsync(InboundConnection conn)
        {
            var ct = _cts.Token;

            // Outbound chain: XHTTP manages its own TLS (two connections), so it is NOT wrapped over a shared
            // TlsTransport; tcp/ws use TCP→TLS (+WebSocket on top when network=ws).
            ITransport outbound;
            if (IsXhttp)
                outbound = new XhttpTransport(_config.Sni, _config.AllowInsecure, _config.WsPath, WsHostHeader, Verbose ? Log : null);
            else
            {
                outbound = new TlsTransport(_config.Sni, _config.AllowInsecure);
                if (IsWebSocket)
                    outbound = new WebSocketTransport(outbound, _config.WsPath, WsHostHeader);
            }

            try
            {
                await outbound.ConnectAsync(DialHost, _config.ServerPort, ct).ConfigureAwait(false);
                var server = outbound.GetStream();

                var header = VlessProtocol.BuildRequestHeader(_uuid, conn.TargetHost, conn.TargetPort);
                await server.WriteAsync(header, 0, header.Length, ct).ConfigureAwait(false);
                await server.FlushAsync(ct).ConfigureAwait(false);

                await StreamRelay.RelayAsync(
                    conn.Stream,
                    server,
                    onClose: () =>
                    {
                        outbound.Close();
                        try { conn.Client.Close(); } catch { }
                    },
                    ct: ct,
                    serverPreamble: c => VlessProtocol.ConsumeResponseHeaderAsync(server, c)).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log?.Invoke("Relay error for " + conn.TargetHost + ":" + conn.TargetPort + " — " + ex.Message);
                outbound.Close();
                try { conn.Client.Close(); } catch { }
            }
        }

        private async Task HandleShadowsocksAsync(InboundConnection conn)
        {
            var ct = _cts.Token;

            // Shadowsocks AEAD runs over raw TCP (no TLS); the SS stream layers crypto on top.
            ITransport outbound = new TcpTransport();
            try
            {
                await outbound.ConnectAsync(DialHost, _config.ServerPort, ct).ConfigureAwait(false);

                var header = ShadowsocksProtocol.BuildAddressHeader(conn.TargetHost, conn.TargetPort);
                var server = new ShadowsocksStream(outbound.GetStream(), _ssMasterKey, _ssSpec, header);

                // No protocol-level response header to strip — the SS stream consumes its salt itself.
                await StreamRelay.RelayAsync(
                    conn.Stream,
                    server,
                    onClose: () =>
                    {
                        outbound.Close();
                        try { conn.Client.Close(); } catch { }
                    },
                    ct: ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log?.Invoke("Relay error for " + conn.TargetHost + ":" + conn.TargetPort + " — " + ex.Message);
                outbound.Close();
                try { conn.Client.Close(); } catch { }
            }
        }

        // SOCKS5 outbound: connect to the proxy (plain TCP), do the SOCKS5 CONNECT handshake, then relay raw.
        private async Task HandleSocksAsync(InboundConnection conn)
        {
            var ct = _cts.Token;
            ITransport outbound = new TcpTransport();
            try
            {
                await outbound.ConnectAsync(DialHost, _config.ServerPort, ct).ConfigureAwait(false);
                var server = outbound.GetStream();
                await SocksClient.HandshakeAsync(server, conn.TargetHost, conn.TargetPort, _config.ProxyUser, _config.ProxyPass, ct).ConfigureAwait(false);
                await StreamRelay.RelayAsync(conn.Stream, server,
                    onClose: () => { outbound.Close(); try { conn.Client.Close(); } catch { } }, ct: ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log?.Invoke("Relay error for " + conn.TargetHost + ":" + conn.TargetPort + " — " + ex.Message);
                outbound.Close();
                try { conn.Client.Close(); } catch { }
            }
        }

        // HTTP(S) outbound: connect to the proxy (TLS when https), issue HTTP CONNECT, then relay raw.
        private async Task HandleHttpAsync(InboundConnection conn)
        {
            var ct = _cts.Token;
            bool https = _protocol == "https";
            ITransport outbound = https
                ? (ITransport)new TlsTransport(string.IsNullOrEmpty(_config.Sni) ? _config.ServerHost : _config.Sni, _config.AllowInsecure)
                : new TcpTransport();
            try
            {
                await outbound.ConnectAsync(DialHost, _config.ServerPort, ct).ConfigureAwait(false);
                var server = outbound.GetStream();
                await HttpConnectClient.ConnectAsync(server, conn.TargetHost, conn.TargetPort, _config.ProxyUser, _config.ProxyPass, ct).ConfigureAwait(false);
                await StreamRelay.RelayAsync(conn.Stream, server,
                    onClose: () => { outbound.Close(); try { conn.Client.Close(); } catch { } }, ct: ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log?.Invoke("Relay error for " + conn.TargetHost + ":" + conn.TargetPort + " — " + ex.Message);
                outbound.Close();
                try { conn.Client.Close(); } catch { }
            }
        }

        private async Task HandleVmessAsync(InboundConnection conn)
        {
            var ct = _cts.Token;

            // VMess AEAD over raw TCP (no TLS for this test); the VMess streams layer crypto on top.
            ITransport outbound = new TcpTransport();
            try
            {
                await outbound.ConnectAsync(DialHost, _config.ServerPort, ct).ConfigureAwait(false);

                Action<string> vlog = Verbose ? (Action<string>)(s => Log?.Invoke(s)) : null;
                var server = await Protocol.Vmess.VmessProtocol.EstablishAsync(
                    outbound.GetStream(), _vmessUuid, conn.TargetHost, conn.TargetPort,
                    Protocol.Vmess.VmessRequest.CommandTcp, vlog, ct).ConfigureAwait(false);

                // The VMess body stream verifies the AEAD response header on its first read — no preamble here.
                await StreamRelay.RelayAsync(
                    conn.Stream,
                    server,
                    onClose: () =>
                    {
                        outbound.Close();
                        try { conn.Client.Close(); } catch { }
                    },
                    ct: ct,
                    onError: s => Log?.Invoke("VMess relay [" + conn.TargetHost + ":" + conn.TargetPort + "] " + s)).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Log?.Invoke("Relay error for " + conn.TargetHost + ":" + conn.TargetPort + " — " + ex.Message);
                outbound.Close();
                try { conn.Client.Close(); } catch { }
            }
        }
    }
}

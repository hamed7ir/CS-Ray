using System;

namespace CS_Ray.Core.Transport
{
    /// <summary>Which TLS implementation outbound "security=tls" connections use.</summary>
    public enum TlsEngine
    {
        /// <summary>.NET SslStream (SChannel) — TLS 1.2 on the target OSes. The default.</summary>
        SslStream,
        /// <summary>Managed BouncyCastle client (<see cref="BcTlsTransport"/>) — TLS 1.3 with 1.2 fallback. Experimental.</summary>
        BouncyCastle
    }

    /// <summary>
    /// Single construction point for TLS transports (engine, XHTTP up/downlinks, delay test, VLESS UDP), so the
    /// engine choice is one switch. Read at connect time: changing it affects NEW connections only.
    /// </summary>
    public static class TlsTransportFactory
    {
        private static volatile TlsEngine _engine = TlsEngine.SslStream;

        public static TlsEngine Engine { get { return _engine; } set { _engine = value; } }

        public static ITransport Create(string sni, bool allowInsecure)
            => _engine == TlsEngine.BouncyCastle
                ? (ITransport)new BcTlsTransport(sni, allowInsecure)
                : new TlsTransport(sni, allowInsecure);

        /// <summary>The security layer a VLESS tcp/ws outbound sits on: REALITY, TLS (security=tls) or plain TCP
        /// (security=none). One place, so the engine, delay test and UDP sessions can't disagree. XTLS Vision over plain
        /// TLS also needs our own TLS 1.3 client (it switches the outer record layer off mid-stream), whatever the engine
        /// setting says.</summary>
        public static ITransport CreateVlessSecurity(VlessConfig c)
            => c.Reality != null ? new Tls13.Tls13Transport(c.Reality)
             : c.UseTls && c.IsVision ? new Tls13.Tls13Transport(SniOrHost(c), c.Fingerprint, null, c.AllowInsecure)
             : c.UseTls ? Create(SniOrHost(c), c.AllowInsecure)
             : (ITransport)new TcpTransport();

        /// <summary>
        /// The whole VLESS / VMess outbound chain for a config — the one place the engine, the delay tester and the UDP
        /// sessions build it: XHTTP (stream-one over HTTP/2 + REALITY, else packet-up over TLS), or the security layer
        /// (REALITY / TLS / none) with optional WebSocket or tcp http-header camouflage. VMess only ever reaches the
        /// tcp / ws + TLS-or-none part (the link parser tags REALITY / Vision / XHTTP VMess as unsupported).
        /// </summary>
        /// <param name="pooled">XHTTP stream-one: share h2 connections (XMUX). False for a private connection (delay test).</param>
        public static ITransport CreateVlessOutbound(VlessConfig c, bool pooled, Action<string> log = null)
        {
            string net = (c.Network ?? "").Trim().ToLowerInvariant();
            string hostHeader = HostHeaderFor(c);
            if (net == "xhttp" || net == "splithttp")
            {
                if (c.Reality != null)
                {
                    var rc = c.Reality;
                    string key = "xhttp|" + Convert.ToBase64String(rc.PublicKey ?? new byte[0]) + "|" + BitConverter.ToString(rc.ShortId ?? new byte[0])
                               + "|" + rc.ServerName + "|" + rc.Fingerprint;
                    return new Http2.XhttpStreamOneTransport(Http2.XhttpSettings.From(hostHeader, c.WsPath, c.XhttpExtra),
                                                             () => new Tls13.Tls13Transport(rc), key, pooled);
                }
                return new XhttpTransport(SniOrHost(c), c.AllowInsecure, Http2.XhttpSettings.From(hostHeader, c.WsPath, c.XhttpExtra), log);
            }
            ITransport o = CreateVlessSecurity(c);
            if (net == "ws") return new WebSocketTransport(o, c.WsPath, hostHeader);
            if (string.Equals(c.HeaderType, "http", StringComparison.OrdinalIgnoreCase)) return new HttpHeaderTransport(o, c.WsHost, c.WsPath);
            return o;
        }

        /// <summary>The ws / xhttp Host header (Xray websocket/dialer.go): the configured host, else the TLS server name when
        /// TLS is on, else the server address (an IPv6 literal bracketed, never a port). A leftover SNI on a security=none
        /// profile is not used.</summary>
        public static string HostHeaderFor(VlessConfig c)
        {
            if (!string.IsNullOrEmpty(c.WsHost)) return c.WsHost;
            string net = (c.Network ?? "").Trim().ToLowerInvariant();
            bool tls = c.UseTls || c.Reality != null || net == "xhttp" || net == "splithttp";   // xhttp always runs over TLS
            if (tls) return SniOrHost(c);
            string h = c.ServerHost ?? "";
            return h.IndexOf(':') >= 0 && !h.StartsWith("[") ? "[" + h + "]" : h;
        }

        /// <summary>The TLS server name for a config: its SNI, else the server HOSTNAME — never the dial address, which
        /// is a pinned IP in full-tunnel mode (that would send no SNI and validate the certificate against an IP).</summary>
        public static string SniOrHost(VlessConfig c) => string.IsNullOrEmpty(c.Sni) ? c.ServerHost : c.Sni;
    }
}

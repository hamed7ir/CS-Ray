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

        /// <summary>The TLS server name for a config: its SNI, else the server HOSTNAME — never the dial address, which
        /// is a pinned IP in full-tunnel mode (that would send no SNI and validate the certificate against an IP).</summary>
        public static string SniOrHost(VlessConfig c) => string.IsNullOrEmpty(c.Sni) ? c.ServerHost : c.Sni;
    }
}

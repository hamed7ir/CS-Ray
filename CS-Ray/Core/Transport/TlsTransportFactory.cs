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
        /// (security=none). One place, so the engine, delay test and UDP sessions can't disagree.</summary>
        public static ITransport CreateVlessSecurity(VlessConfig c)
            => c.Reality != null ? new Tls13.Tls13Transport(c.Reality)
             : c.UseTls ? Create(c.Sni, c.AllowInsecure)
             : (ITransport)new TcpTransport();
    }
}

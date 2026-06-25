using System;
using System.IO;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Transport
{
    /// <summary>
    /// TLS transport: a <see cref="System.Net.Security.SslStream"/> over a raw TCP connection.
    /// Supports SNI (the server name sent in the handshake may differ from the dial host).
    /// Certificate validation is ON by default; certificates are only accepted unconditionally
    /// when <paramref name="allowInsecure"/> is true.
    /// </summary>
    public class TlsTransport : ITransport
    {
        private readonly string _sni;
        private readonly bool _allowInsecure;
        private readonly TcpTransport _tcp = new TcpTransport();
        private SslStream _ssl;

        /// <param name="sni">Server name for the TLS SNI / certificate match. If null/empty, the dial host is used.</param>
        /// <param name="allowInsecure">When true, accept any server certificate (skip validation).</param>
        public TlsTransport(string sni, bool allowInsecure)
        {
            _sni = sni;
            _allowInsecure = allowInsecure;
        }

        public async Task ConnectAsync(string host, int port, CancellationToken ct)
        {
            await _tcp.ConnectAsync(host, port, ct).ConfigureAwait(false);

            var targetHost = string.IsNullOrEmpty(_sni) ? host : _sni;

            _ssl = new SslStream(
                _tcp.GetStream(),
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: ValidateCertificate);

            // Tls12 is the safe baseline available on Win8.1/Win10 ARM32. Tls13 is not
            // guaranteed on those OS versions, so we do not request it here.
            using (ct.Register(() => Close()))
            {
                await _ssl.AuthenticateAsClientAsync(
                    targetHost,
                    clientCertificates: null,
                    enabledSslProtocols: SslProtocols.Tls12,
                    checkCertificateRevocation: false).ConfigureAwait(false);
            }
            ct.ThrowIfCancellationRequested();
        }

        private bool ValidateCertificate(object sender, X509Certificate certificate,
            X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (_allowInsecure)
                return true;                       // explicit opt-out only
            return sslPolicyErrors == SslPolicyErrors.None;
        }

        public Stream GetStream()
        {
            if (_ssl == null)
                throw new InvalidOperationException("TlsTransport is not connected.");
            return _ssl;
        }

        public void Close()
        {
            try { _ssl?.Dispose(); } catch { }
            _ssl = null;
            _tcp.Close();
        }
    }
}

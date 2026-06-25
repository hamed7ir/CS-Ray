using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Transport
{
    /// <summary>
    /// An outbound transport to the proxy server. Implementations open a connection
    /// (optionally wrapping it, e.g. TLS) and expose a single duplex byte stream.
    /// </summary>
    public interface ITransport
    {
        /// <summary>Establish the connection to the given host/port.</summary>
        Task ConnectAsync(string host, int port, CancellationToken ct);

        /// <summary>The duplex stream for reading/writing once connected.</summary>
        Stream GetStream();

        /// <summary>Tear down the connection and release resources.</summary>
        void Close();
    }
}

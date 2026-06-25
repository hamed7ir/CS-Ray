using System;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Transport
{
    /// <summary>Raw TCP transport via <see cref="TcpClient"/>.</summary>
    public class TcpTransport : ITransport
    {
        private TcpClient _client;
        private NetworkStream _stream;

        public async Task ConnectAsync(string host, int port, CancellationToken ct)
        {
            _client = new TcpClient { NoDelay = true };
            // TcpClient.ConnectAsync has no CancellationToken overload on net47;
            // register the token to close the socket, which faults the connect task.
            using (ct.Register(() => { try { _client.Close(); } catch { } }))
            {
                await _client.ConnectAsync(host, port).ConfigureAwait(false);
            }
            ct.ThrowIfCancellationRequested();
            _stream = _client.GetStream();
        }

        public Stream GetStream()
        {
            if (_stream == null)
                throw new InvalidOperationException("TcpTransport is not connected.");
            return _stream;
        }

        public void Close()
        {
            try { _stream?.Dispose(); } catch { }
            try { _client?.Close(); } catch { }
            _stream = null;
            _client = null;
        }
    }
}

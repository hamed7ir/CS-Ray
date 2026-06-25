using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CS_Ray.Core.Transport;

namespace CS_Ray.Core.Protocol.Vmess
{
    /// <summary>
    /// One VMess UDP association = one destination (mirrors <see cref="VlessUdpSession"/>). Opens the same
    /// raw-TCP VMess chain as the TCP path but with Command=UDP (0x02). VMess body framing IS per-datagram:
    /// each chunk = one UDP packet, so one WriteAsync (≤8KB) emits one chunk = one datagram, and each chunk
    /// read back = one datagram. The AEAD response header is consumed once, lazily, on the first read.
    /// Dials the pinned ServerIp when set (full tunnel), else ServerHost — keeping the leak-safe pin intact.
    /// </summary>
    public sealed class VMessUdpSession : IUdpOutbound
    {
        private const int RecvBufSize = 8192; // VmessBodyStream MaxPayload — one ReadAsync returns one chunk/datagram

        private readonly VlessConfig _cfg;
        private readonly byte[] _uuid;
        private ITransport _outbound;
        private Stream _body;
        private readonly byte[] _rbuf = new byte[RecvBufSize];

        public VMessUdpSession(VlessConfig cfg, byte[] uuid16)
        {
            _cfg = cfg ?? throw new ArgumentNullException(nameof(cfg));
            _uuid = uuid16 ?? throw new ArgumentNullException(nameof(uuid16));
        }

        public async Task ConnectAsync(string dstHost, int dstPort, CancellationToken ct)
        {
            // VMess (this build) runs over raw TCP, same as the TCP relay path.
            ITransport outbound = new TcpTransport();
            string dial = !string.IsNullOrEmpty(_cfg.ServerIp) ? _cfg.ServerIp : _cfg.ServerHost;
            await outbound.ConnectAsync(dial, _cfg.ServerPort, ct).ConfigureAwait(false);
            _outbound = outbound;

            _body = await VmessProtocol.EstablishAsync(
                outbound.GetStream(), _uuid, dstHost, dstPort,
                VmessRequest.CommandUdp, null, ct).ConfigureAwait(false);
        }

        public async Task SendAsync(byte[] payload, int offset, int count, CancellationToken ct)
        {
            // count ≤ MTU < 8KB, so this writes exactly one VMess chunk = one datagram (WriteAsync also flushes).
            await _body.WriteAsync(payload, offset, count, ct).ConfigureAwait(false);
        }

        public Task SendAsync(byte[] payload, CancellationToken ct) => SendAsync(payload, 0, payload.Length, ct);

        public async Task<byte[]> ReceiveAsync(CancellationToken ct)
        {
            // With a full-size buffer, one ReadAsync returns exactly one chunk (= one datagram). Null on EOF.
            int n = await _body.ReadAsync(_rbuf, 0, _rbuf.Length, ct).ConfigureAwait(false);
            if (n <= 0) return null;
            var dg = new byte[n];
            Buffer.BlockCopy(_rbuf, 0, dg, 0, n);
            return dg;
        }

        public void Dispose()
        {
            try { _outbound?.Close(); } catch { }
            _outbound = null;
            _body = null;
        }
    }
}

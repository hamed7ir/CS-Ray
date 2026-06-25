using System;
using System.Threading;
using System.Threading.Tasks;

namespace CS_Ray.Core.Protocol
{
    /// <summary>
    /// A per-destination UDP association through the proxy. The TUN UdpHandler NAT table creates one per
    /// flow, sends app datagrams via <see cref="SendAsync"/>, and writes replies from <see cref="ReceiveAsync"/>
    /// back into the TUN. Implemented by VlessUdpSession (E1); VMess UDP plugs in here later (E4).
    /// </summary>
    public interface IUdpOutbound : IDisposable
    {
        Task ConnectAsync(string dstHost, int dstPort, CancellationToken ct);
        Task SendAsync(byte[] payload, int offset, int count, CancellationToken ct);
        Task<byte[]> ReceiveAsync(CancellationToken ct);
    }
}

using System;

namespace CS_Ray.Core.Tun
{
    /// <summary>
    /// ICMP echo handler. Answers an Echo Request by synthesizing an Echo Reply (swap src/dst,
    /// type 8→0, echo id/seq/payload, fix ICMP + IP checksums) and writing it back into the TUN.
    ///
    /// Why synthesize rather than really ping the destination: the destination is the address we
    /// just routed INTO the TUN, so a managed Ping to it would loop straight back to our own read
    /// loop. Synthesizing proves the full read→build→write path and makes "ping &lt;captured-IP&gt;"
    /// succeed. Real ICMP relay needs raw sockets / engine support and is out of Phase-3 scope.
    /// </summary>
    public class IcmpHandler
    {
        private readonly Action<byte[]> _write;
        private readonly Action _onReplied;

        public IcmpHandler(Action<byte[]> write, Action onReplied)
        {
            _write = write;
            _onReplied = onReplied;
        }

        public void Handle(byte[] pkt, int len, int ihl)
        {
            if (len < ihl + 8) return;
            if (pkt[ihl] != 8) return; // only Echo Request (type 8)

            var reply = new byte[len];
            Buffer.BlockCopy(pkt, 0, reply, 0, len);

            // Swap IPv4 source (12..16) and destination (16..20): reply goes FROM target TO sender.
            for (int i = 0; i < 4; i++)
            {
                byte t = reply[12 + i];
                reply[12 + i] = reply[16 + i];
                reply[16 + i] = t;
            }

            reply[ihl] = 0;   // ICMP type 0 (Echo Reply); code/id/seq/payload echoed unchanged
            reply[8] = 64;    // fresh TTL

            Checksums.SetIcmp(reply, ihl, len - ihl);
            Checksums.SetIpHeader(reply, 0, ihl);

            _write(reply);
            _onReplied?.Invoke();
        }
    }
}

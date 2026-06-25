namespace CS_Ray.Core.Tun
{
    public enum PacketAction { Drop, Icmp, Udp, Tcp, Other }

    /// <summary>
    /// Decides what to do with a captured IPv4 packet. With the default route, TUN sees ALL traffic,
    /// so this drops every private/special range (those stay DIRECT via dedicated bypass routes; the
    /// drop here is defense-in-depth) plus the proxy server's own IP. EVERYTHING public is tunneled —
    /// no per-domain/per-vendor exceptions (so UWP/Microsoft public traffic tunnels correctly).
    /// </summary>
    public static class PacketFilter
    {
        /// <summary>Active proxy server IP kept direct (defense-in-depth; the loop-guard route is primary). 0 = none.</summary>
        public static uint BypassServerIp;

        /// <summary>Optional: drop UDP/443 (QUIC) so apps fall back to TCP 443. OFF by default — QUIC tunnels
        /// normally via the engine; turn ON only if you prefer forcing TCP fallback.</summary>
        public static bool BlockQuic;

        /// <summary>Every tunneled DNS query is forced to this resolver (regardless of the server the OS aimed it
        /// at) so ISP-configured (e.g. Iranian) resolvers are never used. 8.8.8.8 by default. The reply is
        /// rewritten to look like it came from the original server.</summary>
        public static uint DnsResolver = 0x08080808; // 8.8.8.8

        public static PacketAction Decide(byte[] pkt, int len, out int ihl, out byte proto, out uint dst)
        {
            ihl = 0; proto = 0; dst = 0;
            if (len < 20) return PacketAction.Drop;

            int version = pkt[0] >> 4;
            if (version != 4) return PacketAction.Drop; // IPv6 deferred (v4-only)

            ihl = (pkt[0] & 0x0F) * 4;
            if (ihl < 20 || len < ihl) return PacketAction.Drop;

            proto = pkt[9];
            byte d0 = pkt[16], d1 = pkt[17];
            dst = (uint)((d0 << 24) | (d1 << 16) | (pkt[18] << 8) | pkt[19]);

            // Private + special ranges → DIRECT (kept off TUN by bypass routes; dropped here as backstop).
            if (d0 == 127) return PacketAction.Drop;                          // 127.0.0.0/8 loopback
            if (d0 == 10) return PacketAction.Drop;                           // 10.0.0.0/8 (incl own 10.18.0.0/30)
            if (d0 == 172 && d1 >= 16 && d1 <= 31) return PacketAction.Drop;  // 172.16.0.0/12
            if (d0 == 192 && d1 == 168) return PacketAction.Drop;             // 192.168.0.0/16
            if (d0 == 169 && d1 == 254) return PacketAction.Drop;             // 169.254.0.0/16 link-local
            if (d0 >= 224) return PacketAction.Drop;                          // 224/4 multicast + 255.x broadcast
            if (BypassServerIp != 0 && dst == BypassServerIp) return PacketAction.Drop; // proxy server

            switch (proto)
            {
                case 1: return PacketAction.Icmp;
                case 6: return PacketAction.Tcp;
                case 17: return PacketAction.Udp;
                default: return PacketAction.Other;
            }
        }
    }
}

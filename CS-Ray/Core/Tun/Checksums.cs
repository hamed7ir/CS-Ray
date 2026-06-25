using System.Text;

namespace CS_Ray.Core.Tun
{
    /// <summary>
    /// Standard one's-complement Internet checksums (RFC 1071) for IPv4 header, ICMP, and UDP
    /// (with pseudo-header). All operate in place on a packet byte[]. Pure managed.
    /// </summary>
    public static class Checksums
    {
        // 16-bit one's-complement running sum (big-endian words).
        private static uint Sum(byte[] d, int off, int len, uint sum)
        {
            int i = off;
            while (len > 1) { sum += (uint)((d[i] << 8) | d[i + 1]); i += 2; len -= 2; }
            if (len == 1) sum += (uint)(d[i] << 8); // pad last byte high
            return sum;
        }

        private static ushort Fold(uint sum)
        {
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)(~sum & 0xFFFF);
        }

        /// <summary>Zero + recompute the IPv4 header checksum (header is <paramref name="ihl"/> bytes at <paramref name="ipOffset"/>).</summary>
        public static void SetIpHeader(byte[] pkt, int ipOffset, int ihl)
        {
            pkt[ipOffset + 10] = 0; pkt[ipOffset + 11] = 0;
            ushort c = Fold(Sum(pkt, ipOffset, ihl, 0));
            pkt[ipOffset + 10] = (byte)(c >> 8); pkt[ipOffset + 11] = (byte)c;
        }

        /// <summary>Zero + recompute the ICMP checksum over the whole ICMP message.</summary>
        public static void SetIcmp(byte[] pkt, int icmpOffset, int icmpLen)
        {
            pkt[icmpOffset + 2] = 0; pkt[icmpOffset + 3] = 0;
            ushort c = Fold(Sum(pkt, icmpOffset, icmpLen, 0));
            pkt[icmpOffset + 2] = (byte)(c >> 8); pkt[icmpOffset + 3] = (byte)c;
        }

        /// <summary>Zero + recompute the UDP checksum (IPv4 pseudo-header + UDP segment). 0 → 0xFFFF.</summary>
        public static void SetUdpV4(byte[] pkt, int ipOffset, int udpOffset, int udpLen)
        {
            pkt[udpOffset + 6] = 0; pkt[udpOffset + 7] = 0;
            uint sum = Sum(pkt, ipOffset + 12, 8, 0); // src(4) + dst(4)
            sum += 17;                                // protocol
            sum += (uint)udpLen;                      // UDP length
            sum = Sum(pkt, udpOffset, udpLen, sum);   // UDP header + data
            ushort c = Fold(sum);
            if (c == 0) c = 0xFFFF;
            pkt[udpOffset + 6] = (byte)(c >> 8); pkt[udpOffset + 7] = (byte)c;
        }

        /// <summary>Zero + recompute the TCP checksum (IPv4 pseudo-header + TCP header + data).</summary>
        public static void SetTcpV4(byte[] pkt, int ipOffset, int tcpOffset, int tcpLen)
        {
            pkt[tcpOffset + 16] = 0; pkt[tcpOffset + 17] = 0;
            uint sum = Sum(pkt, ipOffset + 12, 8, 0); // src(4) + dst(4)
            sum += 6;                                 // protocol TCP
            sum += (uint)tcpLen;                      // TCP length
            sum = Sum(pkt, tcpOffset, tcpLen, sum);   // TCP header + data
            ushort c = Fold(sum);
            pkt[tcpOffset + 16] = (byte)(c >> 8); pkt[tcpOffset + 17] = (byte)c;
        }

        /// <summary>Verification: one's-complement sum over data INCLUDING a correct checksum folds to 0.</summary>
        public static bool Verify(byte[] d, int off, int len) => Fold(Sum(d, off, len, 0)) == 0;

        /// <summary>Self-test against a known IP-header vector + ICMP/UDP self-consistency.</summary>
        public static string SelfTest()
        {
            var sb = new StringBuilder();
            int pass = 0, fail = 0;
            void Check(string n, bool ok, string d = "") { if (ok) { pass++; sb.AppendLine("PASS  " + n); } else { fail++; sb.AppendLine("FAIL  " + n + (d.Length > 0 ? "  -- " + d : "")); } }

            // 1) Known IPv4 header (RFC1071-style): checksum must be 0xB861.
            byte[] ip = { 0x45,0x00,0x00,0x73, 0x00,0x00,0x40,0x00, 0x40,0x11,0x00,0x00,
                          0xc0,0xa8,0x00,0x01, 0xc0,0xa8,0x00,0xc7 };
            SetIpHeader(ip, 0, 20);
            Check("IPv4 header checksum == 0xB861", ip[10] == 0xB8 && ip[11] == 0x61, "got 0x" + ip[10].ToString("X2") + ip[11].ToString("X2"));
            Check("IPv4 header verifies to 0", Verify(ip, 0, 20));

            // 2) ICMP echo: set checksum then verify the whole message folds to 0.
            byte[] icmp = new byte[16];
            icmp[0] = 8; icmp[4] = 0x12; icmp[5] = 0x34; icmp[6] = 0x00; icmp[7] = 0x01;
            for (int i = 8; i < 16; i++) icmp[i] = (byte)i;
            SetIcmp(icmp, 0, 16);
            Check("ICMP checksum verifies to 0", Verify(icmp, 0, 16));

            // 3) UDP over IPv4: set checksum, then verify pseudo-header + segment folds to 0.
            int total = 20 + 8 + 4;
            byte[] u = new byte[total];
            u[0] = 0x45; u[2] = (byte)(total >> 8); u[3] = (byte)total; u[8] = 64; u[9] = 17;
            u[12] = 10; u[13] = 18; u[14] = 0; u[15] = 2;     // src 10.18.0.2
            u[16] = 8; u[17] = 8; u[18] = 8; u[19] = 8;       // dst 8.8.8.8
            u[20] = 0xC3; u[21] = 0x50; u[22] = 0x00; u[23] = 0x35; // ports 50000 -> 53
            int udpLen = 8 + 4; u[24] = (byte)(udpLen >> 8); u[25] = (byte)udpLen;
            u[28] = 0xDE; u[29] = 0xAD; u[30] = 0xBE; u[31] = 0xEF;
            SetUdpV4(u, 0, 20, udpLen);
            SetIpHeader(u, 0, 20);
            uint ps = Sum(u, 12, 8, 0) + 17 + (uint)udpLen;
            Check("UDP checksum verifies to 0", Fold(Sum(u, 20, udpLen, ps)) == 0);
            Check("UDP IP header verifies to 0", Verify(u, 0, 20));

            // 4) TCP over IPv4: set checksum, verify pseudo-header + segment folds to 0.
            int tcpLen = 20 + 4, tt = 20 + tcpLen;
            byte[] tp = new byte[tt];
            tp[0] = 0x45; tp[2] = (byte)(tt >> 8); tp[3] = (byte)tt; tp[8] = 64; tp[9] = 6;
            tp[12] = 10; tp[13] = 18; tp[14] = 0; tp[15] = 2;   // src 10.18.0.2
            tp[16] = 93; tp[17] = 184; tp[18] = 216; tp[19] = 34; // dst 93.184.216.34
            tp[20] = 0xC3; tp[21] = 0x50; tp[22] = 0x00; tp[23] = 0x50; // ports 50000 -> 80
            tp[32] = 0x50; tp[33] = 0x10; tp[34] = 0xFF; tp[35] = 0xFF; // dataOff=5, ACK, window
            tp[40] = 0x47; tp[41] = 0x45; tp[42] = 0x54; tp[43] = 0x0A; // "GET\n"
            Checksums.SetTcpV4(tp, 0, 20, tcpLen);
            Checksums.SetIpHeader(tp, 0, 20);
            uint tps = Sum(tp, 12, 8, 0) + 6 + (uint)tcpLen;
            Check("TCP checksum verifies to 0", Fold(Sum(tp, 20, tcpLen, tps)) == 0);
            Check("TCP IP header verifies to 0", Verify(tp, 0, 20));

            sb.AppendLine();
            sb.AppendLine("RESULT: " + pass + " passed, " + fail + " failed.");
            return sb.ToString();
        }
    }
}

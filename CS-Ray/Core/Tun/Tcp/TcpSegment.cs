using System;

namespace CS_Ray.Core.Tun.Tcp
{
    /// <summary>Parsed view of a TCP segment inside a captured IPv4 packet.</summary>
    public struct TcpSeg
    {
        public uint SrcIp, DstIp;
        public ushort SrcPort, DstPort;
        public uint Seq, Ack;
        public byte Flags;
        public ushort Window;
        public int PayloadOffset;   // offset in the IP packet where TCP payload starts
        public int PayloadLength;
        public ushort Mss;          // from SYN options, else 0
    }

    /// <summary>Parse/build minimal TCP/IPv4 segments (no options on send). Checksums via <see cref="Checksums"/>.</summary>
    public static class TcpSegment
    {
        public const byte FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10;

        public static bool Parse(byte[] ip, int len, int ihl, out TcpSeg s)
        {
            s = default(TcpSeg);
            if (len < ihl + 20) return false;
            int t = ihl;

            s.SrcIp = U32(ip, 12); s.DstIp = U32(ip, 16);
            s.SrcPort = U16(ip, t); s.DstPort = U16(ip, t + 2);
            s.Seq = U32(ip, t + 4); s.Ack = U32(ip, t + 8);
            int dataOff = (ip[t + 12] >> 4) * 4;
            if (dataOff < 20 || len < ihl + dataOff) return false;
            s.Flags = ip[t + 13];
            s.Window = U16(ip, t + 14);
            s.PayloadOffset = ihl + dataOff;
            s.PayloadLength = len - s.PayloadOffset;
            if (s.PayloadLength < 0) return false;

            // Parse MSS option on SYN (kind 2, len 4).
            if ((s.Flags & SYN) != 0 && dataOff > 20)
            {
                int o = t + 20, end = t + dataOff;
                while (o < end)
                {
                    byte kind = ip[o];
                    if (kind == 0) break;            // end of options
                    if (kind == 1) { o++; continue; } // NOP
                    if (o + 1 >= end) break;
                    byte olen = ip[o + 1];
                    if (olen < 2 || o + olen > end) break;
                    if (kind == 2 && olen == 4) s.Mss = U16(ip, o + 2);
                    o += olen;
                }
            }
            return true;
        }

        /// <summary>Builds a TCP/IPv4 packet (20-byte IP + 20-byte TCP, no options) with payload and checksums.</summary>
        public static byte[] Build(uint srcIp, ushort srcPort, uint dstIp, ushort dstPort,
            uint seq, uint ack, byte flags, ushort window, byte[] payload, int payloadOff, int payloadLen)
        {
            int total = 20 + 20 + payloadLen;
            var p = new byte[total];

            // IPv4
            p[0] = 0x45; p[1] = 0;
            p[2] = (byte)(total >> 8); p[3] = (byte)total;
            p[4] = 0; p[5] = 0; p[6] = 0x40; p[7] = 0; // DF
            p[8] = 64; p[9] = 6;                       // TTL, proto=TCP
            W32(p, 12, srcIp); W32(p, 16, dstIp);

            // TCP
            p[20] = (byte)(srcPort >> 8); p[21] = (byte)srcPort;
            p[22] = (byte)(dstPort >> 8); p[23] = (byte)dstPort;
            W32(p, 24, seq); W32(p, 28, ack);
            p[32] = 0x50;          // data offset 5 (20 bytes), no options
            p[33] = flags;
            p[34] = (byte)(window >> 8); p[35] = (byte)window;
            // checksum (36..38) + urgent (38..40) left 0
            if (payloadLen > 0) Buffer.BlockCopy(payload, payloadOff, p, 40, payloadLen);

            Checksums.SetTcpV4(p, 0, 20, 20 + payloadLen);
            Checksums.SetIpHeader(p, 0, 20);
            return p;
        }

        private static ushort U16(byte[] b, int o) => (ushort)((b[o] << 8) | b[o + 1]);
        private static uint U32(byte[] b, int o) => (uint)((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]);
        private static void W32(byte[] b, int o, uint v) { b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v; }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CS_Ray.Core.Transport.Http2
{
    /// <summary>HPACK (RFC 7541) tables. Generated from the RFC text (Appendix A static table, Appendix B Huffman code) —
    /// do not edit by hand.</summary>
    internal static class HpackTables
    {
        /// <summary>Static table, index 1..61 at [index - 1]: { name, value }.</summary>
        public static readonly string[][] Static =
        {
            new[] { ":authority", "" },
            new[] { ":method", "GET" },
            new[] { ":method", "POST" },
            new[] { ":path", "/" },
            new[] { ":path", "/index.html" },
            new[] { ":scheme", "http" },
            new[] { ":scheme", "https" },
            new[] { ":status", "200" },
            new[] { ":status", "204" },
            new[] { ":status", "206" },
            new[] { ":status", "304" },
            new[] { ":status", "400" },
            new[] { ":status", "404" },
            new[] { ":status", "500" },
            new[] { "accept-charset", "" },
            new[] { "accept-encoding", "gzip, deflate" },
            new[] { "accept-language", "" },
            new[] { "accept-ranges", "" },
            new[] { "accept", "" },
            new[] { "access-control-allow-origin", "" },
            new[] { "age", "" },
            new[] { "allow", "" },
            new[] { "authorization", "" },
            new[] { "cache-control", "" },
            new[] { "content-disposition", "" },
            new[] { "content-encoding", "" },
            new[] { "content-language", "" },
            new[] { "content-length", "" },
            new[] { "content-location", "" },
            new[] { "content-range", "" },
            new[] { "content-type", "" },
            new[] { "cookie", "" },
            new[] { "date", "" },
            new[] { "etag", "" },
            new[] { "expect", "" },
            new[] { "expires", "" },
            new[] { "from", "" },
            new[] { "host", "" },
            new[] { "if-match", "" },
            new[] { "if-modified-since", "" },
            new[] { "if-none-match", "" },
            new[] { "if-range", "" },
            new[] { "if-unmodified-since", "" },
            new[] { "last-modified", "" },
            new[] { "link", "" },
            new[] { "location", "" },
            new[] { "max-forwards", "" },
            new[] { "proxy-authenticate", "" },
            new[] { "proxy-authorization", "" },
            new[] { "range", "" },
            new[] { "referer", "" },
            new[] { "refresh", "" },
            new[] { "retry-after", "" },
            new[] { "server", "" },
            new[] { "set-cookie", "" },
            new[] { "strict-transport-security", "" },
            new[] { "transfer-encoding", "" },
            new[] { "user-agent", "" },
            new[] { "vary", "" },
            new[] { "via", "" },
            new[] { "www-authenticate", "" }
        };

        /// <summary>Huffman code (MSB-aligned value) and bit length per symbol 0..256 (256 = EOS).</summary>
        public static readonly uint[] HuffCodes = { 0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7, 0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec, 0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb, 0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18, 0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc, 0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22, 0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7, 0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc, 0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9, 0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf, 0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3, 0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef, 0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde, 0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec, 0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef, 0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1, 0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec, 0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed, 0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2, 0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5, 0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3, 0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4, 0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea, 0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee, 0x3fffffff };
        public static readonly byte[] HuffLens = { 13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30 };
    }

    /// <summary>A header field (HPACK strings are octets; we carry them as Latin-1 so no byte is lost).</summary>
    internal struct HeaderField
    {
        public readonly string Name, Value;
        public HeaderField(string name, string value) { Name = name; Value = value; }
        public override string ToString() => Name + ": " + Value;
    }

    internal sealed class HpackException : Exception
    {
        public HpackException(string message) : base(message) { }
    }

    /// <summary>HPACK Huffman coding (RFC 7541 §5.2, Appendix B).</summary>
    internal static class HpackHuffman
    {
        // Binary decoding tree: node n has children _tree[2n] (bit 0) and _tree[2n + 1] (bit 1). A value >= 0 is a child
        // node index; a value < 0 is a leaf for symbol ~value. 0 means "no child" (node 0 is the root, never a child).
        private static readonly int[] _tree = BuildTree();

        private static int[] BuildTree()
        {
            var t = new List<int> { 0, 0 };   // root
            int nodes = 1;
            for (int sym = 0; sym <= 256; sym++)
            {
                uint code = HpackTables.HuffCodes[sym];
                int len = HpackTables.HuffLens[sym];
                int node = 0;
                for (int i = len - 1; i >= 0; i--)
                {
                    int bit = (int)((code >> i) & 1);
                    int slot = 2 * node + bit;
                    if (i == 0) { t[slot] = ~sym; break; }
                    if (t[slot] == 0) { t[slot] = nodes++; t.Add(0); t.Add(0); }
                    node = t[slot];
                }
            }
            return t.ToArray();
        }

        public static byte[] Decode(byte[] b, int off, int len)
        {
            var output = new MemoryStream(len * 8 / 5 + 1);
            int node = 0, bitsSinceSymbol = 0;
            bool allOnes = true;
            for (int i = off; i < off + len; i++)
            {
                for (int k = 7; k >= 0; k--)
                {
                    int bit = (b[i] >> k) & 1;
                    int next = _tree[2 * node + bit];
                    bitsSinceSymbol++;
                    if (bit == 0) allOnes = false;
                    if (next < 0)
                    {
                        int sym = ~next;
                        if (sym == 256) throw new HpackException("HPACK: EOS symbol inside a Huffman string");
                        output.WriteByte((byte)sym);
                        node = 0; bitsSinceSymbol = 0; allOnes = true;
                    }
                    else if (next == 0) throw new HpackException("HPACK: invalid Huffman code");
                    else node = next;
                }
            }
            // Padding: at most 7 bits, all ones (a prefix of EOS).
            if (bitsSinceSymbol > 7 || !allOnes) throw new HpackException("HPACK: invalid Huffman padding");
            return output.ToArray();
        }

        public static int EncodedLength(byte[] s)
        {
            long bits = 0;
            foreach (byte c in s) bits += HpackTables.HuffLens[c];
            return (int)((bits + 7) / 8);
        }

        public static void Encode(Stream o, byte[] s)
        {
            ulong acc = 0; int n = 0;
            foreach (byte c in s)
            {
                acc = (acc << HpackTables.HuffLens[c]) | HpackTables.HuffCodes[c];
                n += HpackTables.HuffLens[c];
                while (n >= 8) { n -= 8; o.WriteByte((byte)(acc >> n)); }
            }
            if (n > 0) o.WriteByte((byte)((acc << (8 - n)) | (0xFFu >> n)));   // pad with EOS prefix (1s)
        }
    }

    /// <summary>Stateful HPACK decoder for one HTTP/2 connection (header blocks must be fed in order).</summary>
    internal sealed class HpackDecoder
    {
        private readonly LinkedList<HeaderField> _dyn = new LinkedList<HeaderField>();   // First = newest (index 62)
        private int _size;
        private int _max;
        private readonly int _maxAllowed;   // our SETTINGS_HEADER_TABLE_SIZE
        private readonly int _maxDecoded;   // cap on one decoded header list (name + value + 32 per field)
        private static readonly Encoding Latin1 = Encoding.GetEncoding(28591);

        public HpackDecoder(int maxTableSize = 4096, int maxDecodedListSize = 1 << 20) { _max = _maxAllowed = maxTableSize; _maxDecoded = maxDecodedListSize; }

        public int TableSize => _size;
        public int TableCount => _dyn.Count;

        public List<HeaderField> Decode(byte[] b, int off, int len)
        {
            var list = new List<HeaderField>();
            int p = off, end = off + len;
            bool fieldsSeen = false;
            long decoded = 0;
            while (p < end)
            {
                if (list.Count > 0)
                {
                    var last = list[list.Count - 1];
                    decoded += last.Name.Length + last.Value.Length + 32;
                    if (decoded > _maxDecoded) throw new HpackException("HPACK: decoded header list too large");
                }
                byte f = b[p];
                if ((f & 0x80) != 0)                                         // indexed field
                {
                    int idx = ReadInt(b, ref p, end, 7);
                    list.Add(Get(idx)); fieldsSeen = true;
                }
                else if ((f & 0xC0) == 0x40)                                 // literal, incremental indexing
                {
                    var h = ReadLiteral(b, ref p, end, 6);
                    Add(h); list.Add(h); fieldsSeen = true;
                }
                else if ((f & 0xE0) == 0x20)                                 // dynamic table size update
                {
                    if (fieldsSeen) throw new HpackException("HPACK: table size update after a header field");
                    int sz = ReadInt(b, ref p, end, 5);
                    if (sz > _maxAllowed) throw new HpackException("HPACK: table size update above the limit");
                    _max = sz; Evict();
                }
                else                                                          // literal without / never indexed (4-bit)
                {
                    list.Add(ReadLiteral(b, ref p, end, 4)); fieldsSeen = true;
                }
            }
            if (list.Count > 0)
            {
                var last = list[list.Count - 1];
                if (decoded + last.Name.Length + last.Value.Length + 32 > _maxDecoded) throw new HpackException("HPACK: decoded header list too large");
            }
            return list;
        }

        private HeaderField ReadLiteral(byte[] b, ref int p, int end, int prefix)
        {
            int idx = ReadInt(b, ref p, end, prefix);
            string name = idx == 0 ? ReadString(b, ref p, end) : Get(idx).Name;
            return new HeaderField(name, ReadString(b, ref p, end));
        }

        private HeaderField Get(int idx)
        {
            if (idx <= 0) throw new HpackException("HPACK: index 0");
            if (idx <= HpackTables.Static.Length) { var e = HpackTables.Static[idx - 1]; return new HeaderField(e[0], e[1]); }
            int d = idx - HpackTables.Static.Length - 1;
            if (d >= _dyn.Count) throw new HpackException("HPACK: index " + idx + " beyond the dynamic table");
            var node = _dyn.First;
            while (d-- > 0) node = node.Next;
            return node.Value;
        }

        private void Add(HeaderField h)
        {
            int sz = EntrySize(h);
            if (sz > _max) { _dyn.Clear(); _size = 0; return; }   // RFC 7541 §4.4: an oversized entry empties the table
            _dyn.AddFirst(h); _size += sz;
            Evict();
        }

        private void Evict()
        {
            while (_size > _max && _dyn.Count > 0) { _size -= EntrySize(_dyn.Last.Value); _dyn.RemoveLast(); }
        }

        private static int EntrySize(HeaderField h) => Latin1.GetByteCount(h.Name) + Latin1.GetByteCount(h.Value) + 32;

        internal static int ReadInt(byte[] b, ref int p, int end, int prefix)
        {
            if (p >= end) throw new HpackException("HPACK: truncated integer");
            int mask = (1 << prefix) - 1;
            int v = b[p++] & mask;
            if (v < mask) return v;
            int m = 0;
            while (true)
            {
                if (p >= end) throw new HpackException("HPACK: truncated integer");
                byte c = b[p++];
                if (m > 21) throw new HpackException("HPACK: integer too large");
                v += (c & 0x7F) << m;
                m += 7;
                if ((c & 0x80) == 0) return v;
            }
        }

        private static string ReadString(byte[] b, ref int p, int end)
        {
            if (p >= end) throw new HpackException("HPACK: truncated string");
            bool huff = (b[p] & 0x80) != 0;
            int len = ReadInt(b, ref p, end, 7);
            if (len < 0 || p + len > end) throw new HpackException("HPACK: truncated string");
            string s = huff ? Latin1.GetString(HpackHuffman.Decode(b, p, len)) : Latin1.GetString(b, p, len);
            p += len;
            return s;
        }
    }

    /// <summary>
    /// Stateless HPACK encoder for our requests: fully indexed static entries where name+value match, otherwise literal
    /// header fields WITHOUT indexing (we never touch the server's view of our dynamic table, so there is nothing to keep
    /// in sync), Huffman-coded when that is shorter (as Go's encoder does).
    /// </summary>
    internal static class HpackEncoder
    {
        private static readonly Encoding Latin1 = Encoding.GetEncoding(28591);

        public static byte[] Encode(IList<HeaderField> headers)
        {
            var o = new MemoryStream();
            foreach (var h in headers)
            {
                int full = 0, nameOnly = 0;
                for (int i = 0; i < HpackTables.Static.Length; i++)
                {
                    if (HpackTables.Static[i][0] != h.Name) continue;
                    if (nameOnly == 0) nameOnly = i + 1;
                    if (HpackTables.Static[i][1] == h.Value) { full = i + 1; break; }
                }
                if (full != 0) { WriteInt(o, 0x80, 7, full); continue; }
                WriteInt(o, 0x00, 4, nameOnly);                        // literal without indexing
                if (nameOnly == 0) WriteString(o, h.Name);
                WriteString(o, h.Value);
            }
            return o.ToArray();
        }

        internal static void WriteInt(Stream o, int firstByteBits, int prefix, int v)
        {
            int mask = (1 << prefix) - 1;
            if (v < mask) { o.WriteByte((byte)(firstByteBits | v)); return; }
            o.WriteByte((byte)(firstByteBits | mask));
            v -= mask;
            while (v >= 128) { o.WriteByte((byte)((v & 0x7F) | 0x80)); v >>= 7; }
            o.WriteByte((byte)v);
        }

        private static void WriteString(Stream o, string s)
        {
            byte[] raw = Latin1.GetBytes(s);
            int hl = HpackHuffman.EncodedLength(raw);
            if (hl < raw.Length) { WriteInt(o, 0x80, 7, hl); HpackHuffman.Encode(o, raw); }
            else { WriteInt(o, 0x00, 7, raw.Length); o.Write(raw, 0, raw.Length); }
        }
    }
}

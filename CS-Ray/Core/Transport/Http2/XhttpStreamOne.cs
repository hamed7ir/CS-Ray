using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using Org.BouncyCastle.Security;

namespace CS_Ray.Core.Transport.Http2
{
    /// <summary>
    /// XHTTP settings from the share link's host / path / mode / extra (Xray-core transport/internet/splithttp +
    /// infra/conf), for stream-one (h2, REALITY) and packet-up (HTTP/1.1, TLS) alike.
    /// </summary>
    public sealed class XhttpSettings
    {
        public string Host;                 // :authority (no port) and the Referer host
        public string Path = "/";           // decoded path, normalised: leading '/', trailing '/'
        public string Query = "";           // the part after '?' in the configured path
        public bool NoGrpcHeader;
        public int PaddingFrom = 100, PaddingTo = 1000;   // x_padding length range (Xray picks [from, to))
        // xPaddingObfsMode (Xray v26.2+): where/how the padding goes is configurable; off = the classic x_padding.
        public bool PadObfs;
        public string PadKey = "x_padding", PadHeader = "X-Padding", PadPlacement = "queryInHeader", PadMethod = "repeat-x";
        public string Method = "POST";
        public readonly List<KeyValuePair<string, string>> Headers = new List<KeyValuePair<string, string>>();
        // XMUX (defaults when the xmux object is absent/empty: up to 3 connections, 600–900 requests, 1800–3000 s each)
        public int ConnFrom = 3, ConnTo = 3, ConcFrom, ConcTo;   // maxConnections / maxConcurrency ranges (rolled once per pool)
        public int ReqFrom = 600, ReqTo = 900, SecsFrom = 1800, SecsTo = 3000;
        public int ReuseFrom, ReuseTo;      // cMaxReuseTimes (0 = unlimited)
        // packet-up uplink: the most a POST may carry, and the least time between two POSTs (Xray defaults).
        public int MaxPostFrom = 1000000, MaxPostTo = 1000000, MinIntervalFrom = 30, MinIntervalTo = 30;

        /// <summary>Builds settings from the link fields. `extra` is the raw JSON (null/empty ok); unknown fields are ignored.</summary>
        public static XhttpSettings From(string host, string path, string extraJson)
        {
            var s = new XhttpSettings { Host = AsciiHost(host) };
            Dictionary<string, object> x = null;
            if (!string.IsNullOrWhiteSpace(extraJson))
            {
                try { x = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(extraJson); }
                catch (Exception) { x = null; }
            }
            if (x == null) x = new Dictionary<string, object>();

            string p = path ?? "/";
            int q = p.IndexOf('?');
            if (q >= 0) { s.Query = p.Substring(q + 1); p = p.Substring(0, q); }
            if (!p.StartsWith("/")) p = "/" + p;
            // Xray appends '/' when the session id OR seq placement is "path" (the default); both elsewhere → no slash.
            // (The fields were renamed session* → sessionID* in mid-2026; accept both.)
            string sidPl = (Get(x, "sessionIDPlacement") ?? Get(x, "sessionPlacement")) as string;
            string seqPl = Get(x, "seqPlacement") as string;
            bool slash = string.IsNullOrEmpty(sidPl) || sidPl == "path" || string.IsNullOrEmpty(seqPl) || seqPl == "path";
            if (slash && !p.EndsWith("/")) p += "/";
            s.Path = p;
            if (x.Count == 0) return s;
            if (Get(x, "noGRPCHeader") is bool ng) s.NoGrpcHeader = ng;
            if (Range(Get(x, "scMaxEachPostBytes"), out int mpf, out int mpt) && mpt > 0) { s.MaxPostFrom = mpf; s.MaxPostTo = mpt; }
            if (Range(Get(x, "scMinPostsIntervalMs"), out int mif, out int mit) && mit >= 0) { s.MinIntervalFrom = mif; s.MinIntervalTo = mit; }
            if (Get(x, "uplinkHTTPMethod") is string m && m.Length > 0) s.Method = m.ToUpperInvariant();
            if (Range(Get(x, "xPaddingBytes"), out int pf, out int pt) && pt > 0) { s.PaddingFrom = pf; s.PaddingTo = pt; }
            if (Get(x, "xPaddingObfsMode") is bool obfs && obfs)
            {
                s.PadObfs = true;
                if (Get(x, "xPaddingKey") is string k && k.Length > 0) s.PadKey = k;
                if (Get(x, "xPaddingHeader") is string hd && hd.Length > 0) s.PadHeader = hd;
                if (Get(x, "xPaddingPlacement") is string pl && pl.Length > 0) s.PadPlacement = pl;
                if (Get(x, "xPaddingMethod") is string me && me.Length > 0) s.PadMethod = me;
            }
            if (Get(x, "headers") is Dictionary<string, object> hs)
                foreach (var kv in hs) if (!kv.Key.Equals("host", StringComparison.OrdinalIgnoreCase)) s.Headers.Add(new KeyValuePair<string, string>(kv.Key.ToLowerInvariant(), Convert.ToString(kv.Value, CultureInfo.InvariantCulture)));
            if (Get(x, "xmux") is Dictionary<string, object> mx && mx.Count > 0)
            {
                // Any explicit xmux field disables all three defaults (Xray infra/conf); unset ones mean "unlimited".
                s.ConnFrom = s.ConnTo = 0; s.ReqFrom = s.ReqTo = 0; s.SecsFrom = s.SecsTo = 0;
                if (Range(Get(mx, "maxConnections"), out int a, out int b)) { s.ConnFrom = a; s.ConnTo = b; }
                if (Range(Get(mx, "maxConcurrency"), out a, out b)) { s.ConcFrom = a; s.ConcTo = b; }
                if (Range(Get(mx, "hMaxRequestTimes"), out a, out b)) { s.ReqFrom = a; s.ReqTo = b; }
                if (Range(Get(mx, "hMaxReusableSecs"), out a, out b)) { s.SecsFrom = a; s.SecsTo = b; }
                if (Range(Get(mx, "cMaxReuseTimes"), out a, out b)) { s.ReuseFrom = a; s.ReuseTo = b; }
            }
            return s;
        }

        /// <summary>The Host as Go writes it (httpguts.PunycodeHostPort → idna.ToASCII, the Punycode profile): every
        /// non-ASCII label becomes "xn--" + RFC 3492 Punycode, with no case folding or IDNA mapping (so "straße" stays
        /// "xn--strae-oqa", not "strasse").</summary>
        internal static string AsciiHost(string h)
        {
            h = (h ?? "").Trim();
            bool ascii = true;
            foreach (char c in h) if (c > 127) { ascii = false; break; }
            if (ascii) return h;
            var labels = h.Split('.');
            for (int i = 0; i < labels.Length; i++)
            {
                bool plain = true;
                foreach (char c in labels[i]) if (c > 127) { plain = false; break; }
                if (!plain) labels[i] = "xn--" + Punycode(labels[i]);
            }
            return string.Join(".", labels);
        }

        // RFC 3492 Punycode of one label.
        internal static string Punycode(string label)
        {
            const int Base = 36, TMin = 1, TMax = 26;
            var cps = new List<int>();
            for (int i = 0; i < label.Length; i++)
            {
                if (char.IsHighSurrogate(label[i]) && i + 1 < label.Length && char.IsLowSurrogate(label[i + 1])) { cps.Add(char.ConvertToUtf32(label[i], label[i + 1])); i++; }
                else cps.Add(label[i]);
            }
            var o = new StringBuilder();
            foreach (int cp in cps) if (cp < 0x80) o.Append((char)cp);
            int b = o.Length, h = b;
            if (b > 0) o.Append('-');
            int n = 128, delta = 0, bias = 72;
            while (h < cps.Count)
            {
                int m = int.MaxValue;
                foreach (int cp in cps) if (cp >= n && cp < m) m = cp;
                delta += (m - n) * (h + 1);
                n = m;
                foreach (int cp in cps)
                {
                    if (cp < n) delta++;
                    if (cp != n) continue;
                    int q = delta;
                    for (int k = Base; ; k += Base)
                    {
                        int t = k <= bias ? TMin : k >= bias + TMax ? TMax : k - bias;
                        if (q < t) break;
                        o.Append(PunyDigit(t + (q - t) % (Base - t)));
                        q = (q - t) / (Base - t);
                    }
                    o.Append(PunyDigit(q));
                    bias = PunyAdapt(delta, h + 1, h == b);
                    delta = 0;
                    h++;
                }
                delta++;
                n++;
            }
            return o.ToString();
        }

        private static char PunyDigit(int d) => (char)(d < 26 ? 'a' + d : '0' + d - 26);

        private static int PunyAdapt(int delta, int numPoints, bool first)
        {
            delta = first ? delta / 700 : delta / 2;
            delta += delta / numPoints;
            int k = 0;
            while (delta > ((36 - 1) * 26) / 2) { delta /= 36 - 1; k += 36; }
            return k + (36 - 1 + 1) * delta / (delta + 38);
        }

        private static object Get(Dictionary<string, object> d, string k) => d.TryGetValue(k, out var v) ? v : null;

        // Xray Int32Range: a number, or "A-B" / "A" as a string.
        private static bool Range(object v, out int from, out int to)
        {
            from = to = 0;
            if (v == null) return false;
            if (v is int i) { from = to = i; return true; }
            if (v is decimal dm) { if (dm < int.MinValue || dm > int.MaxValue) return false; from = to = (int)dm; return true; }
            string str = Convert.ToString(v, CultureInfo.InvariantCulture).Trim();
            int dash = str.IndexOf('-', 1 < str.Length ? 1 : 0);
            if (dash > 0)
            {
                bool ok = int.TryParse(str.Substring(0, dash), out from) && int.TryParse(str.Substring(dash + 1), out to);
                if (ok) Order(ref from, ref to);
                return ok;
            }
            if (int.TryParse(str, out from)) { to = from; return true; }
            return false;
        }

        private static void Order(ref int from, ref int to) { if (from > to) { int t = from; from = to; to = t; }
        }

        internal static int Pick(int from, int to) => to <= from ? from : from + Rnd(to - from);

        private static readonly SecureRandom Rng = new SecureRandom();
        internal static int Rnd(int n) { lock (Rng) return n <= 0 ? 0 : Rng.Next(n); }

        /// <summary>Go net/url EscapedPath (encodePath): keep A–Z a–z 0–9 - _ . ~ $ &amp; + , / : ; = @, %XX (uppercase)
        /// every other UTF-8 byte — so the server's decoded path equals ours byte for byte.</summary>
        public static string EscapePath(string path)
        {
            var sb = new StringBuilder();
            foreach (byte b in Encoding.UTF8.GetBytes(path))
            {
                char c = (char)b;
                bool keep = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || "-_.~$&+,/:;=@".IndexOf(c) >= 0;
                if (keep) sb.Append(c); else sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }

        /// <summary>The request headers Xray's client sends for stream-one (its default "chrome" fetch masquerade unless a
        /// custom user-agent is configured), with the mandatory x_padding in the Referer.</summary>
        internal List<HeaderField> RequestHeaders()
        {
            string escaped = EscapePath(Path);
            string pad = MakePadding();
            string query = QueryWithPadding(pad);
            var h = new List<HeaderField>
            {
                // Go's x/net/http2 pseudo-header order
                new HeaderField(":authority", Host),
                new HeaderField(":method", Method),
                new HeaderField(":path", escaped + (query.Length > 0 ? "?" + query : "")),
                new HeaderField(":scheme", "https"),
            };
            SentPath = h[2].Value;
            var regular = RegularHeaders(escaped, pad, grpcContentType: true);
            foreach (var kv in regular)
                if (!(kv.Key == "user-agent" && kv.Value.Length == 0)) h.Add(new HeaderField(kv.Key, kv.Value));   // an explicit empty UA sends none
            // Go's x/net/http2 then adds accept-encoding (when the request has none) and a default UA (when none was set).
            if (!regular.Any(kv => kv.Key == "accept-encoding")) h.Add(new HeaderField("accept-encoding", "gzip"));
            if (!regular.Any(kv => kv.Key == "user-agent")) h.Add(new HeaderField("user-agent", "Go-http-client/2.0"));
            return h;
        }

        /// <summary>The configured query plus, in classic mode (or obfs "query" placement), the padding: classic mode puts it
        /// in the Referer (Xray v25.1.30+) AND the URL query (what servers up to v25.1.1 read) — every version accepts the
        /// pair.</summary>
        internal string QueryWithPadding(string pad)
        {
            string query = Query;
            if (!PadObfs || PadPlacement == "query") query = (query.Length > 0 ? query + "&" : "") + (PadObfs ? PadKey : "x_padding") + "=" + pad;
            return query;
        }

        /// <summary>
        /// The non-pseudo request headers (lowercase names), as Xray's GetRequestHeader builds them: the user's
        /// extra.headers, then the "fetch" masquerade of TryDefaultHeadersWith — the browser profile is chosen by the
        /// User-Agent: none or exactly "chrome", "edge", "firefox", "safari" (browser headers that OVERRIDE the identity
        /// headers and only FILL Priority / Cache-Control / Pragma / Accept), "curl" (its UA only), "golang" (no UA: Go's
        /// default); any other value is sent as it is, with no masquerade (an empty one sends no UA at all) — then the
        /// padding. <paramref name="grpcContentType"/>: the streaming POST of stream-one / stream-up also gets Content-Type.
        /// </summary>
        internal List<KeyValuePair<string, string>> RegularHeaders(string escapedBase, string pad, bool grpcContentType)
        {
            var regular = new List<KeyValuePair<string, string>>();
            Action<string, string> set = (n, v) => { regular.RemoveAll(kv => kv.Key == n); regular.Add(new KeyValuePair<string, string>(n, v)); };
            Action<string, string> fill = (n, v) => { if (!regular.Any(kv => kv.Key == n)) regular.Add(new KeyValuePair<string, string>(n, v)); };
            foreach (var kv in Headers)
                if (!kv.Key.StartsWith(":")) set(kv.Key, kv.Value);
            var ua = regular.Where(kv => kv.Key == "user-agent").Select(kv => kv.Value).FirstOrDefault();
            string profile = ua == null ? "chrome" : ua;   // Xray matches the keyword exactly (case-sensitive, untrimmed)
            switch (profile)
            {
                case "chrome":
                case "edge":
                    bool edge = profile == "edge";
                    set("sec-ch-ua", edge ? BrowserHeaders.EdgeSecChUa : BrowserHeaders.ChromeSecChUa);
                    set("sec-ch-ua-mobile", "?0");
                    set("sec-ch-ua-platform", "\"Windows\"");
                    set("dnt", "1");
                    set("user-agent", edge ? BrowserHeaders.EdgeUserAgent : BrowserHeaders.ChromeUserAgent);
                    set("accept-language", "en-US,en;q=0.9");
                    Fetch(set, fill, "u=1, i");
                    break;
                case "firefox":
                    set("user-agent", BrowserHeaders.FirefoxUserAgent);
                    set("dnt", "1");
                    set("accept-language", "en-US,en;q=0.5");
                    Fetch(set, fill, "u=4");
                    break;
                case "safari":
                    set("user-agent", BrowserHeaders.SafariUserAgent);
                    set("accept-language", "en-US,en;q=0.9");
                    Fetch(set, fill, "u=3, i");
                    break;
                case "golang":
                    regular.RemoveAll(kv => kv.Key == "user-agent");   // Go's own default UA, no other headers
                    break;
                case "curl":
                    set("user-agent", BrowserHeaders.CurlUserAgent);
                    break;
            }
            if (!PadObfs) set("referer", "https://" + Host + escapedBase + "?x_padding=" + pad);
            else
            {
                string ph = PadHeader.ToLowerInvariant();
                switch (PadPlacement)
                {
                    case "cookie":   // Go's AddCookie: appended to a Cookie header the user set
                        string have = regular.Where(kv => kv.Key == "cookie").Select(kv => kv.Value).FirstOrDefault();
                        set("cookie", string.IsNullOrEmpty(have) ? PadKey + "=" + pad : have + "; " + PadKey + "=" + pad);
                        break;
                    case "header": set(ph, pad); break;
                    case "query": break;   // already in the URL query
                    default: set(ph, "https://" + Host + escapedBase + "?" + PadKey + "=" + pad); break;   // queryInHeader
                }
            }
            if (grpcContentType && !NoGrpcHeader) set("content-type", "application/grpc");
            return regular;
        }

        /// <summary>The :path of the last request built (diagnostics for 404/400 answers).</summary>
        internal string SentPath { get; private set; }

        private const string Base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        // Length in [from, to) like Xray's RandBetween. repeat-x = 'X'*n; tokenish = random base62 whose HPACK-Huffman
        // length reaches the target (the server checks the Huffman length within ±2 for tokenish).
        internal string MakePadding()
        {
            int target = PaddingFrom + Rnd(Math.Max(1, PaddingTo - PaddingFrom));
            if (!PadObfs || PadMethod != "tokenish") return new string('X', target);
            var sb = new StringBuilder();
            while (HpackHuffman.EncodedLength(Encoding.ASCII.GetBytes(sb.ToString())) < target) sb.Append(Base62[Rnd(Base62.Length)]);
            return sb.ToString();
        }

        // The "fetch" variant: Sec-Fetch-* set, the rest only when absent.
        private static void Fetch(Action<string, string> set, Action<string, string> fill, string priority)
        {
            set("sec-fetch-mode", "cors");
            set("sec-fetch-dest", "empty");
            set("sec-fetch-site", "same-origin");
            fill("priority", priority);
            fill("cache-control", "no-cache");
            fill("pragma", "no-cache");
            fill("accept", "*/*");
        }
    }

    /// <summary>
    /// Shared HTTP/2 connections for XHTTP (Xray "XMUX"): each VLESS connection becomes one h2 stream; up to
    /// MaxConnections connections per server, each retired after its request budget / age, closed after 300 s idle.
    /// </summary>
    internal static class XhttpPool
    {
        internal sealed class Entry
        {
            public Task<bool> Dial;              // completes when Conn/Tls are set (faulted = dial failed)
            public TaskCompletionSource<bool> DialSource;
            public Http2Connection Conn;
            public ITransport Tls;
            public int Running;
            public int LeftRequests;            // int.MaxValue = unlimited
            public int LeftUsage;               // cMaxReuseTimes budget (int.MaxValue = unlimited)
            public DateTime UnreusableAtUtc;    // MaxValue = unlimited
            public DateTime IdleSinceUtc = DateTime.UtcNow;
            public bool Retired;

            public bool Dialing => Dial != null && !Dial.IsCompleted;
            public bool Usable => !Retired && LeftRequests > 0 && LeftUsage > 0 && DateTime.UtcNow < UnreusableAtUtc
                                  && (Dialing || (Conn != null && !Conn.IsDraining));
            /// <summary>Can take a stream right now (a connection at the server's MAX_CONCURRENT_STREAMS is skipped, not retired).</summary>
            public bool HasRoom => Dialing || (Conn != null && Conn.CanOpenStream);

            public void Close() { try { Conn?.Dispose(); } catch { } try { Tls?.Close(); } catch { } }
        }

        private const int IdleCloseSecs = 300;   // Go IdleConnTimeout as Xray sets it
        private static readonly object Sync = new object();
        private static readonly Dictionary<string, List<Entry>> Pools = new Dictionary<string, List<Entry>>();
        private static readonly Dictionary<string, int[]> Limits = new Dictionary<string, int[]>();   // key → {maxConnections, maxConcurrency}
        private static readonly Timer Sweeper = new Timer(_ => Sweep(), null, 30000, 30000);

        /// <summary>Picks (or dials) a connection for one new stream and counts it as running.</summary>
        public static async Task<Entry> AcquireAsync(string key, XhttpSettings s, Func<CancellationToken, Task<Entry>> dial, CancellationToken ct)
        {
            Entry chosen;
            bool mustDial = false;
            lock (Sync)
            {
                if (!Pools.TryGetValue(key, out var list)) Pools[key] = list = new List<Entry>();
                if (!Limits.TryGetValue(key, out var lim))   // Xray rolls these once per XMUX manager, not per request
                    Limits[key] = lim = new[] { s.ConnTo > 0 ? XhttpSettings.Pick(s.ConnFrom, s.ConnTo) : 0, s.ConcTo > 0 ? XhttpSettings.Pick(s.ConcFrom, s.ConcTo) : 0 };
                int maxConnections = lim[0], maxConcurrency = lim[1];
                foreach (var e in list) if (!e.Usable) e.Retired = true;
                list.RemoveAll(e => { if (e.Retired && e.Running <= 0 && !e.Dialing) { e.Close(); return true; } return false; });
                var live = list.Where(e => !e.Retired).ToList();   // includes connections still dialing (Xray counts them at once)
                var usable = live.Where(e => e.HasRoom).ToList();
                bool wantNew = usable.Count == 0 || (maxConnections > 0 && live.Count < maxConnections);
                if (!wantNew && maxConcurrency > 0)
                {
                    usable = usable.Where(e => e.Running < maxConcurrency).ToList();
                    wantNew = usable.Count == 0;
                }
                if (!wantNew) chosen = usable[XhttpSettings.Rnd(usable.Count)];
                else
                {
                    chosen = new Entry();
                    chosen.LeftRequests = s.ReqTo > 0 ? XhttpSettings.Pick(s.ReqFrom, s.ReqTo) : int.MaxValue;
                    chosen.UnreusableAtUtc = s.SecsTo > 0 ? DateTime.UtcNow.AddSeconds(XhttpSettings.Pick(s.SecsFrom, s.SecsTo)) : DateTime.MaxValue;
                    int reuse = s.ReuseTo > 0 ? XhttpSettings.Pick(s.ReuseFrom, s.ReuseTo) : 0;
                    chosen.LeftUsage = reuse > 0 ? reuse : int.MaxValue;   // Take counts this first use: reuse uses in total
                    var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    chosen.Dial = tcs.Task;
                    chosen.DialSource = tcs;
                    list.Add(chosen);
                    mustDial = true;
                }
                Take(chosen);
            }

            if (mustDial)
            {
                try
                {
                    var made = await dial(ct).ConfigureAwait(false);
                    lock (Sync) { chosen.Conn = made.Conn; chosen.Tls = made.Tls; }
                    chosen.DialSource.TrySetResult(true);
                }
                catch (Exception ex)
                {
                    lock (Sync) chosen.Retired = true;
                    chosen.DialSource.TrySetException(ex);
                    Release(chosen, true);
                    throw;
                }
                return chosen;
            }

            // Sharing a connection another caller is still dialing: wait for it (its failure is ours too).
            try { await chosen.Dial.ConfigureAwait(false); }
            catch { Release(chosen, true); throw; }
            return chosen;
        }

        private static void Take(Entry e)
        {
            e.Running++;
            if (e.LeftRequests != int.MaxValue) e.LeftRequests--;
            if (e.LeftUsage != int.MaxValue) e.LeftUsage--;
        }

        public static void Release(Entry e, bool pooled)
        {
            lock (Sync)
            {
                e.Running--;
                if (e.Running <= 0) e.IdleSinceUtc = DateTime.UtcNow;
                if (!pooled || (e.Running <= 0 && (e.Retired || !e.Usable)))
                {
                    if (e.Running <= 0) { e.Retired = true; e.Close(); foreach (var l in Pools.Values) l.Remove(e); }
                }
            }
        }

        /// <summary>Closes every pooled connection (engine stop / server switch).</summary>
        public static void CloseAll()
        {
            List<Entry> all;
            lock (Sync) { all = Pools.Values.SelectMany(l => l).ToList(); Pools.Clear(); Limits.Clear(); }
            foreach (var e in all) e.Close();
        }

        private static void Sweep()
        {
            var dead = new List<Entry>();
            lock (Sync)
            {
                foreach (var list in Pools.Values)
                    foreach (var e in list)
                        if (e.Running <= 0 && !e.Dialing && (e.Conn == null || e.Conn.IsClosed || !e.Usable || (DateTime.UtcNow - e.IdleSinceUtc).TotalSeconds > IdleCloseSecs))
                            dead.Add(e);
                foreach (var d in dead) foreach (var list in Pools.Values) list.Remove(d);
            }
            foreach (var d in dead) d.Close();
        }
    }

    /// <summary>
    /// VLESS over XHTTP mode stream-one: one HTTP/2 POST per connection on a (pooled) h2 connection over REALITY (or
    /// another TLS 1.3 transport). The request body is the uplink, the response body the downlink — raw VLESS bytes.
    /// </summary>
    public sealed class XhttpStreamOneTransport : ITransport
    {
        private readonly XhttpSettings _s;
        private readonly Func<ITransport> _security;
        private readonly string _poolKey;
        private readonly bool _pooled;
        private XhttpPool.Entry _entry;
        private StreamOneStream _stream;
        private int _released;
        private volatile bool _closed;
        private CancellationTokenSource _connectCts;

        /// <param name="security">Builds the secured transport to the server (e.g. a REALITY Tls13Transport).</param>
        /// <param name="poolKey">Connections are shared between transports with the same key (server + security params).</param>
        /// <param name="pooled">False = a private connection, closed with this transport (delay tests measure a full dial).</param>
        public XhttpStreamOneTransport(XhttpSettings settings, Func<ITransport> security, string poolKey, bool pooled)
        {
            _s = settings; _security = security; _poolKey = poolKey; _pooled = pooled;
        }

        public async Task ConnectAsync(string host, int port, CancellationToken ct)
        {
            Func<CancellationToken, Task<XhttpPool.Entry>> dial = async c =>
            {
                var tls = _security();
                try
                {
                    await tls.ConnectAsync(host, port, c).ConfigureAwait(false);
                    var conn = await Http2Connection.StartAsync(tls.GetStream(), c).ConfigureAwait(false);
                    return new XhttpPool.Entry { Conn = conn, Tls = tls };
                }
                catch { tls.Close(); throw; }
            };
            // A private dial (delay test) is aborted by Close(); a pooled one is shared, so it runs on the caller's token
            // and a Close() meanwhile just hands the entry straight back.
            _connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            if (_closed) _connectCts.Cancel();
            _entry = _pooled ? await XhttpPool.AcquireAsync(_poolKey + "|" + host + ":" + port, _s, dial, ct).ConfigureAwait(false)
                             : await PrivateAsync(dial, _connectCts.Token).ConfigureAwait(false);
            if (_closed) { Release(); throw new OperationCanceledException("XHTTP: closed while connecting"); }
            try
            {
                var headers = _s.RequestHeaders();
                var h2 = await _entry.Conn.OpenStreamAsync(headers, _connectCts.Token).ConfigureAwait(false);
                _stream = new StreamOneStream(h2, Release, _s.Host, Http2Stream.Get(headers, ":path"));
            }
            catch { Release(); throw; }
        }

        private static async Task<XhttpPool.Entry> PrivateAsync(Func<CancellationToken, Task<XhttpPool.Entry>> dial, CancellationToken ct)
        {
            var e = await dial(ct).ConfigureAwait(false);
            e.Running = 1; e.LeftRequests = e.LeftUsage = int.MaxValue; e.UnreusableAtUtc = DateTime.MaxValue;
            e.Dial = Task.FromResult(true);
            return e;
        }

        private void Release()
        {
            var e = _entry;
            if (e == null || Interlocked.Exchange(ref _released, 1) != 0) return;   // nothing acquired yet: ConnectAsync releases later
            XhttpPool.Release(e, _pooled);
        }

        public Stream GetStream()
        {
            if (_stream == null) throw new InvalidOperationException("XhttpStreamOneTransport is not connected.");
            return _stream;
        }

        public void Close()
        {
            _closed = true;
            try { _connectCts?.Cancel(); } catch { }
            try { _stream?.Dispose(); } catch { }
            Release();
        }

        /// <summary>The h2 stream as the VLESS duplex stream: the first read checks the response status.</summary>
        private sealed class StreamOneStream : Stream
        {
            private readonly Http2Stream _h2;
            private readonly Action _onDispose;
            private readonly string _authority, _path;
            private bool _checked;
            private int _disposed;

            public StreamOneStream(Http2Stream h2, Action onDispose, string authority, string path) { _h2 = h2; _onDispose = onDispose; _authority = authority; _path = path; }

            public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
            {
                if (!_checked)
                {
                    if (ct.CanBeCanceled && !_h2.ResponseHeadersAsync.IsCompleted)
                    {
                        var cancelled = new TaskCompletionSource<bool>();
                        using (ct.Register(() => cancelled.TrySetResult(true)))
                            await Task.WhenAny(_h2.ResponseHeadersAsync, cancelled.Task).ConfigureAwait(false);
                        ct.ThrowIfCancellationRequested();
                    }
                    var h = await _h2.ResponseHeadersAsync.ConfigureAwait(false);
                    var err = StatusError(h);
                    if (err != null) throw err;
                    _checked = true;
                }
                return await _h2.ReadAsync(buffer, offset, count, ct).ConfigureAwait(false);
            }

            public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
            {
                try { await _h2.WriteAsync(buffer, offset, count, ct).ConfigureAwait(false); }
                catch (Exception) when (_h2.ResponseHeadersAsync.Status == TaskStatus.RanToCompletion && StatusError(_h2.ResponseHeadersAsync.Result) != null)
                {
                    // An early 4xx ends the stream (Go adds RST_STREAM(NO_ERROR)): report the status, not the reset.
                    throw StatusError(_h2.ResponseHeadersAsync.Result);
                }
            }

            private IOException StatusError(List<HeaderField> h)
            {
                string status = Http2Stream.Get(h, ":status");
                if (status == "200") return null;
                return new IOException("XHTTP: the server answered HTTP " + status +
                    (status == "404" ? " (host or path mismatch — sent :authority " + _authority + ", :path " + Trim(_path) + ")"
                     : status == "400" ? " (padding or mode rejected)" : ""));
            }

            private static string Trim(string s) => s == null ? "" : s.Length > 120 ? s.Substring(0, 120) + "…" : s;
            public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
            public override void Flush() { }
            public override int Read(byte[] b, int o, int c) => ReadAsync(b, o, c, CancellationToken.None).GetAwaiter().GetResult();
            public override void Write(byte[] b, int o, int c) => WriteAsync(b, o, c, CancellationToken.None).GetAwaiter().GetResult();
            public override bool CanRead => true;
            public override bool CanWrite => true;
            public override bool CanSeek => false;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
            public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException();
            public override void SetLength(long v) => throw new NotSupportedException();

            protected override void Dispose(bool disposing)
            {
                if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
                if (disposing) { try { _h2.Dispose(); } catch { } _onDispose(); }
                base.Dispose(disposing);
            }
        }
    }
}

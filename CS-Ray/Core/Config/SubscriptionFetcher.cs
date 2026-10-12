using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace CS_Ray.Core.Config
{
    public sealed class SubFetchResult
    {
        public bool Ok;
        public List<ProxyProfile> Profiles;
        public string Error;
        public string Path; // "direct" / "via-proxy"
    }

    /// <summary>
    /// Fetches a subscription URL and decodes it into profiles. Tries a DIRECT HTTPS GET first; if that fails
    /// and the engine is running, retries THROUGH the engine's local inbound (HTTP proxy at 127.0.0.1:port) so a
    /// filtered sub link can be fetched over a working tunnel. The body is base64 → newline-separated share URIs;
    /// each line is parsed tolerantly (a bad line is skipped + logged, never failing the whole sub).
    /// </summary>
    public static class SubscriptionFetcher
    {
        private const int TimeoutMs = 15000; // sub host may be high-RTT

        private sealed class HttpResult { public bool Ok; public string Body; public string Err; }

        public static async Task<SubFetchResult> FetchAsync(string url, int proxyPort, bool engineRunning, Action<string> log)
        {
            if (string.IsNullOrWhiteSpace(url)) return new SubFetchResult { Ok = false, Error = "empty URL" };
            try { ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12; } catch { }

            var r = await GetAsync(url, null).ConfigureAwait(false); // direct
            string path = "direct";
            if (!r.Ok)
            {
                if (!engineRunning)
                    return new SubFetchResult { Ok = false, Error = "direct fetch failed (" + r.Err + ") — connect to a working server, then update" };
                log?.Invoke("Sub: direct fetch failed (" + r.Err + ") — retrying via engine 127.0.0.1:" + proxyPort + " …");
                r = await GetAsync(url, new WebProxy("127.0.0.1", proxyPort)).ConfigureAwait(false);
                path = "via-proxy";
            }
            if (!r.Ok) return new SubFetchResult { Ok = false, Error = r.Err };

            var profiles = Decode(r.Body, log);
            if (profiles.Count == 0)
            {
                log?.Invoke("Sub: 0 usable servers — response shape: " + DescribeShape(r.Body));
                return new SubFetchResult { Ok = false, Error = "no usable servers decoded (see log for response shape)" };
            }
            return new SubFetchResult { Ok = true, Profiles = profiles, Path = path };
        }

        private static async Task<HttpResult> GetAsync(string url, IWebProxy proxy)
        {
            HttpWebRequest req = null;
            try
            {
                req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = "GET";
                req.Proxy = proxy; // null = direct; WebProxy = via the engine's local HTTP proxy
                // V2Board/SSPanel content-negotiate on User-Agent: a v2rayN-style UA makes them serve base64
                // share-URIs (not Clash YAML / sing-box JSON). Accept-all so we can still handle those formats.
                req.UserAgent = "v2rayN/6.45";
                try { req.Accept = "*/*"; } catch { }
                req.AllowAutoRedirect = true;
                req.Timeout = TimeoutMs;
                req.ReadWriteTimeout = TimeoutMs;

                var respTask = req.GetResponseAsync();
                if (await Task.WhenAny(respTask, Task.Delay(TimeoutMs)).ConfigureAwait(false) != respTask)
                {
                    try { req.Abort(); } catch { }
                    Observe(respTask);
                    return new HttpResult { Ok = false, Err = "timeout" };
                }

                using (var resp = (HttpWebResponse)await respTask.ConfigureAwait(false))
                {
                    if ((int)resp.StatusCode != 200)
                        return new HttpResult { Ok = false, Err = "HTTP " + (int)resp.StatusCode };
                    using (var sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                    {
                        var body = await sr.ReadToEndAsync().ConfigureAwait(false);
                        if (string.IsNullOrWhiteSpace(body)) return new HttpResult { Ok = false, Err = "empty body" };
                        return new HttpResult { Ok = true, Body = body };
                    }
                }
            }
            catch (Exception ex) { try { req?.Abort(); } catch { } return new HttpResult { Ok = false, Err = Brief(ex) }; }
        }

        private static readonly string[] SupportedSs = { "chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm" };

        // Multi-format decode, tried in order: base64→URIs (3x-ui), plain URIs, Clash YAML (V2Board/SSPanel
        // "clash"), sing-box JSON. Tolerant per line/entry — a bad/unsupported one is skipped+logged, never fails
        // the whole sub. Returns ≥1 usable server on success.
        internal static List<ProxyProfile> Decode(string body, Action<string> log)
        {
            string raw = (body ?? "").Trim();
            if (raw.Length == 0) return new List<ProxyProfile>();

            string decoded = TryBase64ToText(raw); // null if not base64

            // 1) base64 of share URIs (the common 3x-ui sub format).
            if (decoded != null && LooksLikeUris(decoded)) return ParseUriLines(decoded, log);
            // 2) plain share URIs (not base64).
            if (LooksLikeUris(raw)) return ParseUriLines(raw, log);
            // 3) Clash YAML (proxies:), raw or base64-wrapped.
            if (LooksLikeYaml(raw)) { var y = DecodeClashYaml(raw, log); if (y.Count > 0) return y; }
            if (decoded != null && LooksLikeYaml(decoded)) { var y = DecodeClashYaml(decoded, log); if (y.Count > 0) return y; }
            // 4) sing-box / JSON, raw or base64-wrapped.
            if (raw.StartsWith("{")) { var j = DecodeSingBox(raw, log); if (j.Count > 0) return j; }
            if (decoded != null && decoded.TrimStart().StartsWith("{")) { var j = DecodeSingBox(decoded, log); if (j.Count > 0) return j; }

            return new List<ProxyProfile>();
        }

        private static List<ProxyProfile> ParseUriLines(string text, Action<string> log)
        {
            var list = new List<ProxyProfile>();
            foreach (var rawl in text.Replace("\r", "").Split('\n'))
            {
                var line = rawl.Trim();
                if (line.Length == 0) continue;
                var res = LinkParser.Parse(line);
                if (res.Ok) list.Add(res.Profile);
                else log?.Invoke("Sub: skipped a line — " + res.Error);
            }
            return list;
        }

        // ── Clash YAML (proxies: list) — minimal, handles the flat fields we support (vmess/vless/ss) ──
        private static List<ProxyProfile> DecodeClashYaml(string text, Action<string> log)
        {
            var list = new List<ProxyProfile>();
            bool inProxies = false;
            List<string> cur = null;
            var blocks = new List<List<string>>();
            int itemIndent = -1;   // indent of the "- " that starts each proxy (YAML allows 0: "proxies:\n- name: a")
            foreach (var rawl in text.Replace("\r", "").Split('\n'))
            {
                if (rawl.Trim().Length == 0) continue;
                int indent = rawl.Length - rawl.TrimStart().Length;
                string t = rawl.TrimStart();
                if (t.StartsWith("#")) continue;
                if (indent == 0 && !t.StartsWith("- "))
                {
                    if (cur != null) { blocks.Add(cur); cur = null; }
                    inProxies = t.StartsWith("proxies:");
                    itemIndent = -1;
                    continue;
                }
                if (!inProxies) continue;
                // A new proxy starts only at the item indent; deeper "- x" lines are nested lists (alpn:, path lists, …).
                if (t.StartsWith("- ") && (itemIndent < 0 || indent == itemIndent))
                {
                    itemIndent = indent;
                    if (cur != null) blocks.Add(cur);
                    cur = new List<string> { t.Substring(2) };
                }
                else if (cur != null) cur.Add(t);
            }
            if (cur != null) blocks.Add(cur);

            foreach (var b in blocks)
            {
                try { var p = ClashProxyToProfile(b, log); if (p != null) list.Add(p); }
                catch (Exception ex) { log?.Invoke("Sub: skipped a YAML proxy — " + ex.Message); }
            }
            return list;
        }

        private static ProxyProfile ClashProxyToProfile(List<string> lines, Action<string> log)
        {
            var kv = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var l0 in lines)
            {
                string l = l0.Trim();
                // "- {name: a, type: vmess, …}" — subconverter's default (flow) style: the whole proxy on one line.
                if (l.StartsWith("{")) { YamlFlow.Flatten(l, kv); continue; }
                int c = l.IndexOf(':');
                if (c <= 0) continue;
                string k = l.Substring(0, c).Trim();
                string raw = l.Substring(c + 1).Trim();
                if (raw.StartsWith("{") || raw.StartsWith("["))
                {
                    // "ws-opts: {path: /v, headers: {Host: h}}" / "alpn: [h2, http/1.1]": leaves join the flat key space.
                    string joined = YamlFlow.Flatten(raw, kv);
                    if (k.Length > 0 && !kv.ContainsKey(k)) kv[k] = joined;
                    continue;
                }
                string v = StripYamlQuotes(StripYamlComment(raw));
                if (k.Length > 0 && !kv.ContainsKey(k)) kv[k] = v; // first wins (path/Host appear once per block)
            }
            string type = Get(kv, "type").ToLowerInvariant();
            string server = Get(kv, "server");
            if (type.Length == 0 || server.Length == 0 || !int.TryParse(Get(kv, "port"), out int port)) return null; // malformed → skip

            string rawNet = Get(kv, "network").ToLowerInvariant();
            string net = (rawNet == "" || rawNet == "tcp" || rawNet == "raw") ? "tcp" : (rawNet == "ws" ? "ws" : rawNet);
            string sni = First(Get(kv, "servername"), Get(kv, "sni"));
            if (sni.Length == 0 && net == "ws") sni = Get(kv, "Host");   // mihomo: a ws server name falls back to the Host header
            string wsHost = First(Get(kv, "Host"), sni, server);
            // ws-opts.v2ray-http-upgrade switches the transport to HTTPUpgrade (no WebSocket framing) — not ws.
            string httpUpgrade = net == "ws" && YamlTrue(Get(kv, "v2ray-http-upgrade")) ? "HTTPUpgrade (v2ray-http-upgrade) — unsupported" : null;
            string wsPath = First(Get(kv, "path"), Get(kv, "ws-path"), "/");   // ws-path: the old flat Clash key
            bool insecure = YamlTrue(Get(kv, "skip-cert-verify"));
            string name = First(Get(kv, "name"), server);
            bool reality = kv.ContainsKey("reality-opts");

            var p = new ProxyProfile { Server = server, Port = port, Name = name, Network = net, Sni = sni, WsPath = wsPath, WsHost = wsHost, AllowInsecure = insecure,
                                       UseTls = YamlTrue(Get(kv, "tls")) || reality };
            string reason = null;
            switch (type)
            {
                case "vmess":
                    p.Protocol = "vmess"; p.Uuid = Get(kv, "uuid"); p.VmessSecurity = First(Get(kv, "cipher"), "auto");
                    if (string.IsNullOrEmpty(p.Uuid)) return null;
                    p.Fingerprint = Get(kv, "client-fingerprint");
                    // alterId is ignored: the engine always speaks AEAD (as Xray's client, which has no alterId, does).
                    reason = reality ? "REALITY (VMess) — unsupported (VLESS only)"
                           : httpUpgrade ?? TransportReason(rawNet) ?? LinkParser.VmessTransportReason(NetType(rawNet));
                    break;
                case "vless":
                    p.Protocol = "vless"; p.Uuid = Get(kv, "uuid");
                    if (string.IsNullOrEmpty(p.Uuid)) return null;
                    string flow = Get(kv, "flow");
                    p.Flow = flow.Length > 0 ? flow : null;
                    if (reality)
                    {
                        // reality-opts: { public-key, short-id } — the flat block parse sees the nested keys too.
                        p.Reality = true; p.RealityPublicKey = Get(kv, "public-key"); p.RealityShortId = Get(kv, "short-id");
                    }
                    p.Fingerprint = Get(kv, "client-fingerprint");
                    reason = httpUpgrade ?? (reality ? RealityReason(p, rawNet, flow)
                           : flow.Length > 0 ? VisionReason(p, rawNet, flow)
                           : TransportReason(rawNet)) ?? LinkParser.EncryptionReason(Get(kv, "encryption"));
                    break;
                case "ss":
                case "shadowsocks":
                    p.Protocol = "shadowsocks"; p.Network = "tcp"; p.SsMethod = Get(kv, "cipher"); p.Password = Get(kv, "password");
                    if (string.IsNullOrEmpty(p.Password)) return null;
                    reason = kv.ContainsKey("plugin") ? "Shadowsocks plugin — unsupported"
                           : (Array.IndexOf(SupportedSs, p.SsMethod) < 0 ? "SS cipher '" + p.SsMethod + "' — unsupported (AEAD only)" : null);
                    break;
                case "trojan":
                    p.Protocol = "trojan"; reason = "Trojan — unsupported by the managed engine";
                    break;
                default:
                    p.Protocol = type; reason = "'" + type + "' — unsupported";
                    break;
            }
            if (reason != null) { p.Unsupported = true; p.UnsupportedReason = reason; }
            return p; // imported either way (supported, or greyed-unsupported)
        }

        // Transport (network) → unsupported reason for the managed engine (null = supported tcp/ws).
        // VLESS + REALITY: same rules as share links (flow none or Vision, valid pbk/sid). XHTTP from Clash/sing-box isn't
        // mapped (mode/extra/path), so it stays unsupported here — the share link of the same server works.
        private static string RealityReason(ProxyProfile p, string rawNet, string flow)
            => (NetType(rawNet) == "xhttp" ? "XHTTP from a Clash/sing-box subscription \u2014 not supported yet (use the vless:// link)" : null)
               ?? LinkParser.UnsupportedReason(NetType(rawNet), "reality", flow, allowXhttp: true, allowReality: true) ?? LinkParser.RealityParamsReason(p);

        // VLESS + a flow without REALITY: XTLS Vision over tls+tcp is supported, anything else isn't.
        private static string VisionReason(ProxyProfile p, string rawNet, string flow)
            => LinkParser.UnsupportedReason(NetType(rawNet), p.UseTls ? "tls" : "none", flow, allowXhttp: true, allowReality: true);

        private static string NetType(string rawNet)
        {
            string n = (rawNet ?? "").ToLowerInvariant();
            return n == "" || n == "raw" ? "tcp" : n == "splithttp" ? "xhttp" : n;
        }

        private static string TransportReason(string rawNet)
        {
            string n = (rawNet ?? "").ToLowerInvariant();
            if (n == "" || n == "tcp" || n == "raw" || n == "ws") return null;
            if (n == "xhttp" || n == "splithttp") return "XHTTP — (pending support)";
            return "'" + n + "' transport — unsupported (only tcp/ws)";
        }

        // ── sing-box JSON (outbounds: array with "type") ──
        private static List<ProxyProfile> DecodeSingBox(string body, Action<string> log)
        {
            var list = new List<ProxyProfile>();
            try
            {
                var root = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 }.Deserialize<Dictionary<string, object>>(body);
                object obArr;
                if (root == null || !root.TryGetValue("outbounds", out obArr)) return list;
                var arr = obArr as IEnumerable;
                if (arr == null) return list;
                foreach (var o in arr)
                {
                    try { var p = SingBoxToProfile(o as Dictionary<string, object>, log); if (p != null) list.Add(p); }
                    catch (Exception ex) { log?.Invoke("Sub: skipped a JSON outbound — " + ex.Message); }
                }
            }
            catch (Exception ex) { log?.Invoke("Sub: JSON parse error — " + ex.Message); }
            return list;
        }

        private static ProxyProfile SingBoxToProfile(Dictionary<string, object> d, Action<string> log)
        {
            if (d == null) return null;
            string type = JStr(d, "type").ToLowerInvariant();
            if (type.Length == 0 || type == "direct" || type == "block" || type == "dns" || type == "selector" || type == "urltest") return null;
            string server = JStr(d, "server");
            int port = JInt(d, "server_port");
            if (server.Length == 0 || port <= 0) return null;

            string rawNet = "tcp", wsPath = "/", wsHost = "";
            var transport = JObj(d, "transport");
            string ttype = transport != null ? JStr(transport, "type").ToLowerInvariant() : "";
            if (ttype == "ws")
            {
                rawNet = "ws"; wsPath = First(JStr(transport, "path"), "/");
                var headers = JObj(transport, "headers");
                if (headers != null) wsHost = JFirst(headers, "Host");   // a string or a list (first value is used)
            }
            else if (ttype.Length > 0) rawNet = ttype; // http/grpc/httpupgrade/quic → unsupported below
            string sni = ""; bool insecure = false, reality = false;
            var tls = JObj(d, "tls");
            if (tls != null) { sni = JStr(tls, "server_name"); insecure = JBool(tls, "insecure"); reality = JObj(tls, "reality") != null; }
            if (wsHost.Length == 0) wsHost = First(sni, server);

            string net = (rawNet == "tcp" || rawNet == "ws") ? rawNet : "tcp";
            string flow = JStr(d, "flow");
            string name = First(JStr(d, "tag"), server);
            var p = new ProxyProfile { Server = server, Port = port, Name = name, Network = net, Sni = sni, WsPath = wsPath, WsHost = wsHost, AllowInsecure = insecure,
                                       UseTls = tls != null && (JBool(tls, "enabled") || reality) };
            string reason = null;
            switch (type)
            {
                case "vmess":
                    p.Protocol = "vmess"; p.Uuid = JStr(d, "uuid"); p.VmessSecurity = First(JStr(d, "security"), "auto");
                    if (string.IsNullOrEmpty(p.Uuid)) return null;
                    // alter_id is ignored: the engine always speaks AEAD (as Xray's client, which has no alterId, does).
                    reason = reality ? "REALITY (VMess) — unsupported (VLESS only)"
                           : TransportReason(rawNet) ?? LinkParser.VmessTransportReason(NetType(rawNet));
                    break;
                case "vless":
                    p.Protocol = "vless"; p.Uuid = JStr(d, "uuid");
                    if (string.IsNullOrEmpty(p.Uuid)) return null;
                    p.Flow = flow.Length > 0 ? flow : null;
                    if (reality)
                    {
                        var ro = JObj(tls, "reality");
                        p.Reality = true; p.RealityPublicKey = JStr(ro, "public_key"); p.RealityShortId = JStr(ro, "short_id");
                    }
                    var utls = JObj(tls, "utls");
                    p.Fingerprint = utls != null ? JStr(utls, "fingerprint") : null;
                    reason = reality ? RealityReason(p, rawNet, flow)
                           : flow.Length > 0 ? VisionReason(p, rawNet, flow)
                           : TransportReason(rawNet);
                    break;
                case "shadowsocks":
                    p.Protocol = "shadowsocks"; p.Network = "tcp"; p.SsMethod = JStr(d, "method"); p.Password = JStr(d, "password");
                    if (string.IsNullOrEmpty(p.Password)) return null;
                    reason = Array.IndexOf(SupportedSs, p.SsMethod) < 0 ? "SS method '" + p.SsMethod + "' — unsupported (AEAD only)" : null;
                    break;
                case "trojan":
                    p.Protocol = "trojan"; reason = "Trojan — unsupported by the managed engine";
                    break;
                case "hysteria":
                case "hysteria2":
                case "tuic":
                    p.Protocol = type; reason = type + " — needs native core, unsupported";
                    break;
                default:
                    p.Protocol = type; reason = "'" + type + "' — unsupported";
                    break;
            }
            if (reason != null) { p.Unsupported = true; p.UnsupportedReason = reason; }
            return p;
        }

        // ── helpers ──
        private static string DescribeShape(string body)
        {
            string t = (body ?? "").Trim();
            string head = (t.Length > 200 ? t.Substring(0, 200) : t).Replace("\r", " ").Replace("\n", " ");
            string b64 = TryBase64ToText(t) != null ? "base64-decodable" : "not-base64";
            string kind = t.StartsWith("{") ? "JSON"
                        : LooksLikeYaml(t) ? "Clash-YAML"
                        : LooksLikeUris(t) ? "URI-lines"
                        : (TryBase64ToText(t) != null ? "base64-of-something" : "unknown");
            return "len=" + t.Length + ", " + kind + ", " + b64 + ", first200=[" + head + "]";
        }

        private static string TryBase64ToText(string s)
        {
            try
            {
                string x = s.Replace("\r", "").Replace("\n", "").Replace("\t", "").Replace(" ", "").Replace('-', '+').Replace('_', '/');
                switch (x.Length % 4) { case 2: x += "=="; break; case 3: x += "="; break; case 1: return null; }
                var bytes = Convert.FromBase64String(x);
                var text = Encoding.UTF8.GetString(bytes);
                // Reject "decoded" garbage: require it to look like text we care about.
                return (LooksLikeUris(text) || LooksLikeYaml(text) || text.TrimStart().StartsWith("{")) ? text : null;
            }
            catch { return null; }
        }

        private static bool LooksLikeUris(string s)
            => s.IndexOf("vless://", StringComparison.OrdinalIgnoreCase) >= 0
            || s.IndexOf("vmess://", StringComparison.OrdinalIgnoreCase) >= 0
            || s.IndexOf("ss://", StringComparison.OrdinalIgnoreCase) >= 0
            || s.IndexOf("trojan://", StringComparison.OrdinalIgnoreCase) >= 0;

        private static bool LooksLikeYaml(string s)
            => s.IndexOf("proxies:", StringComparison.OrdinalIgnoreCase) >= 0;

        // YAML 1.1 / Clash booleans: true / yes / on, any case.
        private static bool YamlTrue(string v)
        {
            v = (v ?? "").Trim();
            return v.Equals("true", StringComparison.OrdinalIgnoreCase) || v.Equals("yes", StringComparison.OrdinalIgnoreCase)
                || v.Equals("on", StringComparison.OrdinalIgnoreCase);
        }

        // "value # note" → "value" (a quoted value keeps its '#').
        private static string StripYamlComment(string v)
        {
            if (v.Length > 0 && (v[0] == '"' || v[0] == '\'')) return v;
            int h = v.IndexOf(" #", StringComparison.Ordinal);
            return h >= 0 ? v.Substring(0, h).TrimEnd() : v;
        }

        private static string StripYamlQuotes(string v)
        {
            if (v.Length >= 2 && ((v[0] == '"' && v[v.Length - 1] == '"') || (v[0] == '\'' && v[v.Length - 1] == '\'')))
                return v.Substring(1, v.Length - 2);
            return v;
        }

        private static string Get(Dictionary<string, string> kv, string key) => kv.TryGetValue(key, out var v) ? (v ?? "") : "";
        private static string First(params string[] vals) { foreach (var v in vals) if (!string.IsNullOrEmpty(v)) return v; return ""; }

        private static string JStr(Dictionary<string, object> d, string k) => d != null && d.TryGetValue(k, out var v) && v != null ? v.ToString() : "";
        // A value that may be a string or a list of strings (sing-box header values): the first one.
        private static string JFirst(Dictionary<string, object> d, string k)
        {
            if (d == null || !d.TryGetValue(k, out var v) || v == null) return "";
            if (v is System.Collections.IEnumerable list && !(v is string) && !(v is System.Collections.IDictionary))
            {
                foreach (var x in list) if (x != null && x.ToString().Length > 0) return x.ToString();
                return "";
            }
            return v.ToString();
        }
        private static int JInt(Dictionary<string, object> d, string k) { try { return d != null && d.TryGetValue(k, out var v) && v != null ? Convert.ToInt32(v) : 0; } catch { return 0; } }
        private static bool JBool(Dictionary<string, object> d, string k) { try { return d != null && d.TryGetValue(k, out var v) && v != null && Convert.ToBoolean(v); } catch { return false; } }
        private static Dictionary<string, object> JObj(Dictionary<string, object> d, string k) => d != null && d.TryGetValue(k, out var v) ? v as Dictionary<string, object> : null;

        private static string Brief(Exception ex)
        {
            var m = ex.Message;
            if (ex is WebException we && we.Response is HttpWebResponse hr) m = "HTTP " + (int)hr.StatusCode;
            return m.Length > 80 ? m.Substring(0, 80) + "…" : m;
        }

        private static void Observe(Task t)
        {
            t.ContinueWith(x => { var _ = x.Exception; },
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
        }
    }
}

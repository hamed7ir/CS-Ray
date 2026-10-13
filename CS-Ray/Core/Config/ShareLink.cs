using System;
using System.Collections.Generic;
using System.Text;
using System.Web.Script.Serialization;

namespace CS_Ray.Core.Config
{
    /// <summary>
    /// Builds a share link from a profile: the reverse of <see cref="LinkParser"/>, so a link it makes parses back to
    /// the same server. VLESS uses the Xray-standard URI, VMess the v2rayN base64 JSON (the form every client reads),
    /// Shadowsocks SIP002, socks / http(s) a plain URI with user:pass. A server the engine can't run is not shared: the
    /// importer kept only what the engine needs, so a link rebuilt from it could silently miss settings.
    /// </summary>
    public static class ShareLink
    {
        /// <summary>The link for <paramref name="p"/>, or null with <paramref name="reason"/> saying why not.</summary>
        public static string Build(ProxyProfile p, out string reason)
        {
            reason = null;
            if (p == null) { reason = "No server selected."; return null; }
            if (p.Unsupported)
            {
                reason = "CS-Ray can't run this server, so it didn't keep all of its settings. Share the original link instead.";
                return null;
            }
            if (string.IsNullOrWhiteSpace(p.Server) || p.Port <= 0 || p.Port > 65535) { reason = "This server has no address or port."; return null; }
            switch (p.Protocol)
            {
                case "vless": return Vless(p);
                case "vmess": return Vmess(p);
                case "shadowsocks": return Ss(p);
                case "socks": return Proxy(p, "socks");
                case "http": return Proxy(p, "http");
                case "https": return Proxy(p, "https");
                default: reason = "Sharing " + (p.Protocol ?? "this kind of") + " servers isn't supported."; return null;
            }
        }

        // vless://id@host:port?encryption=none&security=…&type=…#name
        private static string Vless(ProxyProfile p)
        {
            var q = new List<KeyValuePair<string, string>>();
            void Add(string k, string v) { if (!string.IsNullOrEmpty(v)) q.Add(new KeyValuePair<string, string>(k, v)); }

            string net = Net(p);
            Add("encryption", "none");
            Add("security", p.Reality ? "reality" : p.UseTls ? "tls" : "none");
            if (p.UseTls || p.Reality)
            {
                Add("sni", p.Sni);
                Add("fp", p.Fingerprint);
                if (p.AllowInsecure && !p.Reality) Add("allowInsecure", "1");
            }
            if (p.Reality)
            {
                Add("pbk", p.RealityPublicKey);
                Add("sid", p.RealityShortId);
                Add("spx", p.SpiderX);
            }
            Add("type", net);
            AddTransport(p, net, Add);
            Add("flow", p.Flow);
            return "vless://" + Esc(p.Uuid?.Trim()) + "@" + HostPart(p.Server) + ":" + p.Port + "?" + Query(q) + Fragment(p);
        }

        private static void AddTransport(ProxyProfile p, string net, Action<string, string> add)
        {
            switch (net)
            {
                case "ws":
                    add("host", p.WsHost);
                    add("path", string.IsNullOrEmpty(p.WsPath) ? "/" : p.WsPath);
                    break;
                case "xhttp":
                    add("host", p.WsHost);
                    add("path", string.IsNullOrEmpty(p.WsPath) ? "/" : p.WsPath);
                    add("mode", p.XhttpMode);
                    add("extra", p.XhttpExtra);
                    break;
                case "tcp":
                    if (IsHttpHeader(p))
                    {
                        add("headerType", "http");
                        add("host", p.WsHost);
                        add("path", string.IsNullOrEmpty(p.WsPath) ? "/" : p.WsPath);
                    }
                    break;
            }
        }

        // v2rayN: vmess://base64({"v":"2","ps":…,"add":…,"port":"443","id":…,"aid":"0","scy":…,"net":…,"type":…,…})
        private static string Vmess(ProxyProfile p)
        {
            string net = Net(p);
            string type = net == "tcp" ? (IsHttpHeader(p) ? "http" : "none")
                        : net == "xhttp" ? (string.IsNullOrEmpty(p.XhttpMode) ? "auto" : p.XhttpMode)
                        : "none";
            var d = new Dictionary<string, object>
            {
                { "v", "2" },
                { "ps", DisplayName(p) },
                { "add", Unbracket(p.Server.Trim()) },
                { "port", p.Port.ToString() },
                { "id", p.Uuid?.Trim() ?? "" },
                { "aid", "0" },
                { "scy", string.IsNullOrEmpty(p.VmessSecurity) ? "auto" : p.VmessSecurity },
                { "net", net },
                { "type", type },
                { "host", (net == "tcp" && !IsHttpHeader(p)) ? "" : p.WsHost ?? "" },
                { "path", (net == "tcp" && !IsHttpHeader(p)) ? "" : string.IsNullOrEmpty(p.WsPath) ? "/" : p.WsPath },
                { "tls", p.UseTls ? "tls" : "" },
                { "sni", p.UseTls ? p.Sni ?? "" : "" },
                { "alpn", "" },
                { "fp", p.UseTls ? p.Fingerprint ?? "" : "" },
            };
            if (p.UseTls && p.AllowInsecure) d["insecure"] = "1";
            if (net == "xhttp" && !string.IsNullOrWhiteSpace(p.XhttpExtra))
            {
                // A JSON object goes in as an object (what other clients expect); anything else as the raw string.
                object extra;
                try { extra = new JavaScriptSerializer().DeserializeObject(p.XhttpExtra); } catch (Exception) { extra = null; }
                d["extra"] = extra is Dictionary<string, object> ? extra : p.XhttpExtra;
            }
            string json = new JavaScriptSerializer().Serialize(d);
            return "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
        }

        // SIP002: ss://base64url(method:password)@host:port#name
        private static string Ss(ProxyProfile p)
        {
            string userinfo = Convert.ToBase64String(Encoding.UTF8.GetBytes((p.SsMethod ?? "") + ":" + (p.Password ?? "")))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return "ss://" + userinfo + "@" + HostPart(p.Server) + ":" + p.Port + Fragment(p);
        }

        // socks://user:pass@host:port#name (http / https alike)
        private static string Proxy(ProxyProfile p, string scheme)
        {
            string auth = "";
            if (!string.IsNullOrEmpty(p.ProxyUser) || !string.IsNullOrEmpty(p.ProxyPass))
                auth = Esc(p.ProxyUser ?? "") + (string.IsNullOrEmpty(p.ProxyPass) ? "" : ":" + Esc(p.ProxyPass)) + "@";
            return scheme + "://" + auth + HostPart(p.Server) + ":" + p.Port + Fragment(p);
        }

        // ---------------- helpers ----------------

        private static string Net(ProxyProfile p)
        {
            string n = (p.Network ?? "tcp").Trim().ToLowerInvariant();
            if (n == "" || n == "raw") return "tcp";
            if (n == "splithttp") return "xhttp";
            return n;
        }

        private static bool IsHttpHeader(ProxyProfile p)
            => Net(p) == "tcp" && string.Equals(p.HeaderType, "http", StringComparison.OrdinalIgnoreCase);

        private static string DisplayName(ProxyProfile p)
            => !string.IsNullOrWhiteSpace(p.Name) ? p.Name.Trim() : Unbracket(p.Server.Trim()) + ":" + p.Port;

        private static string Fragment(ProxyProfile p) => "#" + Esc(DisplayName(p));

        // An IPv6 literal goes in brackets in a URI (the parser may already have kept them).
        private static string HostPart(string host)
        {
            host = (host ?? "").Trim();
            return host.IndexOf(':') >= 0 && !host.StartsWith("[") ? "[" + host + "]" : host;
        }

        private static string Unbracket(string host)
            => host.Length > 1 && host[0] == '[' && host[host.Length - 1] == ']' ? host.Substring(1, host.Length - 2) : host;

        private static string Query(List<KeyValuePair<string, string>> q)
        {
            var sb = new StringBuilder();
            foreach (var kv in q)
            {
                if (sb.Length > 0) sb.Append('&');
                sb.Append(kv.Key).Append('=').Append(Esc(kv.Value));
            }
            return sb.ToString();
        }

        // RFC 3986 escaping (.NET 4.5+: only A-Z a-z 0-9 - _ . ~ stay as they are).
        private static string Esc(string s) => string.IsNullOrEmpty(s) ? "" : Uri.EscapeDataString(s);
    }
}

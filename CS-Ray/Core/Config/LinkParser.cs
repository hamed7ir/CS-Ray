using System;
using System.Collections.Generic;
using System.Text;
using System.Web.Script.Serialization;

namespace CS_Ray.Core.Config
{
    /// <summary>Result of parsing a share link: either a profile, or a specific error message.</summary>
    public class ParseResult
    {
        public ProxyProfile Profile;
        public string Error;
        public bool Ok => Error == null;

        public static ParseResult Fail(string error) => new ParseResult { Error = error };
        public static ParseResult Success(ProxyProfile p) => new ParseResult { Profile = p };
    }

    /// <summary>
    /// Parses vless:// / vmess:// / ss:// share links into a <see cref="ProxyProfile"/>.
    /// Rejects (with a specific reason) anything the managed engine can't run — non tcp/ws
    /// transports, Reality/XTLS, legacy VMess (alterId>0), and non-AEAD Shadowsocks ciphers.
    /// Never throws on a bad link; returns a <see cref="ParseResult"/> carrying the reason.
    /// </summary>
    public static class LinkParser
    {
        private static readonly HashSet<string> AeadSsMethods = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305"
        };

        public static ParseResult Parse(string link)
        {
            if (string.IsNullOrWhiteSpace(link)) return ParseResult.Fail("Empty link.");
            link = link.Trim();

            try
            {
                if (link.StartsWith("vless://", StringComparison.OrdinalIgnoreCase)) return ParseVless(link);
                if (link.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase)) return ParseVmess(link);
                if (link.StartsWith("ss://", StringComparison.OrdinalIgnoreCase)) return ParseSs(link);
                // Plain proxy outbounds (connect THROUGH a socks5/http proxy).
                if (link.StartsWith("socks5://", StringComparison.OrdinalIgnoreCase) || link.StartsWith("socks://", StringComparison.OrdinalIgnoreCase))
                    return ParseProxy(link, "socks");
                if (link.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return ParseProxy(link, "https");
                if (link.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return ParseProxy(link, "http");
                // Recognized-but-unsupported native-core protocols: import (greyed) so the user sees them.
                if (link.StartsWith("hysteria2://", StringComparison.OrdinalIgnoreCase) || link.StartsWith("hy2://", StringComparison.OrdinalIgnoreCase))
                    return GenericUnsupported(link, "hysteria2", "Hysteria2 — needs native core, unsupported");
                if (link.StartsWith("hysteria://", StringComparison.OrdinalIgnoreCase))
                    return GenericUnsupported(link, "hysteria", "Hysteria — needs native core, unsupported");
                if (link.StartsWith("tuic://", StringComparison.OrdinalIgnoreCase))
                    return GenericUnsupported(link, "tuic", "TUIC — needs native core, unsupported");
                if (link.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase))
                    return GenericUnsupported(link, "trojan", "Trojan — unsupported by the managed engine");
                return ParseResult.Fail("Unrecognized scheme (expected vless://, vmess://, ss://).");
            }
            catch (Exception ex)
            {
                return ParseResult.Fail("Malformed link: " + ex.Message);
            }
        }

        // Tag an otherwise-parsed profile as recognized-but-unsupported (imported greyed, can't start).
        private static ParseResult Unsupported(ProxyProfile p, string reason)
        {
            p.Unsupported = true;
            p.UnsupportedReason = reason;
            return ParseResult.Success(p);
        }

        // Best-effort host/port/name for a scheme our engine can't run at all (hysteria/tuic/trojan).
        private static ParseResult GenericUnsupported(string link, string proto, string reason)
        {
            try
            {
                var uri = new Uri(link);
                string name = Uri.UnescapeDataString(uri.Fragment.TrimStart('#'));
                var p = new ProxyProfile
                {
                    Protocol = proto,
                    Server = uri.Host,
                    Port = uri.Port > 0 ? uri.Port : 0,
                    Name = string.IsNullOrEmpty(name) ? uri.Host : name
                };
                return Unsupported(p, reason);
            }
            catch (Exception ex) { return ParseResult.Fail("Malformed " + proto + " link: " + ex.Message); }
        }

        // ---------------- VLESS ----------------
        // vless://uuid@host:port?type=&security=&sni=&host=&path=&flow=#name
        private static ParseResult ParseVless(string link)
        {
            var uri = new Uri(link);
            var q = ParseQuery(uri.Query);

            var p = new ProxyProfile
            {
                Protocol = "vless",
                Uuid = Uri.UnescapeDataString(uri.UserInfo),
                Server = uri.Host,
                Port = uri.Port,
                Name = Uri.UnescapeDataString(uri.Fragment.TrimStart('#')),
                Sni = Get(q, "sni"),
                WsHost = Get(q, "host"),
                WsPath = string.IsNullOrEmpty(Get(q, "path")) ? "/" : Get(q, "path"),
                AllowInsecure = Get(q, "allowInsecure") == "1" || string.Equals(Get(q, "allowInsecure"), "true", StringComparison.OrdinalIgnoreCase)
            };

            var type = NormalizeNetwork(Get(q, "type"));
            p.Network = type; // keep the real transport for display even when unsupported
            var security = (Get(q, "security") ?? "").ToLowerInvariant();
            var flow = Get(q, "flow");
            p.UseTls = security == "tls" || security == "reality";
            if (string.IsNullOrEmpty(p.Sni) && !string.IsNullOrEmpty(p.WsHost)) p.Sni = p.WsHost;

            string reason = UnsupportedReason(type, security, flow, allowXhttp: true); // VLESS supports xhttp (packet-up)
            return reason != null ? Unsupported(p, reason) : ParseResult.Success(p);
        }

        // Recognized-but-unsupported reason for a vless/vmess transport+security combo (null = supported).
        // VLESS supports xhttp over TLS (packet-up); VMess does not (engine VMess is raw-TCP only).
        private static string UnsupportedReason(string type, string security, string flow, bool allowXhttp)
        {
            if (security == "reality") return "REALITY — needs native core, unsupported";
            if (!string.IsNullOrEmpty(flow)) return "XTLS flow '" + flow + "' — unsupported";
            if (type == "xhttp")
            {
                if (!allowXhttp) return "XHTTP (VMess) — unsupported by the managed engine";
                return security == "tls" ? null : "XHTTP requires TLS — unsupported";
            }
            if (type != "tcp" && type != "ws") return "'" + type + "' transport — unsupported (only tcp/ws)";
            return null;
        }

        // ---------------- VMESS ----------------
        // vmess://base64( { add, port, id, aid, scy, net, type, host, path, tls, sni, ps } )
        private static ParseResult ParseVmess(string link)
        {
            var json = Encoding.UTF8.GetString(DecodeBase64(link.Substring("vmess://".Length)));
            var d = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(json);
            string S(string k) => d != null && d.ContainsKey(k) && d[k] != null ? d[k].ToString() : null;

            int aid = 0; int.TryParse(S("aid"), out aid);
            int port; int.TryParse(S("port"), out port);
            var net = NormalizeNetwork(S("net"));
            var tls = (S("tls") ?? "").ToLowerInvariant();

            var p = new ProxyProfile
            {
                Protocol = "vmess",
                Uuid = S("id"),
                Server = S("add"),
                Port = port,
                Name = S("ps"),
                Network = net,
                WsHost = S("host"),
                WsPath = string.IsNullOrEmpty(S("path")) ? "/" : S("path"),
                Sni = S("sni"),
                UseTls = tls == "tls" || tls == "reality",
                VmessSecurity = string.IsNullOrEmpty(S("scy")) ? "auto" : S("scy")
            };
            if (string.IsNullOrEmpty(p.Sni) && !string.IsNullOrEmpty(p.WsHost)) p.Sni = p.WsHost;

            string reason = aid > 0 ? "VMess alterId>0 (legacy/non-AEAD) — unsupported" : UnsupportedReason(net, tls, null, allowXhttp: false);
            return reason != null ? Unsupported(p, reason) : ParseResult.Success(p);
        }

        // ---------------- SHADOWSOCKS ----------------
        // SIP002: ss://base64url(method:password)@host:port#name
        // Legacy: ss://base64(method:password@host:port)#name
        private static ParseResult ParseSs(string link)
        {
            var rest = link.Substring("ss://".Length);

            string name = null;
            int hash = rest.IndexOf('#');
            if (hash >= 0) { name = Uri.UnescapeDataString(rest.Substring(hash + 1)); rest = rest.Substring(0, hash); }

            string query = null;
            int qm = rest.IndexOf('?');
            if (qm >= 0) { query = rest.Substring(qm + 1); rest = rest.Substring(0, qm); }
            bool hasPlugin = !string.IsNullOrEmpty(query) && query.IndexOf("plugin", StringComparison.OrdinalIgnoreCase) >= 0;

            string method, password, host; int port;
            int at = rest.LastIndexOf('@');
            if (at >= 0)
            {
                // SIP002: base64url(method:password) @ host:port  (userinfo may also be plain method:password)
                var userinfo = rest.Substring(0, at);
                var hostport = rest.Substring(at + 1);
                string mp;
                try { mp = Encoding.UTF8.GetString(DecodeBase64(userinfo)); }
                catch { mp = Uri.UnescapeDataString(userinfo); }
                if (!SplitMethodPassword(mp, out method, out password))
                    return ParseResult.Fail("Could not parse Shadowsocks method:password.");
                if (!SplitHostPort(hostport, out host, out port))
                    return ParseResult.Fail("Could not parse Shadowsocks host:port.");
            }
            else
            {
                // Legacy: base64(method:password@host:port)
                var dec = Encoding.UTF8.GetString(DecodeBase64(rest));
                int at2 = dec.LastIndexOf('@');
                if (at2 < 0) return ParseResult.Fail("Malformed legacy ss link (missing '@').");
                if (!SplitMethodPassword(dec.Substring(0, at2), out method, out password))
                    return ParseResult.Fail("Could not parse Shadowsocks method:password.");
                if (!SplitHostPort(dec.Substring(at2 + 1), out host, out port))
                    return ParseResult.Fail("Could not parse Shadowsocks host:port.");
            }

            var p = new ProxyProfile
            {
                Protocol = "shadowsocks",
                Server = host,
                Port = port,
                SsMethod = method.ToLowerInvariant(),
                Password = password,
                Name = name,
                Network = "tcp"
            };
            if (hasPlugin) return Unsupported(p, "Shadowsocks plugin (e.g. v2ray-plugin) — unsupported");
            if (!AeadSsMethods.Contains(method))
                return Unsupported(p, "SS cipher '" + method + "' — unsupported (AEAD only)");
            return ParseResult.Success(p);
        }

        // ---------------- SOCKS5 / HTTP(S) outbound proxies ----------------
        // socks://[user:pass@]host:port#name  |  http(s)://[user:pass@]host:port#name
        private static ParseResult ParseProxy(string link, string proto)
        {
            var uri = new Uri(link);
            if (string.IsNullOrEmpty(uri.Host)) return ParseResult.Fail("Malformed " + proto + " link (no host).");

            string user = null, pass = null;
            var ui = uri.UserInfo;
            if (!string.IsNullOrEmpty(ui))
            {
                int c = ui.IndexOf(':');
                if (c >= 0) { user = Uri.UnescapeDataString(ui.Substring(0, c)); pass = Uri.UnescapeDataString(ui.Substring(c + 1)); }
                else user = Uri.UnescapeDataString(ui);
            }
            int port = uri.Port;
            if (port <= 0) port = proto == "https" ? 443 : proto == "http" ? 80 : 1080;
            string name = Uri.UnescapeDataString(uri.Fragment.TrimStart('#'));
            if (string.IsNullOrEmpty(name)) name = uri.Host;

            return ParseResult.Success(new ProxyProfile
            {
                Protocol = proto,
                Server = uri.Host,
                Port = port,
                Name = name,
                ProxyUser = user,
                ProxyPass = pass,
                Network = "tcp"
            });
        }

        // ---------------- helpers ----------------

        // xray uses "raw" as the new name for plain TCP; treat it as tcp. splithttp is the old name for xhttp.
        private static string NormalizeNetwork(string net)
        {
            net = (net ?? "tcp").Trim().ToLowerInvariant();
            if (net == "" || net == "raw" || net == "tcp") return "tcp";
            if (net == "splithttp") return "xhttp";
            return net;
        }

        private static bool SplitMethodPassword(string mp, out string method, out string password)
        {
            method = password = null;
            int c = mp.IndexOf(':');
            if (c < 0) return false;
            method = mp.Substring(0, c);
            password = mp.Substring(c + 1);
            return true;
        }

        private static bool SplitHostPort(string hostport, out string host, out int port)
        {
            host = null; port = 0;
            int c = hostport.LastIndexOf(':');
            if (c < 0) return false;
            host = hostport.Substring(0, c);
            return int.TryParse(hostport.Substring(c + 1), out port);
        }

        private static Dictionary<string, string> ParseQuery(string query)
        {
            var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(query)) return d;
            foreach (var part in query.TrimStart('?').Split('&'))
            {
                if (part.Length == 0) continue;
                int eq = part.IndexOf('=');
                if (eq < 0) d[Uri.UnescapeDataString(part)] = "";
                else d[Uri.UnescapeDataString(part.Substring(0, eq))] = Uri.UnescapeDataString(part.Substring(eq + 1));
            }
            return d;
        }

        private static string Get(Dictionary<string, string> q, string key)
            => q.TryGetValue(key, out var v) ? v : null;

        // Base64 that tolerates URL-safe alphabet and missing padding.
        private static byte[] DecodeBase64(string s)
        {
            s = s.Trim().Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
            return Convert.FromBase64String(s);
        }
    }
}

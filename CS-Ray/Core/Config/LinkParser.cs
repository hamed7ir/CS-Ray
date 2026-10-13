using System;
using System.Collections.Generic;
using System.Linq;
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
    /// Tags (with a specific reason) anything the managed engine can't run — e.g. grpc / h2 / kcp transports,
    /// VMess over REALITY, unsupported XTLS flows or XHTTP modes, and non-AEAD Shadowsocks ciphers.
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
                if (link.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
                    return IsStandardVmess(link) ? ParseVmessStandard(link) : ParseVmess(link);
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
            if (type == "xhttp")
            {
                p.XhttpMode = Get(q, "mode");
                p.XhttpExtra = Get(q, "extra");
            }
            var security = (Get(q, "security") ?? "").ToLowerInvariant();
            var flow = Get(q, "flow");
            p.Flow = string.IsNullOrEmpty(flow) ? null : flow;
            p.Fingerprint = Get(q, "fp");   // REALITY and tls+Vision hellos
            p.UseTls = security == "tls" || security == "reality";
            if (security == "reality")
            {
                p.Reality = true;
                p.RealityPublicKey = Get(q, "pbk");
                p.RealityShortId = Get(q, "sid");
                p.SpiderX = Get(q, "spx");
            }
            if (type == "tcp" && string.Equals(Get(q, "headerType"), "http", StringComparison.OrdinalIgnoreCase))
                p.HeaderType = "http";   // tcp http-header camouflage (host= / path= are its Host / path lists)
            if (string.IsNullOrEmpty(p.Sni) && !string.IsNullOrEmpty(p.WsHost)) p.Sni = FirstOfList(p.WsHost);

            string reason = UnsupportedReason(type, security, flow, allowXhttp: true, allowReality: true) // VLESS: xhttp (packet-up), REALITY (tcp)
                         ?? RealityParamsReason(p) ?? HeaderComboReason(p) ?? XhttpModeReason(p) ?? EncryptionReason(Get(q, "encryption"));
            return reason != null ? Unsupported(p, reason) : ParseResult.Success(p);
        }

        // host= may be a comma-separated list (http-header camouflage); an SNI default takes only the first entry (v2rayN).
        private static string FirstOfList(string csv)
        {
            foreach (var part in csv.Split(','))
            {
                var t = part.Trim();
                if (t.Length > 0) return t;
            }
            return null;
        }

        // Recognized-but-unsupported reason for a vless/vmess transport+security combo (null = supported).
        // VLESS supports xhttp (packet-up over TLS, stream-one over REALITY) and REALITY; VMess has no REALITY.
        internal static string UnsupportedReason(string type, string security, string flow, bool allowXhttp, bool allowReality)
        {
            string nflow = Protocol.VlessProtocol.NormalizeFlow(flow);
            bool vision = nflow == Protocol.VlessProtocol.FlowVision;
            if (security == "reality")
            {
                if (!allowReality) return "REALITY (VMess) — unsupported (VLESS only)";
                if (nflow != null && !vision) return "REALITY + XTLS flow '" + flow + "' — unsupported (only xtls-rprx-vision)";
                if (vision && type != "tcp") return "XTLS Vision over '" + type + "' — unsupported (tcp only)";
                if (type != "tcp" && type != "xhttp") return "REALITY over '" + type + "' — unsupported (tcp or xhttp)";
                return null;
            }
            if (nflow != null)
            {
                if (!vision || !allowReality) return "XTLS flow '" + flow + "' — unsupported";
                if (security != "tls") return "XTLS Vision needs security=tls or reality";
                if (type != "tcp") return "XTLS Vision over '" + type + "' — unsupported (tcp only)";
                return null;
            }
            if (type == "xhttp")
            {
                if (!allowXhttp) return "XHTTP (VMess) — unsupported by the managed engine";
                return security == "tls" ? null : "XHTTP requires TLS — unsupported";
            }
            if (type != "tcp" && type != "ws") return "'" + type + "' transport — unsupported (only tcp/ws)";
            return null;
        }

        /// <summary>XHTTP modes we run: stream-one over REALITY (HTTP/2; also what "auto" means with REALITY), packet-up
        /// over TLS (HTTP/1.1; what "auto" means without REALITY). downloadSettings (split up/down links) is not supported.</summary>
        internal static string XhttpModeReason(ProxyProfile p)
        {
            if (!string.Equals(NormalizeNetwork(p.Network), "xhttp", StringComparison.Ordinal)) return null;
            if ((p.XhttpExtra ?? "").IndexOf("downloadSettings", StringComparison.OrdinalIgnoreCase) >= 0)
                return "XHTTP with downloadSettings — unsupported";
            string m = (p.XhttpMode ?? "").Trim().ToLowerInvariant();
            bool auto = m.Length == 0 || m == "auto";
            if (p.Reality) return auto || m == "stream-one" ? null : "XHTTP mode '" + m + "' over REALITY — unsupported (stream-one only)";
            if (!(auto || m == "packet-up")) return "XHTTP mode '" + m + "' over TLS — not supported yet (packet-up only)";
            return PacketUpExtraReason(p.XhttpExtra);
        }

        /// <summary>packet-up carries the session id and seq in the URL path and the data in the POST body; extra settings
        /// that move them elsewhere (Xray sessionIDPlacement / seqPlacement / uplinkDataPlacement) are not implemented.</summary>
        internal static string PacketUpExtraReason(string extra)
        {
            if (string.IsNullOrWhiteSpace(extra)) return null;
            Dictionary<string, object> x;
            try { x = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(extra); } catch (Exception) { return null; }
            if (x == null) return null;
            string S(string k) => x.TryGetValue(k, out var v) && v != null ? Convert.ToString(v).Trim().ToLowerInvariant() : "";
            foreach (var k in new[] { "sessionIDPlacement", "sessionPlacement", "seqPlacement" })
                if (S(k).Length > 0 && S(k) != "path") return "XHTTP " + k + " '" + S(k) + "' — unsupported (path only)";
            string up = S("uplinkDataPlacement");
            if (up.Length > 0 && up != "body" && up != "auto") return "XHTTP uplinkDataPlacement '" + up + "' — unsupported (body only)";
            return null;
        }

        /// <summary>VMess rides the same chain as VLESS — tcp (optional http header) or ws, TLS or not, and XHTTP
        /// packet-up over TLS — nothing else.</summary>
        internal static string VmessTransportReason(string net)
        {
            if (net != "tcp" && net != "ws" && net != "xhttp") return "VMess over '" + net + "' — unsupported (tcp, ws or xhttp only)";
            return null;
        }

        /// <summary>Every VMess rule, from the profile's own fields: transport + security (no REALITY), XHTTP mode.
        /// alterId is not a rule: like Xray's client (which has no alterId) the engine always speaks AEAD.</summary>
        internal static string VmessReason(ProxyProfile p, string security)
        {
            string net = NormalizeNetwork(p.Network);
            return UnsupportedReason(net, security, null, allowXhttp: true, allowReality: false) ?? VmessTransportReason(net) ?? XhttpModeReason(p);
        }

        /// <summary>VLESS Encryption (encryption=mlkem768x25519plus…) isn't implemented; only "none" is.</summary>
        internal static string EncryptionReason(string enc)
        {
            enc = (enc ?? "").Trim();
            if (enc.Length == 0 || enc.Equals("none", StringComparison.OrdinalIgnoreCase)) return null;
            return "VLESS encryption '" + (enc.Length > 24 ? enc.Substring(0, 24) + "…" : enc) + "' — unsupported (only none)";
        }

        /// <summary>Re-classifies a VLESS/VMess profile from its own fields (after an edit): the same rules the share-link
        /// parser applies to the transport/security/flow/REALITY fields the dialog can change. Null = runnable.</summary>
        public static string ReasonForEditedProfile(ProxyProfile p)
        {
            string net = NormalizeNetwork(p.Network);
            string sec = p.Reality ? "reality" : p.UseTls ? "tls" : "none";
            if (p.Protocol == "vless")
                return UnsupportedReason(net, sec, p.Flow, allowXhttp: true, allowReality: true) ?? RealityParamsReason(p) ?? HeaderComboReason(p) ?? XhttpModeReason(p);
            if (p.Protocol == "vmess")
                return VmessReason(p, sec);
            return null;
        }

        /// <summary>True when an unsupported reason is one an edit of the REALITY / flow / security fields can cure.</summary>
        public static bool IsRepairableReason(string reason)
        {
            reason = reason ?? "";
            return reason.IndexOf("REALITY", StringComparison.OrdinalIgnoreCase) >= 0
                || reason.IndexOf("XTLS", StringComparison.OrdinalIgnoreCase) >= 0
                || reason.IndexOf("Vision", StringComparison.OrdinalIgnoreCase) >= 0
                || reason.IndexOf("VMess over", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>REALITY and XTLS Vision run directly on tcp — not under the http-header camouflage (Xray: XTLS only
        /// supports TLS and REALITY directly).</summary>
        internal static string HeaderComboReason(ProxyProfile p)
        {
            if (p.HeaderType != "http") return null;
            if (p.Reality) return "REALITY with the http header camouflage — unsupported";
            if (Protocol.VlessProtocol.NormalizeFlow(p.Flow) == Protocol.VlessProtocol.FlowVision) return "XTLS Vision with the http header camouflage — unsupported";
            return null;
        }

        /// <summary>A REALITY profile needs a usable server key and short id (null = fine or not REALITY).</summary>
        internal static string RealityParamsReason(ProxyProfile p)
        {
            if (!p.Reality) return null;
            if (Transport.Tls13.RealityConfig.ParsePublicKey(p.RealityPublicKey) == null) return "REALITY link without a valid public key (pbk)";
            if (Transport.Tls13.RealityConfig.ParseShortId(p.RealityShortId) == null) return "REALITY short id (sid) must be 0–16 hex characters";
            return null;
        }

        // ---------------- VMESS ----------------
        // v2rayN: vmess://base64( { add, port, id, aid, scy, net, type, host, path, tls, sni, alpn, fp, insecure, ps } )
        // net=tcp: type=http is the header camouflage (host / path are comma lists); net=xhttp: type is the mode
        // (3x-ui writes a top-level "mode" instead). aid is ignored — the engine always speaks AEAD, like Xray.
        private static ParseResult ParseVmess(string link)
        {
            var json = Encoding.UTF8.GetString(DecodeBase64(link.Substring("vmess://".Length)));
            var d = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(json);
            string S(string k)
            {
                if (d == null || !d.TryGetValue(k, out var v) || v == null) return null;
                if (v is System.Collections.IDictionary) return new JavaScriptSerializer().Serialize(v);   // a JSON object stays JSON
                if (v is System.Collections.IEnumerable list && !(v is string))
                {
                    var items = list.Cast<object>().Where(x => x != null).ToList();
                    return items.Any(x => x is System.Collections.IEnumerable && !(x is string))
                        ? new JavaScriptSerializer().Serialize(v)                       // nested: keep as JSON
                        : string.Join(",", items.Select(x => x.ToString()));           // a list of scalars: comma-join
                }
                return v.ToString();
            }

            int port; int.TryParse(S("port"), out port);
            var net = NormalizeNetwork(S("net"));
            var tls = (S("tls") ?? "").Trim().ToLowerInvariant();
            string type = (S("type") ?? "").Trim();

            var p = new ProxyProfile
            {
                Protocol = "vmess",
                Uuid = S("id"),
                Server = S("add"),
                Port = port,
                Name = S("ps"),
                Network = net,
                WsHost = net == "ws" ? FirstOfList(S("host") ?? "") : S("host"),   // ws takes one Host (v2rayN sends it raw)
                WsPath = string.IsNullOrEmpty(S("path")) ? "/" : S("path"),
                Sni = S("sni"),
                UseTls = tls == "tls" || tls == "reality",
                VmessSecurity = string.IsNullOrEmpty(S("scy")) ? "auto" : S("scy"),
                Fingerprint = S("fp"),
                AllowInsecure = IsTrue(S("insecure")) || IsTrue(S("allowInsecure")),
                HeaderType = net == "tcp" && string.Equals(type, "http", StringComparison.OrdinalIgnoreCase) ? "http" : null
            };
            if (net == "xhttp")
            {
                string mode = S("mode");
                p.XhttpMode = !string.IsNullOrEmpty(mode) ? mode : type.Length > 0 && !type.Equals("none", StringComparison.OrdinalIgnoreCase) ? type : null;
                p.XhttpExtra = S("extra");
                // 3x-ui flattens extra's keys (downloadSettings, xmux, …) into the top level of the JSON.
                if (d.ContainsKey("downloadSettings") && (p.XhttpExtra ?? "").IndexOf("downloadSettings", StringComparison.OrdinalIgnoreCase) < 0)
                    p.XhttpExtra = new JavaScriptSerializer().Serialize(new Dictionary<string, object> { { "downloadSettings", d["downloadSettings"] } });
            }
            if (string.IsNullOrEmpty(p.Sni) && !string.IsNullOrEmpty(p.WsHost)) p.Sni = FirstOfList(p.WsHost);

            string reason = VmessReason(p, tls);
            return reason != null ? Unsupported(p, reason) : ParseResult.Success(p);
        }

        // Xray's standard share link (XTLS/Xray-core discussion #716) has '@' before the host — never part of base64.
        private static bool IsStandardVmess(string link)
        {
            string rest = link.Substring("vmess://".Length);
            int cut = rest.IndexOfAny(new[] { '#', '?' });
            return (cut >= 0 ? rest.Substring(0, cut) : rest).IndexOf('@') >= 0;
        }

        // vmess://uuid@host:port?type=&security=&encryption=&sni=&host=&path=&headerType=&fp=&mode=&extra=#name
        private static ParseResult ParseVmessStandard(string link)
        {
            var uri = new Uri(link);
            var q = ParseQuery(uri.Query);
            var type = NormalizeNetwork(Get(q, "type"));
            var security = (Get(q, "security") ?? "").Trim().ToLowerInvariant();
            var p = new ProxyProfile
            {
                Protocol = "vmess",
                Uuid = Uri.UnescapeDataString(uri.UserInfo),
                Server = uri.Host,
                Port = uri.Port,
                Name = Uri.UnescapeDataString(uri.Fragment.TrimStart('#')),
                Network = type,
                Sni = Get(q, "sni"),
                WsHost = Get(q, "host"),
                WsPath = string.IsNullOrEmpty(Get(q, "path")) ? "/" : Get(q, "path"),
                UseTls = security == "tls" || security == "reality",
                VmessSecurity = string.IsNullOrEmpty(Get(q, "encryption")) ? "auto" : Get(q, "encryption"),
                Fingerprint = Get(q, "fp"),
                AllowInsecure = IsTrue(Get(q, "allowInsecure")) || IsTrue(Get(q, "insecure")) || IsTrue(Get(q, "allow_insecure")),
                HeaderType = type == "tcp" && string.Equals(Get(q, "headerType"), "http", StringComparison.OrdinalIgnoreCase) ? "http" : null
            };
            if (type == "xhttp") { p.XhttpMode = Get(q, "mode"); p.XhttpExtra = Get(q, "extra"); }
            if (string.IsNullOrEmpty(p.Sni) && !string.IsNullOrEmpty(p.WsHost)) p.Sni = FirstOfList(p.WsHost);

            string reason = VmessReason(p, security);
            return reason != null ? Unsupported(p, reason) : ParseResult.Success(p);
        }

        private static bool IsTrue(string v)
            => v != null && (v.Trim() == "1" || v.Trim().Equals("true", StringComparison.OrdinalIgnoreCase));

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

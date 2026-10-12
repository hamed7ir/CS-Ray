using System;
using System.Linq;
using System.Text;

namespace CS_Ray.Core.Config
{
    /// <summary>Offline self-tests for <see cref="LinkParser"/> using synthetic links.</summary>
    public static class LinkParserSelfTest
    {
        public static string Run()
        {
            var sb = new StringBuilder();
            int pass = 0, fail = 0;
            void Check(string name, bool ok, string detail = "")
            {
                if (ok) { pass++; sb.AppendLine("PASS  " + name); }
                else { fail++; sb.AppendLine("FAIL  " + name + (detail.Length > 0 ? "  -- " + detail : "")); }
            }

            string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s));

            // VLESS tcp+tls
            {
                var r = LinkParser.Parse("vless://5d8a2b98-8129-4e5c-bc48-3f75e148d1a6@1.2.3.4:443?type=tcp&security=tls&sni=ex.com#My%20VLESS");
                Check("VLESS tcp+tls parses", r.Ok, r.Error);
                if (r.Ok)
                {
                    var p = r.Profile;
                    Check("  VLESS fields", p.Protocol == "vless" && p.Server == "1.2.3.4" && p.Port == 443 &&
                          p.Uuid == "5d8a2b98-8129-4e5c-bc48-3f75e148d1a6" && p.Network == "tcp" && p.UseTls &&
                          p.Sni == "ex.com" && p.Name == "My VLESS",
                          p.Server + ":" + p.Port + " net=" + p.Network + " sni=" + p.Sni + " name=" + p.Name);
                }
            }

            // VLESS ws (path url-decoded)
            {
                var r = LinkParser.Parse("vless://uuid-x@1.2.3.4:443?type=ws&security=tls&host=cdn.ex.com&path=%2Fapi%2Fde#WS");
                Check("VLESS ws parses + path decoded", r.Ok && r.Profile.Network == "ws" &&
                      r.Profile.WsPath == "/api/de" && r.Profile.WsHost == "cdn.ex.com" && r.Profile.Sni == "cdn.ex.com",
                      r.Ok ? "path=" + r.Profile.WsPath + " sni=" + r.Profile.Sni : r.Error);
            }

            // VMESS base64 json (tcp, aid 0)
            {
                var json = "{\"v\":\"2\",\"ps\":\"vm-test\",\"add\":\"9.8.7.6\",\"port\":\"8165\",\"id\":\"5d8a2b98-8129-4e5c-bc48-3f75e148d1a6\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"tcp\",\"type\":\"none\",\"host\":\"\",\"path\":\"\",\"tls\":\"\"}";
                var r = LinkParser.Parse("vmess://" + B64(json));
                Check("VMESS parses", r.Ok, r.Error);
                if (r.Ok)
                {
                    var p = r.Profile;
                    Check("  VMESS fields", p.Protocol == "vmess" && p.Server == "9.8.7.6" && p.Port == 8165 &&
                          p.Uuid == "5d8a2b98-8129-4e5c-bc48-3f75e148d1a6" && p.Network == "tcp" &&
                          p.VmessSecurity == "auto" && p.Name == "vm-test",
                          p.Server + ":" + p.Port + " scy=" + p.VmessSecurity + " name=" + p.Name);
                }
            }

            // SS SIP002
            {
                var r = LinkParser.Parse("ss://" + B64("chacha20-ietf-poly1305:secretpw") + "@5.6.7.8:8388#SS-Node");
                Check("SS SIP002 parses", r.Ok && r.Profile.SsMethod == "chacha20-ietf-poly1305" &&
                      r.Profile.Password == "secretpw" && r.Profile.Server == "5.6.7.8" && r.Profile.Port == 8388 &&
                      r.Profile.Name == "SS-Node",
                      r.Ok ? r.Profile.SsMethod + "@" + r.Profile.Server + ":" + r.Profile.Port : r.Error);
            }

            // SS legacy (whole body base64)
            {
                var r = LinkParser.Parse("ss://" + B64("aes-256-gcm:pw123@9.9.9.9:443") + "#Legacy");
                Check("SS legacy parses", r.Ok && r.Profile.SsMethod == "aes-256-gcm" &&
                      r.Profile.Password == "pw123" && r.Profile.Server == "9.9.9.9" && r.Profile.Port == 443,
                      r.Ok ? r.Profile.SsMethod + "@" + r.Profile.Server + ":" + r.Profile.Port : r.Error);
            }

            // --- Recognized-but-unsupported: IMPORTED (parsed OK) + tagged with a reason ---
            Unsupported(Check, "tag VLESS grpc",
                LinkParser.Parse("vless://u@1.2.3.4:443?type=grpc&security=tls"), "grpc");
            Unsupported(Check, "tag VLESS reality (bad pbk)",
                LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&security=reality&pbk=x"), "REALITY");
            {
                const string pbk = "q0ZjwXLc5OCk4V6-cLx3eKZYbcY3wbRW0V5yRS5pXGw";   // synthetic 32-byte key
                var rr = LinkParser.Parse("vless://5d8a2b98-8129-4e5c-bc48-3f75e148d1a6@1.2.3.4:443?type=tcp&security=reality&sni=www.apple.com&fp=edge&pbk=" + pbk + "&sid=6ba85179e30d4fc2&spx=%2Fx#R");
                var rp = rr.Profile;
                Check("VLESS reality tcp SUPPORTED + fields", rr.Ok && rp != null && !rp.Unsupported && rp.Reality && rp.UseTls &&
                      rp.RealityPublicKey == pbk && rp.RealityShortId == "6ba85179e30d4fc2" && rp.Fingerprint == "edge" &&
                      rp.SpiderX == "/x" && rp.Sni == "www.apple.com" && rp.ToEngineConfig().Reality != null &&
                      rp.ToEngineConfig().Reality.PublicKey.Length == 32 && rp.ToEngineConfig().Reality.ShortId.Length == 8,
                      rr.Ok ? (rp.Unsupported ? "tagged: " + rp.UnsupportedReason : "reality=" + rp.Reality) : rr.Error);
                Supported(Check, "VLESS reality + vision SUPPORTED",
                    LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&security=reality&flow=xtls-rprx-vision&pbk=" + pbk),
                    x => x.Flow == "xtls-rprx-vision" && x.ToEngineConfig().IsVision && x.ToEngineConfig().Reality != null);
                Supported(Check, "VLESS reality + vision-udp443 alias normalized",
                    LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&security=reality&flow=xtls-rprx-vision-udp443&pbk=" + pbk),
                    x => x.ToEngineConfig().IsVision);
                Unsupported(Check, "tag VLESS reality + other flow",
                    LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&security=reality&flow=xtls-rprx-direct&pbk=" + pbk), "only xtls-rprx-vision");
                Unsupported(Check, "tag VLESS reality + http header",
                    LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&headerType=http&security=reality&pbk=" + pbk), "http header");
                Supported(Check, "VLESS reality over xhttp (mode auto = stream-one) SUPPORTED",
                    LinkParser.Parse("vless://u@1.2.3.4:443?type=xhttp&security=reality&pbk=" + pbk), x => x.Network == "xhttp" && x.Reality);
                Unsupported(Check, "tag VLESS reality bad sid",
                    LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&security=reality&sid=xyz&pbk=" + pbk), "short id");
            }
            Supported(Check, "VLESS tls + vision SUPPORTED (fp kept)",
                LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&security=tls&flow=xtls-rprx-vision&fp=edge"),
                x => x.ToEngineConfig().IsVision && x.Fingerprint == "edge" && x.ToEngineConfig().Reality == null);
            Supported(Check, "VLESS tls flow=none is plain TLS",
                LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&security=tls&flow=none"), x => !x.ToEngineConfig().IsVision);
            Unsupported(Check, "tag VLESS legacy xtls flow",
                LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&security=tls&flow=xtls-rprx-direct"), "XTLS");
            Unsupported(Check, "tag VLESS vision without TLS",
                LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&flow=xtls-rprx-vision"), "needs security");
            Unsupported(Check, "tag VLESS vision over ws",
                LinkParser.Parse("vless://u@1.2.3.4:443?type=ws&security=tls&flow=xtls-rprx-vision"), "tcp only");
            Unsupported(Check, "tag VLESS vision + http header",
                LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&headerType=http&security=tls&flow=xtls-rprx-vision"), "http header");
            Unsupported(Check, "tag VLESS encryption (ML-KEM)",
                LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&security=tls&encryption=mlkem768x25519plus.native.0rtt.abc"), "encryption");
            Supported(Check, "VLESS encryption=none is fine",
                LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&security=tls&encryption=none"), x => true);
            Unsupported(Check, "tag VMESS ws (engine is raw TCP)",
                LinkParser.Parse("vmess://" + B64("{\"add\":\"1.2.3.4\",\"port\":\"80\",\"id\":\"5d8a2b98-8129-4e5c-bc48-3f75e148d1a6\",\"aid\":\"0\",\"net\":\"ws\"}")), "raw TCP only");
            Unsupported(Check, "tag VMESS tls (engine is raw TCP)",
                LinkParser.Parse("vmess://" + B64("{\"add\":\"1.2.3.4\",\"port\":\"443\",\"id\":\"5d8a2b98-8129-4e5c-bc48-3f75e148d1a6\",\"aid\":\"0\",\"net\":\"tcp\",\"tls\":\"tls\"}")), "raw TCP only");
            {
                // XHTTP: stream-one over REALITY (HTTP/2) is supported; other modes get precise reasons.
                const string k = "q0ZjwXLc5OCk4V6-cLx3eKZYbcY3wbRW0V5yRS5pXGw";
                string xr = "vless://5d8a2b98-8129-4e5c-bc48-3f75e148d1a6@1.2.3.4:443?security=reality&type=xhttp&sni=a.com&fp=chrome&pbk=" + k
                          + "&host=a.com&path=%2F%E6%98%9F%E4%BA%91%2Fx%2F&extra=%7B%22noGRPCHeader%22%3Atrue%2C%22xPaddingBytes%22%3A%22200-300%22%7D";
                Supported(Check, "VLESS reality + xhttp stream-one SUPPORTED", LinkParser.Parse(xr + "&mode=stream-one#X"),
                    x => x.XhttpMode == "stream-one" && x.XhttpExtra.Contains("noGRPCHeader") && x.ToEngineConfig().XhttpExtra == x.XhttpExtra);
                Supported(Check, "VLESS reality + xhttp auto SUPPORTED", LinkParser.Parse(xr + "&mode=auto#X"), x => true);
                Unsupported(Check, "tag reality + xhttp packet-up", LinkParser.Parse(xr + "&mode=packet-up#X"), "stream-one only");
                Unsupported(Check, "tag tls + xhttp stream-one", LinkParser.Parse("vless://u@1.2.3.4:443?security=tls&type=xhttp&mode=stream-one"), "packet-up only");
                Supported(Check, "VLESS tls + xhttp packet-up still SUPPORTED", LinkParser.Parse("vless://u@1.2.3.4:443?security=tls&type=xhttp&mode=packet-up"), x => true);
                Unsupported(Check, "tag xhttp downloadSettings", LinkParser.Parse(xr + "&mode=auto&extra=%7B%22downloadSettings%22%3A%7B%7D%7D"), "downloadSettings");
                Unsupported(Check, "tag vision over reality xhttp", LinkParser.Parse(xr + "&mode=stream-one&flow=xtls-rprx-vision"), "tcp only");

                // Request shape: Go-escaped path with trailing slash, Referer x_padding in range, no content-type.
                var xs = CS_Ray.Core.Transport.Http2.XhttpSettings.From("a.com", "/\u661f\u4e91/x", "{\"noGRPCHeader\":true,\"xPaddingBytes\":\"200-300\"}");
                var hs = xs.RequestHeaders();
                string path = hs.First(h => h.Name == ":path").Value, referer = hs.First(h => h.Name == "referer").Value;
                int pad = referer.Length - referer.IndexOf("x_padding=", StringComparison.Ordinal) - "x_padding=".Length;
                Check("XHTTP path escaped Go-style + trailing slash + dual padding", path.StartsWith("/%E6%98%9F%E4%BA%91/x/?x_padding=", StringComparison.Ordinal)
                      && path.Substring(path.IndexOf('=') + 1) == referer.Substring(referer.IndexOf("x_padding=", StringComparison.Ordinal) + 10), path.Substring(0, 40));
                Check("XHTTP x_padding in 200..299, no content-type", pad >= 200 && pad < 300 && !hs.Any(h => h.Name == "content-type")
                      && referer.StartsWith("https://a.com/%E6%98%9F", StringComparison.Ordinal), "pad " + pad);
                var xs2 = CS_Ray.Core.Transport.Http2.XhttpSettings.From("a.com", "/p", "{\"xmux\":{\"maxConcurrency\":\"16-32\"}}");
                Check("XHTTP xmux overrides defaults", xs2.ConnTo == 0 && xs2.ConcFrom == 16 && xs2.ConcTo == 32 && xs2.ReqTo == 0, "conc " + xs2.ConcFrom + "-" + xs2.ConcTo);
                Check("XHTTP default grpc content-type", CS_Ray.Core.Transport.Http2.XhttpSettings.From("a.com", "/p", null).RequestHeaders().Any(h => h.Name == "content-type" && h.Value == "application/grpc"), "");
            }
            {
                // An edit that supplies the missing REALITY key re-classifies the profile as runnable.
                var old = LinkParser.Parse("vless://5d8a2b98-8129-4e5c-bc48-3f75e148d1a6@1.2.3.4:443?type=tcp&security=reality&sni=a.com").Profile;
                bool wasRepairable = old.Unsupported && LinkParser.IsRepairableReason(old.UnsupportedReason);
                old.RealityPublicKey = "q0ZjwXLc5OCk4V6-cLx3eKZYbcY3wbRW0V5yRS5pXGw";
                Check("edit repairs a key-less REALITY profile", wasRepairable && LinkParser.ReasonForEditedProfile(old) == null,
                      old.UnsupportedReason + " -> " + (LinkParser.ReasonForEditedProfile(old) ?? "runnable"));
            }
            {
                var rx = LinkParser.Parse("vless://u@1.2.3.4:443?type=xhttp&security=tls&host=h&path=/p#X");
                Check("VLESS xhttp+tls SUPPORTED", rx.Ok && rx.Profile != null && !rx.Profile.Unsupported && rx.Profile.Network == "xhttp",
                      rx.Ok ? (rx.Profile.Unsupported ? "tagged: " + rx.Profile.UnsupportedReason : "net=" + rx.Profile.Network) : rx.Error);
            }
            Unsupported(Check, "tag VLESS xhttp without TLS",
                LinkParser.Parse("vless://u@1.2.3.4:443?type=xhttp"), "XHTTP requires TLS");
            Unsupported(Check, "tag VMESS alterId>0",
                LinkParser.Parse("vmess://" + B64("{\"add\":\"1.2.3.4\",\"port\":\"80\",\"id\":\"x\",\"aid\":\"2\",\"net\":\"tcp\"}")), "alterId");
            Unsupported(Check, "tag SS non-AEAD cipher",
                LinkParser.Parse("ss://" + B64("rc4-md5:pw") + "@1.2.3.4:8388"), "AEAD only");
            Unsupported(Check, "tag hysteria2 scheme",
                LinkParser.Parse("hysteria2://pw@1.2.3.4:443#HY2"), "Hysteria2");

            // A truly malformed / unknown line is still rejected (distinct from recognized-but-unsupported).
            Reject(Check, "reject unknown scheme", LinkParser.Parse("foobar://x"), "Unrecognized scheme");

            sb.AppendLine();
            sb.AppendLine("RESULT: " + pass + " passed, " + fail + " failed.");
            return sb.ToString();
        }

        private static void Unsupported(Action<string, bool, string> check, string name, ParseResult r, string expectFragment)
        {
            bool ok = r.Ok && r.Profile != null && r.Profile.Unsupported &&
                      (r.Profile.UnsupportedReason ?? "").IndexOf(expectFragment, StringComparison.OrdinalIgnoreCase) >= 0;
            check(name, ok, !r.Ok ? "(failed: " + r.Error + ")" : (r.Profile.Unsupported ? r.Profile.UnsupportedReason : "(parsed as SUPPORTED)"));
        }

        private static void Supported(Action<string, bool, string> check, string name, ParseResult r, Func<ProxyProfile, bool> fields)
        {
            bool ok = r.Ok && r.Profile != null && !r.Profile.Unsupported && fields(r.Profile);
            check(name, ok, !r.Ok ? "(failed: " + r.Error + ")" : (r.Profile.Unsupported ? "tagged: " + r.Profile.UnsupportedReason : "fields"));
        }

        private static void Reject(Action<string, bool, string> check, string name, ParseResult r, string expectFragment)
        {
            bool ok = !r.Ok && r.Error != null && r.Error.IndexOf(expectFragment, StringComparison.OrdinalIgnoreCase) >= 0;
            check(name, ok, r.Ok ? "(unexpectedly parsed)" : r.Error);
        }
    }
}

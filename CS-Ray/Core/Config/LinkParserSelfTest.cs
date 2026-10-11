using System;
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
                Unsupported(Check, "tag VLESS reality over xhttp",
                    LinkParser.Parse("vless://u@1.2.3.4:443?type=xhttp&security=reality&pbk=" + pbk), "xhttp");
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

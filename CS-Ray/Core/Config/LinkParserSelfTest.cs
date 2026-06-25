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
            Unsupported(Check, "tag VLESS reality",
                LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&security=reality&pbk=x"), "REALITY");
            Unsupported(Check, "tag VLESS xtls flow",
                LinkParser.Parse("vless://u@1.2.3.4:443?type=tcp&security=tls&flow=xtls-rprx-vision"), "XTLS");
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

        private static void Reject(Action<string, bool, string> check, string name, ParseResult r, string expectFragment)
        {
            bool ok = !r.Ok && r.Error != null && r.Error.IndexOf(expectFragment, StringComparison.OrdinalIgnoreCase) >= 0;
            check(name, ok, r.Ok ? "(unexpectedly parsed)" : r.Error);
        }
    }
}

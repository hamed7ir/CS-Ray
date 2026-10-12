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
            {
                string Vm(string extra) => "vmess://" + B64("{\"add\":\"1.2.3.4\",\"port\":\"443\",\"id\":\"5d8a2b98-8129-4e5c-bc48-3f75e148d1a6\",\"aid\":\"0\"" + extra + "}");
                Supported(Check, "VMESS ws SUPPORTED", LinkParser.Parse(Vm(",\"net\":\"ws\",\"path\":\"/v\",\"host\":\"cdn.ex.com\"")),
                          x => x.Network == "ws" && !x.UseTls && x.WsPath == "/v" && x.WsHost == "cdn.ex.com");
                Supported(Check, "VMESS tcp+tls SUPPORTED", LinkParser.Parse(Vm(",\"net\":\"tcp\",\"tls\":\"tls\",\"sni\":\"ex.com\"")),
                          x => x.Network == "tcp" && x.UseTls && x.Sni == "ex.com" && x.ToEngineConfig().UseTls);
                Supported(Check, "VMESS ws+tls: empty sni = host", LinkParser.Parse(Vm(",\"net\":\"ws\",\"tls\":\"tls\",\"host\":\"cdn.ex.com\"")),
                          x => x.UseTls && x.Sni == "cdn.ex.com");
                Supported(Check, "VMESS http header + tls SUPPORTED", LinkParser.Parse(Vm(",\"net\":\"tcp\",\"type\":\"http\",\"tls\":\"tls\",\"path\":\"/h\"")),
                          x => x.HeaderType == "http" && x.UseTls);
                Supported(Check, "VMESS plain tcp stays plain in the engine", LinkParser.Parse(Vm(",\"net\":\"tcp\"")),
                          x => !x.UseTls && !x.ToEngineConfig().UseTls);
                Unsupported(Check, "tag VMESS grpc", LinkParser.Parse(Vm(",\"net\":\"grpc\",\"tls\":\"tls\"")), "grpc");
                Supported(Check, "VMESS xhttp+tls SUPPORTED (mode in type)", LinkParser.Parse(Vm(",\"net\":\"xhttp\",\"tls\":\"tls\",\"type\":\"packet-up\",\"path\":\"/x\"")),
                          x => x.Network == "xhttp" && x.XhttpMode == "packet-up" && x.HeaderType == null);
                Unsupported(Check, "tag VMESS xhttp stream-one over TLS", LinkParser.Parse(Vm(",\"net\":\"xhttp\",\"tls\":\"tls\",\"type\":\"stream-one\"")), "packet-up only");
                Supported(Check, "VMESS xhttp: 3x-ui mode key, type none", LinkParser.Parse(Vm(",\"net\":\"xhttp\",\"tls\":\"tls\",\"type\":\"none\",\"mode\":\"auto\"")),
                          x => x.XhttpMode == "auto");
                Unsupported(Check, "tag VMESS xhttp without TLS", LinkParser.Parse(Vm(",\"net\":\"xhttp\"")), "requires TLS");
                Supported(Check, "VMESS insecure / fp read", LinkParser.Parse(Vm(",\"net\":\"ws\",\"tls\":\"tls\",\"insecure\":\"1\",\"fp\":\"firefox\"")),
                          x => x.AllowInsecure && x.Fingerprint == "firefox");
                Supported(Check, "VMESS ws host list: first entry", LinkParser.Parse(Vm(",\"net\":\"ws\",\"tls\":\"tls\",\"host\":\"a.com, b.com\"")),
                          x => x.WsHost == "a.com" && x.Sni == "a.com");
                Supported(Check, "VMESS JSON array value joined", LinkParser.Parse(Vm(",\"net\":\"tcp\",\"type\":\"http\",\"host\":[\"h1.com\",\"h2.com\"]")),
                          x => x.WsHost == "h1.com,h2.com" && x.HeaderType == "http");
                Supported(Check, "VMESS standard URI ws+tls", LinkParser.Parse("vmess://5d8a2b98-8129-4e5c-bc48-3f75e148d1a6@cdn.ex.com:443?type=ws&security=tls&encryption=auto&path=%2Fv%3Fed%3D2048&host=h.ex.com&sni=s.ex.com&allowInsecure=1#Std%20WS"),
                          x => x.Protocol == "vmess" && x.Network == "ws" && x.UseTls && x.WsPath == "/v?ed=2048" && x.WsHost == "h.ex.com" && x.Sni == "s.ex.com" && x.AllowInsecure && x.Name == "Std WS" && x.Port == 443);
                Supported(Check, "VMESS standard URI tcp http header", LinkParser.Parse("vmess://5d8a2b98-8129-4e5c-bc48-3f75e148d1a6@1.2.3.4:80?type=tcp&headerType=http&host=x.com&path=%2Fa#h"),
                          x => x.HeaderType == "http" && !x.UseTls && x.WsHost == "x.com");
                Unsupported(Check, "tag VMESS standard URI reality", LinkParser.Parse("vmess://5d8a2b98-8129-4e5c-bc48-3f75e148d1a6@1.2.3.4:443?type=tcp&security=reality#r"), "VLESS only");
                Unsupported(Check, "tag VMESS reality", LinkParser.Parse(Vm(",\"net\":\"tcp\",\"tls\":\"reality\"")), "VLESS only");
            }
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
            Supported(Check, "VMESS alterId>0 runs as AEAD (like Xray)",
                LinkParser.Parse("vmess://" + B64("{\"add\":\"1.2.3.4\",\"port\":\"80\",\"id\":\"5d8a2b98-8129-4e5c-bc48-3f75e148d1a6\",\"aid\":\"2\",\"net\":\"tcp\"}")), x => !x.UseTls);
            {
                // Subscriptions: Clash / sing-box VMess over ws+tls.
                var clash = SubscriptionFetcher.Decode("proxies:\n  - name: c1\n    type: vmess\n    server: 1.2.3.4\n    port: 443\n    uuid: 5d8a2b98-8129-4e5c-bc48-3f75e148d1a6\n    alterId: 64\n    cipher: auto\n    tls: true\n    network: ws\n    ws-opts:\n      path: /v\n      headers:\n        Host: cdn.ex.com\n" +
                                                       "  - name: c2\n    type: vmess\n    server: 1.2.3.4\n    port: 443\n    uuid: 5d8a2b98-8129-4e5c-bc48-3f75e148d1a6\n    cipher: auto\n    tls: true\n    network: ws\n    ws-opts:\n      path: /u\n      v2ray-http-upgrade: true\n", null);
                var c1 = clash.FirstOrDefault(x => x.Name == "c1"); var c2 = clash.FirstOrDefault(x => x.Name == "c2");
                Check("Clash vmess ws+tls (alterId 64) runnable, SNI from Host", c1 != null && !c1.Unsupported && c1.UseTls && c1.Sni == "cdn.ex.com" && c1.WsHost == "cdn.ex.com" && c1.WsPath == "/v",
                      c1 == null ? "missing" : (c1.Unsupported ? c1.UnsupportedReason : "sni=" + c1.Sni + " host=" + c1.WsHost));
                Check("Clash ws-opts v2ray-http-upgrade tagged", c2 != null && c2.Unsupported && (c2.UnsupportedReason ?? "").Contains("HTTPUpgrade"), c2 == null ? "missing" : c2.UnsupportedReason ?? "runnable?!");
                var sb2 = SubscriptionFetcher.Decode("{\"outbounds\":[{\"type\":\"vmess\",\"tag\":\"s1\",\"server\":\"1.2.3.4\",\"server_port\":443,\"uuid\":\"5d8a2b98-8129-4e5c-bc48-3f75e148d1a6\",\"alter_id\":1,\"tls\":{\"enabled\":true,\"server_name\":\"s.ex.com\"},\"transport\":{\"type\":\"ws\",\"path\":\"/w\",\"headers\":{\"Host\":[\"h.ex.com\"]}}}]}", null);
                var s1 = sb2.FirstOrDefault();
                Check("sing-box vmess ws+tls, list Host", s1 != null && !s1.Unsupported && s1.WsHost == "h.ex.com" && s1.Sni == "s.ex.com" && s1.UseTls,
                      s1 == null ? "missing" : (s1.Unsupported ? s1.UnsupportedReason : "host=" + s1.WsHost + " sni=" + s1.Sni));
            }
            Unsupported(Check, "tag SS non-AEAD cipher",
                LinkParser.Parse("ss://" + B64("rc4-md5:pw") + "@1.2.3.4:8388"), "AEAD only");
            Unsupported(Check, "tag hysteria2 scheme",
                LinkParser.Parse("hysteria2://pw@1.2.3.4:443#HY2"), "Hysteria2");

            // WebSocket early data: Xray strips a non-empty "ed" from the request path (keeping the rest, sorted by key).
            {
                string Ed(string path) { string p = Transport.WebSocketTransport.SplitEarlyData(path, out int n); return p + "|" + n; }
                Check("ws ed: /ed?ed=2048", Ed("/ed?ed=2048") == "/ed|2048", Ed("/ed?ed=2048"));
                Check("ws ed: other params kept, sorted", Ed("/p?b=2&ed=64&a=1") == "/p?a=1&b=2|64", Ed("/p?b=2&ed=64&a=1"));
                Check("ws ed: no ed = untouched", Ed("/p?b=2&a=1") == "/p?b=2&a=1|0", Ed("/p?b=2&a=1"));
                Check("ws ed: empty ed = untouched", Ed("/p?ed=") == "/p?ed=|0", Ed("/p?ed="));
                Check("ws ed: non-numeric ed dropped, no early data", Ed("/p?ed=abc") == "/p|0", Ed("/p?ed=abc"));
            }

            // Browser masquerade + Go-shaped ws request target / Host (review round).
            {
                Check("Sec-CH-UA: Chrome 124 matches the real browser", Transport.BrowserHeaders.SecChUa(124) == "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"", Transport.BrowserHeaders.SecChUa(124));
                Check("Sec-CH-UA: Chrome 147 order", Transport.BrowserHeaders.ChromeSecChUa == "\"Google Chrome\";v=\"147\", \"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"147\"", Transport.BrowserHeaders.ChromeSecChUa);
                string T(string x) => Transport.WebSocketTransport.RequestTarget(x);
                Check("ws target: space escaped", T("/my ws") == "/my%20ws", T("/my ws"));
                Check("ws target: UTF-8 escaped", T("/路径") == "/%E8%B7%AF%E5%BE%84", T("/路径"));
                Check("ws target: valid escaping kept", T("/a%20b!(c)*") == "/a%20b!(c)*", T("/a%20b!(c)*"));
                Check("ws target: invalid path re-escaped like Go", T("/a b%41") == "/a%20bA", T("/a b%41"));
                Check("ws target: fragment dropped, query kept", T("/p?x=1&y=a b#f") == "/p?x=1&y=a%20b", T("/p?x=1&y=a b#f"));
                var hc = new VlessConfig { ServerHost = "srv.example", Sni = "stale.example", Network = "ws", UseTls = false };
                Check("ws Host: no TLS → server address (stale SNI ignored)", Transport.TlsTransportFactory.HostHeaderFor(hc) == "srv.example", Transport.TlsTransportFactory.HostHeaderFor(hc));
                hc.UseTls = true;
                Check("ws Host: TLS → SNI", Transport.TlsTransportFactory.HostHeaderFor(hc) == "stale.example", Transport.TlsTransportFactory.HostHeaderFor(hc));
                var h6 = new VlessConfig { ServerHost = "2001:db8::1", Network = "ws", UseTls = false };
                Check("ws Host: IPv6 bracketed", Transport.TlsTransportFactory.HostHeaderFor(h6) == "[2001:db8::1]", Transport.TlsTransportFactory.HostHeaderFor(h6));
            }
            {
                // Clash flow style (subconverter's default), YAML booleans, comments.
                var flow = SubscriptionFetcher.Decode("proxies:\n  - {name: f1, type: vmess, server: 1.2.3.4, port: 443, uuid: 5d8a2b98-8129-4e5c-bc48-3f75e148d1a6, alterId: 0, cipher: auto, tls: True, skip-cert-verify: yes, network: ws, ws-opts: {path: \"/f?ed=2048\", headers: {Host: cdn.f.com}}}\n" +
                                                      "  - {name: f2, type: vless, server: 5.6.7.8, port: 443, uuid: 5d8a2b98-8129-4e5c-bc48-3f75e148d1a6, network: tcp, tls: true, flow: xtls-rprx-vision, servername: r.com, client-fingerprint: chrome, reality-opts: {public-key: q0ZjwXLc5OCk4V6-cLx3eKZYbcY3wbRW0V5yRS5pXGw, short-id: ab12}}\n" +
                                                      "  - name: f3\n    type: vmess\n    server: 1.2.3.4\n    port: 443\n    uuid: 5d8a2b98-8129-4e5c-bc48-3f75e148d1a6\n    cipher: auto\n    tls: true # TLS on\n    network: ws\n    ws-opts: {path: /u, v2ray-http-upgrade: True}\n", null);
                var f1 = flow.FirstOrDefault(x => x.Name == "f1"); var f2 = flow.FirstOrDefault(x => x.Name == "f2"); var f3 = flow.FirstOrDefault(x => x.Name == "f3");
                Check("Clash flow-style vmess ws+tls", f1 != null && !f1.Unsupported && f1.UseTls && f1.AllowInsecure && f1.WsPath == "/f?ed=2048" && f1.WsHost == "cdn.f.com" && f1.Sni == "cdn.f.com",
                      f1 == null ? "missing" : (f1.Unsupported ? f1.UnsupportedReason : "path=" + f1.WsPath + " host=" + f1.WsHost + " sni=" + f1.Sni + " tls=" + f1.UseTls + " insecure=" + f1.AllowInsecure));
                Check("Clash flow-style vless reality", f2 != null && !f2.Unsupported && f2.Reality && f2.RealityShortId == "ab12" && f2.Sni == "r.com",
                      f2 == null ? "missing" : (f2.Unsupported ? f2.UnsupportedReason : "reality=" + f2.Reality + " sid=" + f2.RealityShortId));
                Check("Clash inline ws-opts v2ray-http-upgrade: True tagged", f3 != null && f3.Unsupported && (f3.UnsupportedReason ?? "").Contains("HTTPUpgrade") && f3.UseTls,
                      f3 == null ? "missing" : (f3.UnsupportedReason ?? "runnable?!"));
            }
            {
                // vmess:// JSON: an object-valued extra stays JSON; 3x-ui's top-level downloadSettings is caught.
                string Vx(string extra) => "vmess://" + B64("{\"add\":\"1.2.3.4\",\"port\":\"443\",\"id\":\"5d8a2b98-8129-4e5c-bc48-3f75e148d1a6\",\"net\":\"xhttp\",\"tls\":\"tls\",\"type\":\"auto\"" + extra + "}");
                var top = LinkParser.Parse(Vx(",\"downloadSettings\":{\"address\":\"dl.example\"}"));
                Check("VMESS xhttp top-level downloadSettings tagged", top.Ok && top.Profile.Unsupported && (top.Profile.UnsupportedReason ?? "").Contains("downloadSettings"), top.Ok ? top.Profile.UnsupportedReason ?? "runnable?!" : top.Error);
                var obj = LinkParser.Parse(Vx(",\"extra\":{\"xPaddingBytes\":\"100-1000\"}"));
                Check("VMESS xhttp object extra kept as JSON", obj.Ok && !obj.Profile.Unsupported && (obj.Profile.XhttpExtra ?? "").Contains("\"xPaddingBytes\""), obj.Ok ? obj.Profile.XhttpExtra : obj.Error);
            }
            {
                // ProfileStore.Load re-classifies only hand-added VMess profiles tagged under the old rules.
                string tmp = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "csray-mig-" + Guid.NewGuid().ToString("N") + ".json");
                try
                {
                    var seed = new ProfileStore(tmp);
                    seed.Profiles.Add(new ProxyProfile { Id = "m1", Protocol = "vmess", Server = "1.2.3.4", Port = 443, Uuid = "5d8a2b98-8129-4e5c-bc48-3f75e148d1a6", Network = "ws", UseTls = true, Group = ProfileStore.ManualGroup, Unsupported = true, UnsupportedReason = "VMess over 'ws' — unsupported (raw TCP only)" });
                    seed.Profiles.Add(new ProxyProfile { Id = "s1", Protocol = "vmess", Server = "1.2.3.4", Port = 443, Uuid = "5d8a2b98-8129-4e5c-bc48-3f75e148d1a6", Network = "tcp", UseTls = true, Group = "sub-x", Unsupported = true, UnsupportedReason = "VMess alterId>0 (legacy/non-AEAD) — unsupported" });
                    seed.Profiles.Add(new ProxyProfile { Id = "m2", Protocol = "vmess", Server = "1.2.3.4", Port = 443, Uuid = "5d8a2b98-8129-4e5c-bc48-3f75e148d1a6", Network = "xhttp", UseTls = true, Group = ProfileStore.ManualGroup, Unsupported = true, UnsupportedReason = "VMess alterId>0 (legacy/non-AEAD) — unsupported" });
                    seed.Save();
                    var st = new ProfileStore(tmp); st.Load();
                    Check("migration: manual ws profile becomes runnable", !st.GetById("m1").Unsupported, st.GetById("m1").UnsupportedReason ?? "runnable");
                    Check("migration: subscription profile waits for a refresh", st.GetById("s1").Unsupported, "");
                    Check("migration: old xhttp import waits for a re-import", st.GetById("m2").Unsupported, "");
                }
                finally { try { System.IO.File.Delete(tmp); } catch { } }
            }

            // Manual-add dedup: the same link re-added updates in place; a different security/transport is a new server.
            {
                string tmp = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "csray-dedup-" + Guid.NewGuid().ToString("N") + ".json");
                try
                {
                    var store = new ProfileStore(tmp);
                    const string U = "5d8a2b98-8129-4e5c-bc48-3f75e148d1a6", K = "q0ZjwXLc5OCk4V6-cLx3eKZYbcY3wbRW0V5yRS5pXGw";
                    string R(string q) => "vless://" + U + "@1.2.3.4:443?type=tcp&security=reality&sni=a.com&pbk=" + K + "&sid=ab12&fp=chrome&flow=xtls-rprx-vision" + q;
                    bool Add(string link, string group = null)
                    {
                        var pr = LinkParser.Parse(link).Profile; pr.Group = group;
                        store.AddOrUpdate(pr, out bool replaced);
                        return replaced;
                    }
                    Add(R("#first"));
                    string id = store.Profiles[0].Id;
                    bool again = Add(R("#renamed"));
                    Check("dedup: same link re-added updates in place", again && store.Profiles.Count == 1 && store.Profiles[0].Id == id &&
                          store.Profiles[0].Name == "renamed", "count=" + store.Profiles.Count + " replaced=" + again);
                    bool prefsOnly = Add(R("&fp=firefox&spx=%2Fx&allowInsecure=1#prefs").Replace(U, U.ToUpperInvariant()).Replace("fp=chrome&", ""));
                    Check("dedup: fp / spiderX / uuid case alone = same server", prefsOnly && store.Profiles.Count == 1, "count=" + store.Profiles.Count);
                    Check("dedup: different sni = new server", !Add(R("#x").Replace("sni=a.com", "sni=b.com")), "");
                    Check("dedup: different pbk = new server", !Add(R("#x").Replace(K, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")), "");
                    Check("dedup: different short id = new server", !Add(R("#x").Replace("sid=ab12", "sid=cd34")), "");
                    Check("dedup: Vision vs no flow = new server", !Add(R("#x").Replace("&flow=xtls-rprx-vision", "")), "");
                    Check("dedup: same link in a sub group = separate", !Add(R("#x"), "sub-1") && store.Profiles.Count == 6, "count=" + store.Profiles.Count);
                    const string W = "vless://" + U + "@5.6.7.8:443?type=ws&security=tls&sni=c.com&path=%2Fa";
                    Add(W + "#w");
                    Check("dedup: ws empty host = host of the SNI", Add(W + "&host=C.com#w2"), "");
                    Check("dedup: ws different path = new server", !Add(W.Replace("%2Fa", "%2Fb") + "#w3"), "");
                    Check("dedup: tls vs plain = new server", !Add(W.Replace("security=tls", "security=none") + "#w4"), "");
                    Check("dedup: tcp vs raw = same server", Add(R("#raw").Replace("type=tcp", "type=raw")), "");
                    Check("dedup: SS different password = new server",
                          !Add("ss://" + B64("aes-128-gcm:pw1") + "@9.9.9.9:8388#s1") & !Add("ss://" + B64("aes-128-gcm:pw2") + "@9.9.9.9:8388#s2"), "");
                    int n = store.Profiles.Count;
                    Check("dedup: link without #name keeps the given name", Add(W) && store.Profiles.Count == n &&
                          store.Profiles.Any(x => x.Name == "w2") && !store.Profiles.Any(x => string.IsNullOrEmpty(x.Name)), "");
                    const string L = "vless://" + U + "@7.7.7.7:443?type=tcp&security=tls&sni=a.com";
                    Add(L + "#v");
                    Check("dedup: unsupported import never overwrites a runnable one", !Add(L + "&encryption=mlkem768x25519plus.native.0rtt.abc#v2") &&
                          store.Profiles.Count(x => x.Server == "7.7.7.7") == 2 && store.Profiles.Any(x => x.Server == "7.7.7.7" && !x.Unsupported), "");
                    string X = "vless://" + U + "@8.8.4.4:443?type=xhttp&security=reality&sni=a.com&pbk=" + K + "&sid=ab12&path=%2Fp";
                    Add(X + "&mode=auto#x1");
                    Check("dedup: xhttp auto = stream-one over REALITY", Add(X + "&mode=stream-one#x2"), "");
                }
                finally { try { System.IO.File.Delete(tmp); } catch { } }
            }

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

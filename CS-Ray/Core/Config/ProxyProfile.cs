using System;

namespace CS_Ray.Core.Config
{
    /// <summary>
    /// One unified proxy profile the engine consumes, regardless of share-link format.
    /// <see cref="ToEngineConfig"/> is the single bridge from a profile to the engine's
    /// existing <see cref="VlessConfig"/> (which already carries every per-protocol field).
    /// </summary>
    public class ProxyProfile
    {
        public string Id = Guid.NewGuid().ToString();
        public string Protocol;          // "vless" | "vmess" | "shadowsocks" | "socks" | "http" | "https"
        public string Name;              // display name (from #fragment / ps)
        public string Remark;

        /// <summary>Origin group: null/"manual" = hand-added; otherwise a Subscription.Id. Sub tabs are kept
        /// separate and never deduped against Manual (a hand-added and a sub-fetched same server coexist).</summary>
        public string Group;

        public string Server;
        public int Port;

        public string Uuid;              // vless / vmess id
        public string Password;          // shadowsocks password

        public string Network = "tcp";   // "tcp" | "ws"
        public string WsPath = "/";
        public string WsHost;
        /// <summary>TCP header camouflage: "http" (Xray tcpSettings.header.type) or null/"none". Uses WsHost / WsPath
        /// as the camouflage Host list / request path list (the share link's host= / path=).</summary>
        public string HeaderType;

        public bool UseTls;
        public string Sni;
        public bool AllowInsecure;

        /// <summary>VLESS security=reality (UseTls is also true). Share link pbk / sid / fp / spx; Sni = the server name
        /// the REALITY server impersonates (must be in its serverNames).</summary>
        public bool Reality;
        public string RealityPublicKey;  // pbk: the server's X25519 public key (base64url)
        public string RealityShortId;    // sid: 0–16 hex chars
        public string Fingerprint;       // fp: uTLS fingerprint name (chrome / edge / …) — picks our ClientHello shape (REALITY, tls+Vision)
        public string SpiderX;           // spx: Xray's fallback-crawler path (camouflage only; kept for export)
        /// <summary>VLESS flow: "xtls-rprx-vision" (XTLS Vision — tcp + tls/reality) or null. Other flows are kept
        /// verbatim but leave the profile unsupported.</summary>
        public string Flow;

        /// <summary>XHTTP share-link mode (stream-one / packet-up / auto / stream-up) and raw "extra" JSON.</summary>
        public string XhttpMode;
        public string XhttpExtra;

        public string SsMethod;
        public string VmessSecurity = "auto";

        /// <summary>SOCKS5 / HTTP(S) outbound proxy credentials (optional).</summary>
        public string ProxyUser;
        public string ProxyPass;

        /// <summary>True when this server was recognized + imported but the managed engine can't run it
        /// (Reality/XTLS/Hysteria/TUIC/XHTTP/etc.). It's kept in the list (greyed) so the user sees it, but it
        /// can't be set active / started. <see cref="UnsupportedReason"/> explains why.</summary>
        public bool Unsupported;
        public string UnsupportedReason;

        /// <summary>Maps this profile to the engine's per-protocol config (one bridge point).</summary>
        public VlessConfig ToEngineConfig()
        {
            var c = new VlessConfig
            {
                Protocol = Protocol,
                ServerHost = Server,
                ServerPort = Port,
                Network = string.IsNullOrEmpty(Network) ? "tcp" : Network,
                WsPath = string.IsNullOrEmpty(WsPath) ? "/" : WsPath,
                WsHost = WsHost,
                Sni = Sni,
                AllowInsecure = AllowInsecure
            };

            switch (Protocol)
            {
                case "vless":
                    c.Uuid = Uuid;
                    c.UseTls = UseTls;   // security=tls vs none (was never passed → every VLESS server was dialed with TLS)
                    c.HeaderType = TcpHeader();
                    c.Flow = CS_Ray.Core.Protocol.VlessProtocol.NormalizeFlow(Flow);
                    c.XhttpExtra = XhttpExtra;
                    c.Fingerprint = Fingerprint;
                    if (Reality)
                        c.Reality = new Transport.Tls13.RealityConfig
                        {
                            // Never let SNI fall back to a pinned dial IP: an empty sni means the server hostname (Xray).
                            ServerName = string.IsNullOrEmpty(Sni) ? Server : Sni,
                            PublicKey = Transport.Tls13.RealityConfig.ParsePublicKey(RealityPublicKey),
                            ShortId = Transport.Tls13.RealityConfig.ParseShortId(RealityShortId) ?? new byte[0],
                            Fingerprint = Fingerprint,
                        };
                    break;
                case "vmess":
                    c.VmessId = Uuid;
                    c.HeaderType = TcpHeader();
                    c.VmessSecurity = string.IsNullOrEmpty(VmessSecurity) ? "auto" : VmessSecurity;
                    break;
                case "shadowsocks":
                    c.SsMethod = SsMethod;
                    c.SsPassword = Password;
                    break;
                case "socks":
                case "http":
                case "https":
                    c.ProxyUser = ProxyUser;
                    c.ProxyPass = ProxyPass;
                    break;
            }
            return c;
        }

        // The http header camouflage only exists for the plain tcp transport.
        private string TcpHeader()
            => string.Equals(Network ?? "tcp", "tcp", StringComparison.OrdinalIgnoreCase)
               && string.Equals(HeaderType, "http", StringComparison.OrdinalIgnoreCase) ? "http" : null;
    }
}

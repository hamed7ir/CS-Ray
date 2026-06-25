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

        public bool UseTls;
        public string Sni;
        public bool AllowInsecure;

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
                    break;
                case "vmess":
                    c.VmessId = Uuid;
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
    }
}

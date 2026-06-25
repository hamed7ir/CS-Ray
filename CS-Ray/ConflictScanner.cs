using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace CS_Ray
{
    /// <summary>
    /// Detects other proxy/VPN apps that also manipulate routes/DNS — two route-managers at once is a real
    /// DNS/IP-leak risk. It only WARNS: force-killing a proxy mid-operation can strand ITS routes/adapter and
    /// cause the very leaks we avoid, so CS-Ray never Kills. An explicit user click may attempt a GRACEFUL close
    /// (<see cref="Process.CloseMainWindow"/>, never <see cref="Process.Kill"/>).
    /// </summary>
    internal static class ConflictScanner
    {
        // Easily-editable list of known proxy/VPN app process names (lowercase, no ".exe").
        public static readonly string[] KnownProxyApps =
        {
            "v2rayn", "v2rayng", "xray", "sing-box", "singbox", "nekoray", "nekobox",
            "clash", "clash-verge", "clash-verge-rev", "clash-meta", "clashx", "mihomo",
            "v2raya", "hiddify", "hiddify-next", "tun2socks"
        };

        public static List<string> Detect()
        {
            var found = new List<string>();
            int self = SafeSelfId();
            Process[] procs;
            try { procs = Process.GetProcesses(); } catch { return found; }
            foreach (var p in procs)
            {
                try
                {
                    if (p.Id == self) continue;
                    string n = p.ProcessName.ToLowerInvariant();
                    if (Array.IndexOf(KnownProxyApps, n) >= 0 && !found.Contains(p.ProcessName))
                        found.Add(p.ProcessName);
                }
                catch { }
                finally { try { p.Dispose(); } catch { } }
            }
            return found;
        }

        /// <summary>Best-effort GRACEFUL close (CloseMainWindow only) — returns how many were signaled. Never Kill.</summary>
        public static int TryGracefulClose()
        {
            int n = 0, self = SafeSelfId();
            Process[] procs;
            try { procs = Process.GetProcesses(); } catch { return 0; }
            foreach (var p in procs)
            {
                try
                {
                    if (p.Id == self) continue;
                    if (Array.IndexOf(KnownProxyApps, p.ProcessName.ToLowerInvariant()) >= 0 && p.CloseMainWindow())
                        n++;
                }
                catch { }
                finally { try { p.Dispose(); } catch { } }
            }
            return n;
        }

        private static int SafeSelfId()
        {
            try { return Process.GetCurrentProcess().Id; } catch { return -1; }
        }
    }
}

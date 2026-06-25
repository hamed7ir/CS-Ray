using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace CS_Ray.Core.Tun
{
    /// <summary>
    /// Phase 2 TUN networking: assign the adapter an IPv4 /30, disable IPv6 on it, add ONE test
    /// route capturing a single destination to the adapter, and pin the proxy server's IP to the
    /// REAL default gateway (the loop-guard that keeps engine-outbound traffic off the TUN adapter).
    /// Routes NOTHING through the engine. Every change is recorded and reversed on <see cref="Restore"/>.
    /// </summary>
    public class TunNetwork
    {
        public const string TunIp = "10.18.0.2";
        public const string TunMask = "255.255.255.252"; // /30
        public const string TunGateway = "10.18.0.1";

        private readonly Action<string> _log;
        private readonly List<string[]> _routes = new List<string[]>(); // { prefix, ifIndex }
        private string _alias;
        private uint _tunIfIndex;
        private bool _ipv6Disabled;
        private bool _physV6Disabled;     // we disabled IPv6 on the PHYSICAL NIC (full tunnel) — re-enable on restore
        private uint _physV6Index;        // the physical ifIndex we disabled it on
        private bool _dnsSet;
        private bool _physDnsSet;         // we overrode the PHYSICAL NIC's IPv4 DNS — restore the snapshot on teardown
        private uint _physDnsIndex;
        private bool _physDnsWasDhcp;
        private System.Collections.Generic.List<string> _physDnsServers; // snapshot of prior static servers (in order)
        private bool _physDefRemoved;     // we removed the PHYSICAL NIC's 0.0.0.0/0 default route — re-add on teardown
        private uint _physDefIndex;
        private string _physDefGateway;
        private string _physDefMetric;

        /// <summary>Physical NIC interface index discovered for the loop-guard (0 if none) — used by the UDP relay.</summary>
        public uint PhysicalIfIndex { get; private set; }

        private static TunNetwork s_active;

        public TunNetwork(Action<string> log) { _log = log; }

        public bool Apply(IntPtr adapter, string serverHostOrIp, int serverPort, string testTargetIp, bool routeAll, int enginePort, Action<uint> onPhysIfIndex, Action<string> onServerIp = null)
        {
            if (adapter == IntPtr.Zero) { _log?.Invoke("TUN net: no adapter."); return false; }

            WintunApi.WintunGetAdapterLUID(adapter, out ulong luid);
            if (ConvertInterfaceLuidToIndex(ref luid, out uint tunIdx) != 0) { _log?.Invoke("TUN net: LUID→index failed."); return false; }
            var sb = new StringBuilder(257);
            ConvertInterfaceLuidToAlias(ref luid, sb, (UIntPtr)257);
            _alias = sb.ToString();
            _tunIfIndex = tunIdx;
            _log?.Invoke("TUN net: adapter ifIndex=" + tunIdx + " alias='" + _alias + "'.");

            // 1) IPv4 address (NO gateway → no default route hijack in phase 2).
            Run("netsh", "interface ipv4 set address name=\"" + _alias + "\" static " + TunIp + " " + TunMask, out var oIp);
            _log?.Invoke("TUN net: IPv4 " + TunIp + "/30 -> " + Brief(oIp));

            // 2) Disable IPv6 on the adapter (best-effort) to stop the ND noise.
            if (Run("powershell", "-NoProfile -Command \"Disable-NetAdapterBinding -Name '" + _alias + "' -ComponentID ms_tcpip6 -ErrorAction Stop\"", out var oV6))
            { _ipv6Disabled = true; _log?.Invoke("TUN net: IPv6 disabled on adapter."); }
            else _log?.Invoke("TUN net: IPv6 disable best-effort failed (" + Brief(oV6) + ") — continuing.");

            s_active = this; // registered now so an abort path's Restore() fully reverts

            // Resolve server + find the PHYSICAL default gateway once (skipping any on-link TUN default).
            var serverIp = ResolveIPv4(serverHostOrIp);
            PacketFilter.BypassServerIp = serverIp != null ? ToDword(serverIp) : 0;
            bool havePhys = FindPhysicalDefaultGateway(tunIdx, out uint gw, out uint oidx);
            string gwStr = havePhys ? new IPAddress(BitConverter.GetBytes(gw)).ToString() : null;
            if (havePhys) { PhysicalIfIndex = oidx; onPhysIfIndex?.Invoke(oidx); }

            // ---- Full-tunnel preconditions (verify IN ORDER; abort cleanly if any fails) ----
            if (routeAll)
            {
                bool engineOk = EngineReachable(enginePort);
                _log?.Invoke("TUN precond [1] engine 127.0.0.1:" + enginePort + " reachable: " + (engineOk ? "YES" : "NO"));
                _log?.Invoke("TUN precond [2] proxy server '" + serverHostOrIp + "' resolved: " + (serverIp ?? "NO"));
                _log?.Invoke("TUN precond [3] physical gateway: " + (havePhys ? gwStr + " if " + oidx : "NONE"));
                if (!engineOk) return Abort("engine not reachable — start an engine profile first");
                if (serverIp == null) return Abort("proxy server did not resolve");
                if (!havePhys) return Abort("no physical default gateway (disable other VPN/TUN)");

                // Pin the resolved server IP so the engine/UDP sessions dial it directly (no per-connection DNS).
                onServerIp?.Invoke(serverIp);
            }

            // Loop-guard: pin the proxy server's IP to the physical gateway BEFORE any default capture.
            bool lgOk = serverIp != null && havePhys && AddRoute(serverIp + "/32", oidx, gwStr, "loop-guard");
            if (!lgOk && !routeAll)
                _log?.Invoke("TUN net: loop-guard skipped (server resolve=" + (serverIp != null) + ", physGw=" + havePhys + ").");

            if (routeAll)
            {
                _log?.Invoke("TUN precond [4] loop-guard route added: " + (lgOk ? "YES" : "NO"));
                if (!lgOk) return Abort("loop-guard route failed");

                // Private ranges → DIRECT via the physical gateway (longer prefixes outrank the /1 capture).
                AddRoute("10.0.0.0/8", oidx, gwStr, "bypass");
                AddRoute("172.16.0.0/12", oidx, gwStr, "bypass");
                AddRoute("192.168.0.0/16", oidx, gwStr, "bypass");
                AddRoute("169.254.0.0/16", oidx, gwStr, "bypass");

                // Default capture: 0.0.0.0/1 + 128.0.0.0/1 via the TUN gateway outrank the real default
                // (0.0.0.0/0) without deleting it → clean restore.
                AddRoute("0.0.0.0/1", tunIdx, TunGateway, "default-capture");
                AddRoute("128.0.0.0/1", tunIdx, TunGateway, "default-capture");

                // Use the interface INDEX + validate=no — works on Win10 ARM32 AND RT 8.1 (the alias/
                // validating form fails on RT with "configured DNS server is incorrect"). If it still
                // fails, DNS works anyway via capture+relay (direct or, when leak-proof, over the engine).
                bool dnsOk = Run("netsh", "interface ipv4 set dnsservers name=" + tunIdx + " static 8.8.8.8 primary validate=no", out var oD);
                _dnsSet = dnsOk;
                _log?.Invoke("TUN net: adapter DNS -> 8.8.8.8 (if " + tunIdx + ") -> " + (dnsOk ? "OK" : "FAILED (" + Brief(oD) + ") — DNS still works via capture+relay"));

                // Kill IPv6 on the PHYSICAL NIC for the tunnel's duration. Our TUN is IPv4-only; if the
                // physical adapter keeps native IPv6, the OS sends WebRTC/STUN/traffic straight out over v6,
                // bypassing the tunnel = a public-IPv6 leak. Snapshot prior state; restore exactly on stop.
                DisablePhysicalIpv6(oidx);

                // Force the PHYSICAL NIC's IPv4 DNS to our resolver too — some apps/resolvers (e.g. Firefox)
                // query the physical adapter's ISP DNS directly, which would leak. This is now LOOP-FREE because
                // the engine + VLESS UDP dial the pinned ServerIp (no per-connection DNS for the server), so the
                // old resolve-server → DNS → TUN → resolve-server deadlock can't happen. App DNS is also kept
                // leak-safe by the in-tunnel UDP/53 → DnsResolver redirect. Snapshot prior config; restore on stop.
                SetPhysicalDns(oidx);

                _log?.Invoke("TUN precond [5] default capture installed: YES. FULL TUNNEL ready.");

                // E3b: remove the PHYSICAL NIC's 0.0.0.0/0 default route. WebRTC/ICE binds a UDP socket to the
                // physical NIC's IP and srflx-gathers via THAT default route, bypassing the TUN (the real-IP leak).
                // Safe to remove because: the server stays reachable via the more-specific /32 loop-guard (pinned
                // ServerIp via the physical gateway); all normal traffic already rides the /1+/1 capture via TUN;
                // LAN bypass + on-link connected routes remain. Only physical-default-dependent sends (the leak
                // path) lose their exit → ICE STUN can only survive through the tunnel → WebRTC shows the exit IP.
                RemovePhysicalDefaultRoute(oidx, gwStr);

                // Self-check: the engine MUST still reach the pinned server via the /32 loop-guard. If not, the
                // /32 is missing/wrong — re-add the default route (via Abort→Restore) rather than brick the box.
                if (_physDefRemoved && serverIp != null && serverPort > 0 && !TcpReachable(serverIp, serverPort, 3000))
                    return Abort("server " + serverIp + ":" + serverPort + " unreachable after removing physical default route (loop-guard /32 missing?)");
            }
            else if (!string.IsNullOrEmpty(testTargetIp) && IPAddress.TryParse(testTargetIp, out _))
            {
                AddRoute(testTargetIp + "/32", tunIdx, TunGateway, "TEST");
            }
            else _log?.Invoke("TUN net: no Test IP entered — no destination captured.");

            return true;
        }

        private bool Abort(string why)
        {
            _log?.Invoke("TUN: FULL TUNNEL ABORTED — " + why + ". Reverting (no default route installed).");
            Restore();
            return false;
        }

        // Disable the IPv6 binding on the physical NIC (by interface index) so nothing leaks over native v6
        // while the v4-only tunnel is up. Only re-enabled on restore if WE turned it off (snapshot prior state).
        private void DisablePhysicalIpv6(uint physIndex)
        {
            if (physIndex == 0) return;
            // One PowerShell pass: if the binding is currently enabled, disable it and report DISABLED; else leave it.
            string cmd = "-NoProfile -Command \"" +
                "$a = Get-NetAdapter -InterfaceIndex " + physIndex + " -ErrorAction Stop; " +
                "$b = $a | Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop; " +
                "if ($b.Enabled) { $a | Disable-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction Stop; 'DISABLED' } else { 'ALREADYOFF' }\"";
            bool ok = Run("powershell", cmd, out var o);
            if (ok && o.IndexOf("DISABLED", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                _physV6Disabled = true; _physV6Index = physIndex;
                _log?.Invoke("TUN net: IPv6 disabled on PHYSICAL NIC (if " + physIndex + ") — no native-v6 leak.");
            }
            else if (ok && o.IndexOf("ALREADYOFF", StringComparison.OrdinalIgnoreCase) >= 0)
                _log?.Invoke("TUN net: physical NIC IPv6 already off (if " + physIndex + ") — left as-is.");
            else
                _log?.Invoke("TUN net: physical IPv6 disable best-effort failed (" + Brief(o) + ") — continuing (v6 may leak; report if so).");
        }

        // Snapshot the physical NIC's IPv4 DNS, then point it at our resolver so apps that query the adapter's
        // ISP DNS directly (e.g. Firefox) can't leak. Restored exactly on teardown. Loop-free under IP-pinning.
        private void SetPhysicalDns(uint physIndex)
        {
            if (physIndex == 0 || _physDnsSet) return;   // never stack a second override
            string resolver = ResolverDotted();
            if (resolver == null) return;

            // Snapshot current config (DHCP vs static, and the static server list) before overriding.
            bool wasDhcp; System.Collections.Generic.List<string> servers;
            if (Run("netsh", "interface ipv4 show dnsservers name=" + physIndex, out var show))
            {
                wasDhcp = show.IndexOf("DHCP", StringComparison.OrdinalIgnoreCase) >= 0;
                servers = ExtractIPv4s(show);
            }
            else { wasDhcp = true; servers = null; } // safe default: restore to DHCP

            // Stale-state safety: if the only configured server is already OUR resolver as static, this is a
            // leftover from a prior crash (not the user's real config) — treat it as DHCP so we never restore 8.8.8.8.
            if (!wasDhcp && servers != null && servers.Count == 1 && servers[0] == resolver)
            {
                wasDhcp = true; servers = null;
                _log?.Invoke("TUN net: physical NIC DNS was already " + resolver + " (stale override from a prior crash) — will restore to DHCP.");
            }

            bool ok = Run("netsh", "interface ipv4 set dnsservers name=" + physIndex + " static " + resolver + " primary validate=no", out var o);
            if (ok)
            {
                _physDnsSet = true; _physDnsIndex = physIndex; _physDnsWasDhcp = wasDhcp; _physDnsServers = servers;
                _log?.Invoke("TUN net: physical NIC IPv4 DNS -> " + resolver + " (if " + physIndex + "; was " +
                    (wasDhcp ? "DHCP" : (servers != null && servers.Count > 0 ? string.Join(",", servers.ToArray()) : "none")) + ").");
            }
            else
                _log?.Invoke("TUN net: physical DNS override best-effort failed (" + Brief(o) + ") — continuing (UDP/53 redirect still forces " + resolver + ").");
        }

        private void RestorePhysicalDns()
        {
            if (!_physDnsSet || _physDnsIndex == 0) return;
            if (_physDnsWasDhcp || _physDnsServers == null || _physDnsServers.Count == 0)
            {
                Run("netsh", "interface ipv4 set dnsservers name=" + _physDnsIndex + " dhcp", out _);
                _log?.Invoke("TUN net: physical NIC DNS restored to DHCP (if " + _physDnsIndex + ").");
            }
            else
            {
                Run("netsh", "interface ipv4 set dnsservers name=" + _physDnsIndex + " static " + _physDnsServers[0] + " primary validate=no", out _);
                for (int i = 1; i < _physDnsServers.Count; i++)
                    Run("netsh", "interface ipv4 add dnsservers name=" + _physDnsIndex + " address=" + _physDnsServers[i] + " index=" + (i + 1) + " validate=no", out _);
                _log?.Invoke("TUN net: physical NIC DNS restored to " + string.Join(",", _physDnsServers.ToArray()) + " (if " + _physDnsIndex + ").");
            }
            _physDnsSet = false; _physDnsIndex = 0; _physDnsWasDhcp = false; _physDnsServers = null; // clear snapshot after restore
        }

        // Our configured resolver (PacketFilter.DnsResolver, host-order uint) as dotted IPv4, or null if unset.
        private static string ResolverDotted()
        {
            uint r = PacketFilter.DnsResolver;
            if (r == 0) return null;
            return ((r >> 24) & 0xFF) + "." + ((r >> 16) & 0xFF) + "." + ((r >> 8) & 0xFF) + "." + (r & 0xFF);
        }

        private static System.Collections.Generic.List<string> ExtractIPv4s(string text)
        {
            var list = new System.Collections.Generic.List<string>();
            foreach (System.Text.RegularExpressions.Match m in
                     System.Text.RegularExpressions.Regex.Matches(text ?? "", @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"))
            {
                if (IPAddress.TryParse(m.Value, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork && !list.Contains(m.Value))
                    list.Add(m.Value);
            }
            return list;
        }

        // Remove the physical NIC's 0.0.0.0/0 default route (snapshot metric+gateway first for exact restore).
        // Only snapshots once; if there is no default route to remove, leaves state untouched.
        private void RemovePhysicalDefaultRoute(uint physIndex, string fallbackGateway)
        {
            if (_physDefRemoved || physIndex == 0) return;
            if (!GetPhysicalDefaultRoute(physIndex, out string metric, out string gateway))
            {
                _log?.Invoke("TUN net: no physical default route on if " + physIndex + " to remove — skipping (WebRTC may still leak; report).");
                return;
            }
            if (string.IsNullOrEmpty(gateway)) gateway = fallbackGateway;

            bool ok = Run("netsh", "interface ipv4 delete route prefix=0.0.0.0/0 interface=" + physIndex + " nexthop=" + gateway, out var o);
            if (ok)
            {
                _physDefRemoved = true; _physDefIndex = physIndex; _physDefGateway = gateway; _physDefMetric = metric;
                _log?.Invoke("TUN net: physical default route 0.0.0.0/0 via " + gateway + " (if " + physIndex + ", metric " + metric + ") REMOVED — closes WebRTC/ICE physical-egress leak.");
            }
            else
                _log?.Invoke("TUN net: physical default route removal failed (" + Brief(o) + ") — continuing (WebRTC may leak).");
        }

        private void RestorePhysicalDefaultRoute()
        {
            if (!_physDefRemoved || _physDefIndex == 0) return;
            // Reconcile: if the OS (DHCP) already re-added a default route on this iface, don't duplicate it.
            if (GetPhysicalDefaultRoute(_physDefIndex, out _, out string curGw))
                _log?.Invoke("TUN net: physical default route already present (if " + _physDefIndex + ", via " + curGw + ") — not re-adding.");
            else
            {
                string args = "interface ipv4 add route prefix=0.0.0.0/0 interface=" + _physDefIndex + " nexthop=" + _physDefGateway + " store=active";
                if (!string.IsNullOrEmpty(_physDefMetric)) args += " metric=" + _physDefMetric;
                Run("netsh", args, out var o);
                _log?.Invoke("TUN net: physical default route restored 0.0.0.0/0 via " + _physDefGateway + " (if " + _physDefIndex + ", metric " + _physDefMetric + ") -> " + Brief(o));
            }
            _physDefRemoved = false; _physDefIndex = 0; _physDefGateway = null; _physDefMetric = null;
        }

        // Parse `netsh interface ipv4 show route` for the 0.0.0.0/0 row on the given ifIndex. Data rows are
        // numeric (Publish Type Met Prefix Idx Gateway), so this is language-independent.
        private bool GetPhysicalDefaultRoute(uint physIndex, out string metric, out string gateway)
        {
            metric = null; gateway = null;
            if (!Run("netsh", "interface ipv4 show route", out var outp)) return false;
            foreach (var line in outp.Split('\n'))
            {
                var m = System.Text.RegularExpressions.Regex.Match(line, @"^\s*\S+\s+\S+\s+(\d+)\s+0\.0\.0\.0/0\s+(\d+)\s+(\S+)");
                if (m.Success && m.Groups[2].Value == physIndex.ToString())
                {
                    metric = m.Groups[1].Value; gateway = m.Groups[3].Value; return true;
                }
            }
            return false;
        }

        private static bool EngineReachable(int port)
        {
            try
            {
                using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    var ar = s.BeginConnect(IPAddress.Loopback, port, null, null);
                    if (ar.AsyncWaitHandle.WaitOne(1000) && s.Connected) { s.EndConnect(ar); return true; }
                    return false;
                }
            }
            catch { return false; }
        }

        // TCP-connect probe to an arbitrary IPv4:port (used to confirm the server is still reachable via the
        // /32 loop-guard after removing the physical default route).
        private static bool TcpReachable(string ip, int port, int timeoutMs)
        {
            try
            {
                using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                {
                    var ar = s.BeginConnect(IPAddress.Parse(ip), port, null, null);
                    if (ar.AsyncWaitHandle.WaitOne(timeoutMs) && s.Connected) { s.EndConnect(ar); return true; }
                    return false;
                }
            }
            catch { return false; }
        }

        // Big-endian dword (d0 high byte) to match PacketFilter's dst computation.
        private static uint ToDword(string ip)
        {
            var b = IPAddress.Parse(ip).GetAddressBytes();
            return (uint)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
        }

        private static bool AlreadyExists(string netshOutput)
            => netshOutput != null && netshOutput.IndexOf("already exists", StringComparison.OrdinalIgnoreCase) >= 0;

        private bool AddRoute(string prefix, uint ifIndex, string nexthop, string label)
        {
            string addArgs = "interface ipv4 add route prefix=" + prefix + " interface=" + ifIndex + " nexthop=" + nexthop + " store=active";
            bool ok = Run("netsh", addArgs, out var o);

            // Stale-state tolerance (same as our DNS/default-route restores): an active-store route survives a
            // force-kill/crash — TerminateProcess doesn't drop it, and the crash-restore handler never runs on a
            // hard kill. A leftover loop-guard /32 must NOT permanently block TUN. If the add reports "already
            // exists", delete the leftover (any interface) and re-add it as ours; if it still reports present,
            // accept it. Either way it gets RECORDED below so teardown removes it.
            if (!ok && AlreadyExists(o))
            {
                Run("netsh", "interface ipv4 delete route prefix=" + prefix, out _);
                ok = Run("netsh", addArgs, out o);
                if (!ok && AlreadyExists(o)) ok = true; // accept-if-present
                if (ok) _log?.Invoke("TUN net: " + label + " route " + prefix + " pre-existed (stale leftover) — reclaimed.");
            }

            // Record EVERY route we own (including a reclaimed one) so Restore() always deletes it — even when the
            // add "failed" only because the route was already present.
            if (ok) _routes.Add(new[] { prefix, ifIndex.ToString() });
            _log?.Invoke("TUN net: " + label + " route " + prefix + " via " + nexthop + " if " + ifIndex + " -> " + (ok ? "OK" : "FAILED: " + Brief(o)));
            return ok;
        }

        public void Restore()
        {
            PacketFilter.BypassServerIp = 0;
            foreach (var r in _routes)
            {
                Run("netsh", "interface ipv4 delete route prefix=" + r[0] + " interface=" + r[1], out var o);
                _log?.Invoke("TUN net: removed route " + r[0] + " if " + r[1] + " -> " + Brief(o));
            }
            _routes.Clear();

            RestorePhysicalDefaultRoute();

            if (_dnsSet && _tunIfIndex != 0)
            {
                Run("netsh", "interface ipv4 set dnsservers name=" + _tunIfIndex + " dhcp", out _);
                _dnsSet = false;
                _log?.Invoke("TUN net: adapter DNS reset to DHCP.");
            }

            if (_ipv6Disabled && !string.IsNullOrEmpty(_alias))
            {
                Run("powershell", "-NoProfile -Command \"Enable-NetAdapterBinding -Name '" + _alias + "' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue\"", out _);
                _ipv6Disabled = false;
                _log?.Invoke("TUN net: IPv6 re-enabled on adapter.");
            }

            if (_physV6Disabled && _physV6Index != 0)
            {
                Run("powershell", "-NoProfile -Command \"Get-NetAdapter -InterfaceIndex " + _physV6Index +
                    " -ErrorAction SilentlyContinue | Enable-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue\"", out _);
                _physV6Disabled = false;
                _log?.Invoke("TUN net: IPv6 re-enabled on PHYSICAL NIC (if " + _physV6Index + ").");
                _physV6Index = 0;
            }

            RestorePhysicalDns();

            if (s_active == this) s_active = null;
            _log?.Invoke("TUN net: routing restored.");
        }

        /// <summary>Restore from process exit/crash handlers (before the adapter is closed).</summary>
        public static void RestoreActive() { try { s_active?.Restore(); } catch { } }

        private static string ResolveIPv4(string host)
        {
            if (string.IsNullOrWhiteSpace(host)) return null;
            if (IPAddress.TryParse(host, out var ip)) return ip.AddressFamily == AddressFamily.InterNetwork ? ip.ToString() : null;
            try
            {
                foreach (var a in Dns.GetHostAddresses(host))
                    if (a.AddressFamily == AddressFamily.InterNetwork) return a.ToString();
            }
            catch { }
            return null;
        }

        // Pick the default route (0.0.0.0/0) with a real next hop, lowest metric, excluding OUR OWN
        // TUN interface (so we never loop-guard the server back through CS-Ray's adapter). NOTE: a
        // co-existing third-party TUN (e.g. xray_tun) also presents a non-zero-nexthop default and is
        // indistinguishable here — disable other tun2socks before relying on this.
        private bool FindPhysicalDefaultGateway(uint excludeIfIndex, out uint gateway, out uint ifIndex)
        {
            gateway = 0; ifIndex = 0;
            int size = 0;
            GetIpForwardTable(IntPtr.Zero, ref size, true); // sizing call → ERROR_INSUFFICIENT_BUFFER
            if (size <= 0) return false;

            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (GetIpForwardTable(buf, ref size, true) != 0) return false;
                int n = Marshal.ReadInt32(buf); // dwNumEntries
                int rowSize = Marshal.SizeOf(typeof(MIB_IPFORWARDROW));
                uint best = uint.MaxValue;
                for (int i = 0; i < n; i++)
                {
                    var row = (MIB_IPFORWARDROW)Marshal.PtrToStructure(IntPtr.Add(buf, 4 + i * rowSize), typeof(MIB_IPFORWARDROW));
                    if (row.dwForwardDest == 0 && row.dwForwardMask == 0 && row.dwForwardNextHop != 0 &&
                        row.dwForwardIfIndex != excludeIfIndex && row.dwForwardMetric1 < best)
                    {
                        best = row.dwForwardMetric1;
                        gateway = row.dwForwardNextHop;
                        ifIndex = row.dwForwardIfIndex;
                    }
                }
                return gateway != 0;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private bool Run(string exe, string args, out string output)
        {
            try
            {
                var psi = new ProcessStartInfo(exe, args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using (var p = Process.Start(psi))
                {
                    output = (p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd()).Trim();
                    p.WaitForExit(15000);
                    return p.ExitCode == 0;
                }
            }
            catch (Exception ex) { output = ex.Message; return false; }
        }

        private static string Brief(string s)
        {
            if (string.IsNullOrEmpty(s)) return "Ok.";
            s = s.Replace("\r", " ").Replace("\n", " ").Trim();
            return s.Length > 70 ? s.Substring(0, 70) + "…" : s;
        }

        // ---- IP Helper P/Invoke ----
        [DllImport("iphlpapi.dll")]
        private static extern int ConvertInterfaceLuidToIndex(ref ulong interfaceLuid, out uint interfaceIndex);

        [DllImport("iphlpapi.dll", CharSet = CharSet.Unicode)]
        private static extern int ConvertInterfaceLuidToAlias(ref ulong interfaceLuid, StringBuilder interfaceAlias, UIntPtr length);

        [DllImport("iphlpapi.dll")]
        private static extern int GetIpForwardTable(IntPtr pIpForwardTable, ref int pdwSize, bool bOrder);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_IPFORWARDROW
        {
            public uint dwForwardDest;
            public uint dwForwardMask;
            public uint dwForwardPolicy;
            public uint dwForwardNextHop;
            public uint dwForwardIfIndex;
            public uint dwForwardType;
            public uint dwForwardProto;
            public uint dwForwardAge;
            public uint dwForwardNextHopAS;
            public uint dwForwardMetric1;
            public uint dwForwardMetric2;
            public uint dwForwardMetric3;
            public uint dwForwardMetric4;
            public uint dwForwardMetric5;
        }
    }
}

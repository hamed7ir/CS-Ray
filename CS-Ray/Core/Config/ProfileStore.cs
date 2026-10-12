using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;

namespace CS_Ray.Core.Config
{
    /// <summary>
    /// Persists the profile list + active selection to profiles.json next to the exe.
    /// A missing or corrupt file degrades to an empty list (never throws/crashes).
    /// Stores only what's in <see cref="ProxyProfile"/>.
    /// </summary>
    public class ProfileStore
    {
        private class StoreData
        {
            public List<ProxyProfile> Profiles { get; set; }
            public string ActiveProfileId { get; set; }
            public string DelayTestUrl { get; set; }
            public List<Subscription> Subscriptions { get; set; }
            public string ThemeMode { get; set; }
            public string AccentColor { get; set; }
            public bool BlockQuic { get; set; }
            public bool UseManagedTls { get; set; }
            public bool VlessSecurityHonored { get; set; }
        }

        public const string ManualGroup = "manual";

        private readonly string _path;

        public List<ProxyProfile> Profiles { get; private set; } = new List<ProxyProfile>();
        public string ActiveProfileId { get; set; }
        public List<Subscription> Subscriptions { get; private set; } = new List<Subscription>();

        /// <summary>User's preferred delay-test target URL (null = use the built-in default).</summary>
        public string DelayTestUrl { get; set; }

        /// <summary>Persisted theme: "System" | "Dark" | "Light" (null = System).</summary>
        public string ThemeMode { get; set; }

        /// <summary>Persisted accent override "#RRGGBB" (null/empty = follow the Windows accent).</summary>
        public string AccentColor { get; set; }

        /// <summary>Persisted Block-QUIC (UDP/443 drop) preference.</summary>
        public bool BlockQuic { get; set; }

        /// <summary>Use the managed BouncyCastle TLS 1.3 engine instead of SslStream (experimental; default off).</summary>
        public bool UseManagedTls { get; set; }

        /// <summary>True once saved VLESS profiles were migrated to the engine honoring UseTls (see <see cref="Load"/>).</summary>
        public bool VlessSecurityHonored { get; private set; }

        /// <summary>Set by <see cref="Load"/> when it just migrated older data; the caller should Save() once.</summary>
        public bool MigratedOnLoad { get; private set; }

        /// <summary>A profile's effective group id (null/empty → Manual).</summary>
        public static string GroupOf(ProxyProfile p) => string.IsNullOrEmpty(p.Group) ? ManualGroup : p.Group;

        public ProfileStore(string path) { _path = path; }

        private static string _resolvedPath;
        private static string _resolutionInfo;

        /// <summary>The profiles.json path, resolved ONCE by probing for a genuinely writable location and cached.
        /// Order: Documents → %APPDATA% → beside-exe. (Documents is first because it's the proven-writable spot on
        /// jailbroken Windows RT 8.1, where %APPDATA% is unreliable.)</summary>
        public static string DefaultPath => _resolvedPath ?? (_resolvedPath = Resolve());

        /// <summary>Human-readable note on which location won (and any migration) — log it once at startup.</summary>
        public static string ResolutionInfo => _resolutionInfo;

        private static string Resolve()
        {
            // (label, directory) candidates in priority order. Documents/AppData get a CS-Ray subfolder; the
            // beside-exe fallback keeps profiles.json directly next to the exe (portable convention).
            var tried = new List<KeyValuePair<string, string>>();
            string docs = SafeFolder(Environment.SpecialFolder.MyDocuments);
            if (docs != null) tried.Add(new KeyValuePair<string, string>("Documents", Path.Combine(docs, "CS-Ray")));
            string appdata = SafeFolder(Environment.SpecialFolder.ApplicationData);
            if (appdata != null) tried.Add(new KeyValuePair<string, string>("AppData", Path.Combine(appdata, "CS-Ray")));
            tried.Add(new KeyValuePair<string, string>("beside-exe", AppDomain.CurrentDomain.BaseDirectory));

            var failures = new List<string>();
            foreach (var c in tried)
            {
                // The decisive test: actually create the dir + write+delete a probe file. SpecialFolder paths can
                // exist yet be non-writable (RT 8.1), so Directory.Exists is NOT enough.
                if (!IsWritable(c.Value)) { failures.Add(c.Key + " not writable"); continue; }
                string chosen = Path.Combine(c.Value, "profiles.json");
                string note = "Settings location: " + c.Key + " → " + chosen;
                note += MigrateBesideExe(chosen);
                if (failures.Count > 0) note += "  (skipped: " + string.Join(", ", failures.ToArray()) + ")";
                _resolutionInfo = note;
                return chosen;
            }

            // Should be unreachable (beside-exe almost always passes), but never throw.
            _resolvedPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "profiles.json");
            _resolutionInfo = "Settings location: FALLBACK beside-exe (no writable location found: " + string.Join(", ", failures.ToArray()) + ")";
            return _resolvedPath;
        }

        private static string SafeFolder(Environment.SpecialFolder f)
        {
            try { var p = Environment.GetFolderPath(f); return string.IsNullOrEmpty(p) ? null : p; }
            catch { return null; }
        }

        // Create-dir + write + delete a tiny probe; any exception → not writable.
        private static bool IsWritable(string dir)
        {
            try
            {
                if (string.IsNullOrEmpty(dir)) return false;
                Directory.CreateDirectory(dir);
                string probe = Path.Combine(dir, ".csray_probe_" + Guid.NewGuid().ToString("N") + ".tmp");
                File.WriteAllText(probe, "ok");
                File.Delete(probe);
                return true;
            }
            catch { return false; }
        }

        // One-time migration: if the chosen location has no profiles.json yet but a beside-exe one exists (from
        // earlier local testing), copy it in so saved servers aren't lost. Returns a log suffix (or "").
        private static string MigrateBesideExe(string chosenPath)
        {
            try
            {
                if (File.Exists(chosenPath)) return "";
                string beside = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "profiles.json");
                if (!File.Exists(beside)) return "";
                if (string.Equals(Path.GetFullPath(beside), Path.GetFullPath(chosenPath), StringComparison.OrdinalIgnoreCase)) return "";
                File.Copy(beside, chosenPath, false);
                return "  (migrated existing beside-exe profiles.json)";
            }
            catch { return ""; }
        }

        public void Load()
        {
            try
            {
                // Fresh store: nothing to migrate — new profiles are created under the honored-UseTls rules.
                if (!File.Exists(_path)) { Profiles = new List<ProxyProfile>(); ActiveProfileId = null; VlessSecurityHonored = true; MigratedOnLoad = false; return; }
                var data = new JavaScriptSerializer().Deserialize<StoreData>(File.ReadAllText(_path));
                Profiles = data?.Profiles ?? new List<ProxyProfile>();
                ActiveProfileId = data?.ActiveProfileId;
                DelayTestUrl = data?.DelayTestUrl;
                Subscriptions = data?.Subscriptions ?? new List<Subscription>();
                ThemeMode = data?.ThemeMode;
                AccentColor = data?.AccentColor;
                BlockQuic = data?.BlockQuic ?? false;
                UseManagedTls = data?.UseManagedTls ?? false;

                // One-time upgrade: builds before VlessSecurityHonored dialed EVERY VLESS server with TLS whatever UseTls
                // said (Clash / sing-box subscriptions never even set it). Keep that working behavior for saved profiles —
                // TLS on — so nothing breaks on upgrade; from now on the flag is honored as stored (a subscription refresh
                // re-imports with the correct value; a security=none server is switched off per profile in Edit).
                MigratedOnLoad = false;
                VlessSecurityHonored = data?.VlessSecurityHonored ?? false;
                if (!VlessSecurityHonored)
                {
                    foreach (var pr in Profiles) if (pr != null && pr.Protocol == "vless") pr.UseTls = true;
                    VlessSecurityHonored = true;
                    MigratedOnLoad = data != null;
                }

                // VMess used to run over raw TCP only, and alterId>0 was refused. A hand-added (Manual) profile tagged for
                // those reasons kept its link's transport fields, so re-check it against today's rules — it becomes runnable
                // without a re-import. Subscription servers wait for their next refresh: older importers could store a
                // different transport (sing-box collapsed grpc/http to tcp, Clash dropped v2ray-http-upgrade), and an old
                // XHTTP import kept no mode.
                foreach (var pr in Profiles)
                    if (pr != null && pr.Unsupported && pr.Protocol == "vmess"
                        && string.Equals(GroupOf(pr), ManualGroup, StringComparison.OrdinalIgnoreCase)
                        && !string.Equals((pr.Network ?? "").Trim(), "xhttp", StringComparison.OrdinalIgnoreCase)
                        && ((pr.UnsupportedReason ?? "").StartsWith("VMess over", StringComparison.Ordinal)
                            || (pr.UnsupportedReason ?? "").StartsWith("VMess alterId", StringComparison.Ordinal)))
                    {
                        string why = LinkParser.ReasonForEditedProfile(pr);
                        pr.Unsupported = why != null;
                        pr.UnsupportedReason = why;
                    }
            }
            catch
            {
                Profiles = new List<ProxyProfile>();
                ActiveProfileId = null;
                Subscriptions = new List<Subscription>();
                VlessSecurityHonored = true; MigratedOnLoad = false;   // starting over: nothing old to migrate
            }
        }

        public void Save()
        {
            try
            {
                var json = new JavaScriptSerializer().Serialize(new StoreData
                {
                    Profiles = Profiles,
                    ActiveProfileId = ActiveProfileId,
                    DelayTestUrl = DelayTestUrl,
                    Subscriptions = Subscriptions,
                    ThemeMode = ThemeMode,
                    AccentColor = AccentColor,
                    BlockQuic = BlockQuic,
                    UseManagedTls = UseManagedTls,
                    VlessSecurityHonored = VlessSecurityHonored
                });
                File.WriteAllText(_path, json);
            }
            catch { /* read-only dir etc. — non-fatal */ }
        }

        /// <summary>Adds the profile, or replaces the one in the same group that is the SAME server (see
        /// <see cref="SameEndpoint"/>) — keeping its Id, so an active selection survives. Returns the stored profile;
        /// <paramref name="replaced"/> tells which happened.</summary>
        public ProxyProfile AddOrUpdate(ProxyProfile p, out bool replaced)
        {
            if (string.IsNullOrEmpty(p.Group)) p.Group = ManualGroup;
            // Dedup only WITHIN the same group — a Manual server and a sub server may share an endpoint.
            var existing = Profiles.FirstOrDefault(x =>
                string.Equals(GroupOf(x), GroupOf(p), StringComparison.OrdinalIgnoreCase) && SameEndpoint(x, p));
            replaced = existing != null;
            if (existing != null)
            {
                p.Id = existing.Id;
                if (string.IsNullOrEmpty(p.Name)) p.Name = existing.Name;   // a link without #name keeps the given one
                Profiles[Profiles.IndexOf(existing)] = p;
            }
            else
            {
                Profiles.Add(p);
            }
            Save();
            return p;
        }

        /// <summary>Failure-safe sub install: atomically replace a group's servers with a fresh set (the caller
        /// only calls this AFTER a successful fetch+decode, so a failed fetch never empties the group).</summary>
        public void ReplaceGroup(string groupId, List<ProxyProfile> fresh)
        {
            Profiles.RemoveAll(x => string.Equals(GroupOf(x), groupId, StringComparison.OrdinalIgnoreCase));
            foreach (var p in fresh) { p.Group = groupId; Profiles.Add(p); }
            Save();
        }

        public Subscription AddSubscription(string name, string url)
        {
            var s = new Subscription { Name = name, Url = url };
            Subscriptions.Add(s);
            Save();
            return s;
        }

        public Subscription GetSubscription(string id) => Subscriptions.FirstOrDefault(s => s.Id == id);

        /// <summary>Rename / re-point a subscription (does not refetch — the caller updates servers separately).</summary>
        public void UpdateSubscription(string id, string name, string url)
        {
            var s = GetSubscription(id);
            if (s == null) return;
            s.Name = name; s.Url = url;
            Save();
        }

        /// <summary>Remove a subscription and all of its servers.</summary>
        public void RemoveSubscription(string id)
        {
            Subscriptions.RemoveAll(s => s.Id == id);
            Profiles.RemoveAll(x => string.Equals(GroupOf(x), id, StringComparison.OrdinalIgnoreCase));
            Save();
        }

        public void Remove(string id)
        {
            Profiles.RemoveAll(x => x.Id == id);
            if (ActiveProfileId == id) ActiveProfileId = null;
            Save();
        }

        /// <summary>Replace a profile in place by Id (used by the edit dialog — keeps Id/Group, no endpoint dedup).</summary>
        public void Update(ProxyProfile p)
        {
            for (int i = 0; i < Profiles.Count; i++)
                if (Profiles[i].Id == p.Id) { Profiles[i] = p; Save(); return; }
            Profiles.Add(p);
            Save();
        }

        public ProxyProfile GetById(string id) => Profiles.FirstOrDefault(x => x.Id == id);

        /// <summary>
        /// Two profiles are the same server when everything that shapes the connection matches: protocol, address,
        /// credentials, transport (network / path / host / header), security (TLS / REALITY key + short id / SNI), flow
        /// and XHTTP mode/extra. Client-side preferences — name, fingerprint, allowInsecure, VMess cipher, proxy password,
        /// spiderX — don't make a different server: re-adding with only those changed updates the entry in place.
        /// </summary>
        internal static bool SameEndpoint(ProxyProfile a, ProxyProfile b) => EndpointKey(a) == EndpointKey(b);

        /// <summary>Normalised identity string for <see cref="SameEndpoint"/> (null/empty/defaults folded together).</summary>
        internal static string EndpointKey(ProxyProfile p)
        {
            string proto = Norm(p.Protocol);
            var k = new StringBuilder();
            Action<string> add = v => k.Append(v ?? "").Append('\u001f');
            add(proto);
            add(Norm(p.Server).Trim('[', ']'));
            add(p.Port.ToString(System.Globalization.CultureInfo.InvariantCulture));
            switch (proto)
            {
                case "vless":
                case "vmess":
                    add(Norm(p.Uuid).Replace("-", ""));
                    break;
                case "shadowsocks":
                    add(Norm(p.SsMethod)); add(p.Password ?? "");
                    break;
                case "socks":
                case "http":
                case "https":   // plain proxies: the account, not its password
                    add(p.ProxyUser ?? "");
                    break;
                default:        // trojan / unsupported schemes: whatever credential was kept
                    add(p.Uuid ?? ""); add(p.Password ?? "");
                    break;
            }
            // A recognized-but-unsupported import (vmess aid>0, unsupported transport, ...) may differ only in a field we
            // don't store — never let it overwrite a runnable entry (or vice versa).
            add(p.Unsupported ? "unsupported:" + Norm(p.UnsupportedReason) : "");
            if (proto == "vless" || proto == "vmess")
            {
                string net = Norm(p.Network);
                if (net.Length == 0 || net == "raw") net = "tcp";
                if (net == "splithttp") net = "xhttp";
                add(net);
                bool tcpHttp = net == "tcp" && Norm(p.HeaderType) == "http";
                bool usesPathHost = net != "tcp" || tcpHttp;
                add(usesPathHost ? (string.IsNullOrEmpty(p.WsPath) ? "/" : p.WsPath.Trim()) : "");
                string sni = Norm(string.IsNullOrEmpty(p.Sni) ? p.Server : p.Sni);   // the engine's SniOrHost
                // ws / xhttp send SniOrHost when host is empty; the tcp http header falls back to its own default hosts.
                bool hostFallsBackToSni = net == "ws" || net == "xhttp";
                add(!usesPathHost ? "" : hostFallsBackToSni && string.IsNullOrEmpty(p.WsHost) ? sni : Norm(p.WsHost));
                add(tcpHttp ? "http" : "");
                add(p.Reality ? "reality" : p.UseTls ? "tls" : "none");
                add(p.Reality || p.UseTls ? sni : "");
                if (p.Reality)
                {
                    var key = Transport.Tls13.RealityConfig.ParsePublicKey(p.RealityPublicKey);
                    add(key != null ? Convert.ToBase64String(key) : (p.RealityPublicKey ?? "").Trim());   // base64 is case-sensitive
                    add(Norm(p.RealityShortId));
                }
                add(Norm(Protocol.VlessProtocol.NormalizeFlow(p.Flow)));
                if (net == "xhttp")
                {
                    // The mode only classifies support: runnable profiles use stream-one over REALITY and packet-up over
                    // TLS, so auto and that effective mode are the same server. extra is read only by stream-one.
                    string mode = Norm(p.XhttpMode);
                    if (mode == "auto" || mode == (p.Reality ? "stream-one" : "packet-up")) mode = "";
                    add(mode);
                    add(p.Reality ? (p.XhttpExtra ?? "").Trim() : "");
                }
            }
            else if (proto == "https") add(Norm(string.IsNullOrEmpty(p.Sni) ? p.Server : p.Sni));
            return k.ToString();
        }

        private static string Norm(string s) => (s ?? "").Trim().ToLowerInvariant();
    }
}

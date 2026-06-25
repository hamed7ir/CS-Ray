using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
            public bool BlockQuic { get; set; }
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

        /// <summary>Persisted Block-QUIC (UDP/443 drop) preference.</summary>
        public bool BlockQuic { get; set; }

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
                if (!File.Exists(_path)) { Profiles = new List<ProxyProfile>(); ActiveProfileId = null; return; }
                var data = new JavaScriptSerializer().Deserialize<StoreData>(File.ReadAllText(_path));
                Profiles = data?.Profiles ?? new List<ProxyProfile>();
                ActiveProfileId = data?.ActiveProfileId;
                DelayTestUrl = data?.DelayTestUrl;
                Subscriptions = data?.Subscriptions ?? new List<Subscription>();
                ThemeMode = data?.ThemeMode;
                BlockQuic = data?.BlockQuic ?? false;
            }
            catch
            {
                Profiles = new List<ProxyProfile>();
                ActiveProfileId = null;
                Subscriptions = new List<Subscription>();
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
                    BlockQuic = BlockQuic
                });
                File.WriteAllText(_path, json);
            }
            catch { /* read-only dir etc. — non-fatal */ }
        }

        /// <summary>
        /// Adds a profile, or — if one with the same endpoint (protocol+server+port+credential)
        /// already exists — updates it in place (keeping its Id). Returns the stored profile.
        /// </summary>
        public ProxyProfile AddOrUpdate(ProxyProfile p)
        {
            if (string.IsNullOrEmpty(p.Group)) p.Group = ManualGroup;
            // Dedup only WITHIN the same group — a Manual server and a sub server may share an endpoint.
            var existing = Profiles.FirstOrDefault(x =>
                string.Equals(GroupOf(x), GroupOf(p), StringComparison.OrdinalIgnoreCase) && SameEndpoint(x, p));
            if (existing != null)
            {
                p.Id = existing.Id;
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

        private static bool SameEndpoint(ProxyProfile a, ProxyProfile b)
            => string.Equals(a.Protocol, b.Protocol, StringComparison.OrdinalIgnoreCase)
            && string.Equals(a.Server, b.Server, StringComparison.OrdinalIgnoreCase)
            && a.Port == b.Port
            && string.Equals(a.Uuid ?? "", b.Uuid ?? "", StringComparison.Ordinal)
            && string.Equals(a.Password ?? "", b.Password ?? "", StringComparison.Ordinal);
    }
}

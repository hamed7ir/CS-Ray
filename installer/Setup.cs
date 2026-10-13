// =============================================================================
//  CS-Ray installer (Setup.cs) — ONE self-contained exe.
//
//  DroidFinestra's installer, adapted. AnyCPU/MSIL so it RUNS ON WINDOWS RT 8.1 (ARM32) as well as x86/x64 — an
//  Inno Setup loader is native x86 and cannot start on RT.
//
//   * .NET Framework 4.0 Client Profile only, so Setup itself starts on RT 8.1's in-box 4.5.1 and on a bare 4.0
//     Client machine, where it can still say what is missing. The app files are EMBEDDED in this exe as gzip
//     resources ("payload/<file>.gz") listed with SHA-256 in payload.list and checked on extraction. One file to ship.
//   * Per-user %LocalAppData%\Programs\CS-Ray (no admin), IShellLink shortcuts, HKCU Uninstall entry, uninstall.exe
//     self-copy, self-deleting uninstall. The user's settings (Documents\CS-Ray\profiles.json) are never touched.
//   * A REQUIREMENTS CHECK on demand ("Check requirements", or --check): .NET Framework 4.7+ (the app's target), and
//     for the native wintun.dll the app would load on this PC (TUN mode), whether this Windows can run it and has
//     every DLL it imports. It NEVER blocks installing.
//   * A running CS-Ray (it may own the system proxy or the TUN adapter) must be closed by the user first — it is never
//     killed. Uninstall turns off a system proxy a crashed CS-Ray left pointing at itself, and removes the
//     start-at-login entry only when it points into the folder being removed.
//
//  Modes:
//    (no args)                      install wizard, with a "Check requirements" button
//    --check [file]                 requirements report only (to file, or a dialog); installs nothing.
//                                   exit 0 all present, 3 something missing, 2 the package cannot run here
//    --silent [dir] [--no-desktop]  install without UI. exit 0 ok, 4 CS-Ray is running from there,
//                                   5 the folder is refused (see SafeTarget), 2 unknown switch, 1 error
//    --uninstall <dir> [--silent]   remove what Setup put in the folder, the shortcuts and the uninstall entry
//                                   (settings kept). With a UI (Apps & features) unless --silent.
//    (run as uninstall.exe)         confirm, then uninstall its own folder
// =============================================================================
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace CSRaySetup
{
    internal static class Program
    {
        internal const string AppName = "CS-Ray";
        internal const string InstallFolderName = "CS-Ray";
        internal const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\CS-Ray";
        internal const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        internal const string RunValue = "CS-Ray";
        internal const string ShortcutDesc = "CS-Ray - proxy client";
        internal const string Publisher = "Hamed (hamed7ir)";
        internal const string ExeName = "CS-Ray.exe";
        internal const string ProcessName = "CS-Ray";
        internal const string DataFolderNote = @"Documents\CS-Ray";

        [STAThread]
        private static int Main(string[] args)
        {
            bool quiet = Array.Exists(args, a => Eq(a, "--silent"));
            try
            {
                string a0 = args.Length >= 1 ? args[0] : "";
                if (Eq(a0, "--uninstall"))
                {
                    // Entries written by any build quote the folder; tolerate a stray quote or trailing backslash.
                    string dir = args.Length >= 2 && !args[1].StartsWith("--") ? args[1].Trim().Trim('"') : Path.GetDirectoryName(Application.ExecutablePath);
                    if (quiet)
                    {
                        if (InUse.Check(dir) != null) return 4;
                        if (!SafeTarget.IsInstalledCopy(dir)) return 5;   // never touch a folder that is not an installed CS-Ray
                        return Uninstaller.Run(dir) ? 0 : 1;
                    }
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    return UninstallWithUi(dir, false);   // Apps & features has already asked "are you sure"
                }
                if (Eq(a0, "--check"))
                {
                    var rep = Requirements.Check(null);
                    string text = Requirements.Format(rep);
                    if (args.Length >= 2) File.WriteAllText(args[1], text, Encoding.UTF8);
                    else MessageBox.Show(text, AppName + " " + Info.AppVersion + " - requirements");
                    return Requirements.ExitCode(rep);
                }
                if (Eq(a0, "--silent"))
                {
                    string dir = DefaultDir();
                    bool desktop = true;
                    for (int i = 1; i < args.Length; i++)
                    {
                        if (Eq(args[i], "--no-desktop")) desktop = false;
                        else if (args[i].StartsWith("-") || args[i].StartsWith("/")) return 2;   // e.g. /S: not a folder
                        else dir = args[i];
                    }
                    if (SafeTarget.Problem(dir) != null) return 5;
                    if (InUse.Check(dir) != null) return 4;
                    Installer.Install(dir, desktop, null);
                    return 0;
                }

                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                // Double-clicking the dropped uninstall.exe (no args) -> confirm + uninstall its own folder.
                if (Eq(Path.GetFileNameWithoutExtension(Application.ExecutablePath), "uninstall"))
                    return UninstallWithUi(Path.GetDirectoryName(Application.ExecutablePath), true);

                Application.Run(new InstallForm());
                return 0;
            }
            catch (Exception ex)
            {
                if (quiet) { try { Console.Error.WriteLine(ex.ToString()); } catch { } return 1; }   // unattended: never block on a dialog
                try { MessageBox.Show(ex.ToString(), AppName + " Setup - error", MessageBoxButtons.OK, MessageBoxIcon.Error); } catch { }
                return 1;
            }
        }

        private static int UninstallWithUi(string dir, bool confirm)
        {
            if (confirm && MessageBox.Show("Remove " + AppName + " from this computer?\n\n(Your server list and settings in " + DataFolderNote + " are kept.)",
                    "Uninstall " + AppName, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return 0;
            string busy;
            while ((busy = InUse.Check(dir)) != null)
                if (MessageBox.Show(busy + "\n\nClose it (tray icon > Exit), then press Retry.", "Uninstall " + AppName,
                    MessageBoxButtons.RetryCancel, MessageBoxIcon.Warning) != DialogResult.Retry) return 4;
            if (!SafeTarget.IsInstalledCopy(dir))
            {
                MessageBox.Show(dir + "\n\ndoesn't look like an installed " + AppName + " (no " + ExeName + " and uninstall.exe in it), so nothing was removed.",
                    "Uninstall " + AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return 5;
            }
            Uninstaller.Run(dir);
            return 0;
        }

        internal static bool Eq(string a, string b) { return string.Equals(a, b, StringComparison.OrdinalIgnoreCase); }

        internal static string DefaultDir()
        {
            string p = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            return Path.Combine(Path.Combine(p, "Programs"), InstallFolderName);
        }
    }

    // ── payload: embedded gzip resources + payload.list (sha256 <TAB> size <TAB> relative name) ─────────────
    internal sealed class PayloadFile
    {
        public string Name, Sha256;
        public long Size;
    }

    internal static class Payload
    {
        internal static List<PayloadFile> List()
        {
            var list = new List<PayloadFile>();
            using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.list"))
            {
                if (s == null) throw new InvalidDataException("This Setup has no payload.list - it was not built by scripts\\build.ps1.");
                using (var r = new StreamReader(s, Encoding.UTF8))
                {
                    string line;
                    while ((line = r.ReadLine()) != null)
                    {
                        var f = line.Split('\t');
                        if (f.Length != 3) continue;
                        list.Add(new PayloadFile { Sha256 = f[0], Size = long.Parse(f[1]), Name = f[2] });
                    }
                }
            }
            return list;
        }

        internal static Stream Open(PayloadFile f)
        {
            var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload/" + f.Name.Replace('\\', '/') + ".gz");
            if (s == null) throw new InvalidDataException("Payload resource missing: " + f.Name);
            return new GZipStream(s, CompressionMode.Decompress);
        }

        internal static byte[] ReadAll(PayloadFile f)
        {
            using (var s = Open(f))
            using (var m = new MemoryStream())
            {
                Copy(s, m);
                return m.ToArray();
            }
        }

        internal static void Copy(Stream from, Stream to)
        {
            var buf = new byte[81920];
            int n;
            while ((n = from.Read(buf, 0, buf.Length)) > 0) to.Write(buf, 0, n);
        }

        internal static string Hex(byte[] h)
        {
            var sb = new StringBuilder(h.Length * 2);
            foreach (var b in h) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }

    // ── requirements ─────────────────────────────────────────────────────────────────────────────────────────
    internal enum Level { Ok, Warn, Missing, Blocked }

    internal sealed class Req
    {
        public Level Level;
        public string Text, Fix, Url;
    }

    internal static class Requirements
    {
        internal const ushort X86 = 0x14c, X64 = 0x8664, ArmNt = 0x1c4, Arm = 0x1c0, Arm64 = 0xaa64;
        internal const int Net47Release = 460798;   // the app targets .NET Framework 4.7

        [StructLayout(LayoutKind.Sequential)]
        private struct OSVERSIONINFOEX
        {
            public int dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szCSDVersion;
            public ushort wServicePackMajor, wServicePackMinor, wSuiteMask;
            public byte wProductType, wReserved;
        }
        [DllImport("ntdll.dll")] private static extern int RtlGetVersion(ref OSVERSIONINFOEX v);

        /// <summary>Real OS version (Environment.OSVersion stops at 6.2 for an unmanifested app on 8.1+).</summary>
        internal static Version OsVersion()
        {
            try
            {
                var v = new OSVERSIONINFOEX { dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEX)) };
                if (RtlGetVersion(ref v) == 0) return new Version(v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber);
            }
            catch { }
            return Environment.OSVersion.Version;
        }

        /// <summary>"AMD64" | "X86" | "ARM" | "ARM64" — the OS, not this process.</summary>
        internal static string OsArch()
        {
            return (Environment.GetEnvironmentVariable("PROCESSOR_ARCHITEW6432")
                    ?? Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") ?? "").ToUpperInvariant();
        }

        internal static string MachineName(ushort m)
        {
            switch (m)
            {
                case X86: return "x86";
                case X64: return "x64";
                case ArmNt: case Arm: return "ARM32";
                case Arm64: return "ARM64";
                default: return "machine 0x" + m.ToString("X");
            }
        }

        private static string OsArchName(string a)
        {
            switch (a) { case "AMD64": return "x64"; case "X86": return "x86"; case "ARM": return "ARM32"; case "ARM64": return "ARM64"; default: return a; }
        }

        /// <summary>The wintun\&lt;arch&gt; folder(s) CS-Ray may load on this Windows. The app is AnyCPU + Prefer32Bit, so it
        /// runs as a 32-bit process wherever one exists (x86 under WOW64 on x64, ARM32 on Windows RT); on ARM64 it may
        /// run as x86 (emulated) or natively, depending on the .NET Framework there (mirrors WintunLoader.ArchFolder).</summary>
        internal static string[] WintunArchs(string os)
        {
            switch (os)
            {
                case "ARM": return new[] { "arm" };
                case "ARM64": return new[] { "x86", "arm64" };
                default: return new[] { "x86" };
            }
        }

        /// <summary>Null when this Windows can run programs of machine type <paramref name="m"/>, else why not.</summary>
        internal static string CannotRun(ushort m, string os, Version ver)
        {
            switch (m)
            {
                case X86: return os == "ARM" ? "ARM32 Windows cannot run x86 programs" : null;
                case X64:
                    if (os == "AMD64") return null;
                    if (os == "ARM64") return ver.Build >= 22000 ? null : "Windows 10 on ARM64 cannot run x64 programs (Windows 11 can)";
                    return OsArchName(os) + " Windows cannot run x64 programs";
                case ArmNt: case Arm:
                    if (os == "ARM") return null;
                    if (os == "ARM64") return ver.Build >= 26100 ? "Windows 11 24H2 and later no longer run 32-bit ARM programs" : null;
                    return OsArchName(os) + " Windows cannot run ARM32 programs";
                case Arm64: return os == "ARM64" ? null : OsArchName(os) + " Windows cannot run ARM64 programs";
                default: return "unknown machine type 0x" + m.ToString("X");
            }
        }

        /// <summary>The folder a program of machine type <paramref name="m"/> loads system DLLs from on this Windows.</summary>
        internal static string SystemDirFor(ushort m, string os)
        {
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            // a 32-bit Setup on 64-bit Windows sees SysWOW64 as System32; Sysnative is the real one
            string native = Path.Combine(win, Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess ? "Sysnative" : "System32");
            switch (m)
            {
                case X86: return os == "X86" ? native : Path.Combine(win, "SysWOW64");
                case ArmNt: case Arm: return os == "ARM" ? native : Path.Combine(win, "SysArm32");
                default: return native;   // x64 on x64 or ARM64 (ARM64X System32), ARM64 on ARM64
            }
        }

        /// <summary>What a DLL name is: the Universal CRT, a Visual C++ runtime, an API-set contract (resolved by
        /// Windows itself), or an ordinary Windows DLL.</summary>
        internal static string Kind(string dll)
        {
            string d = dll.ToLowerInvariant();
            if (d.StartsWith("api-ms-win-crt-") || d == "ucrtbase.dll") return "ucrt";
            if (d.StartsWith("vcruntime") || d.StartsWith("msvcp1") || d.StartsWith("msvcr1") || d.StartsWith("concrt1")
                || d.StartsWith("vcomp1") || d.StartsWith("vccorlib")) return "vc";
            if (d.StartsWith("api-ms-") || d.StartsWith("ext-ms-")) return "apiset";
            return "system";
        }

        /// <summary>Machine type + imported DLL names of a PE image; false if it is not one.</summary>
        internal static bool ParsePe(byte[] b, out ushort machine, out List<string> imports)
        {
            machine = 0; imports = new List<string>();
            try
            {
                if (b.Length < 0x40 || b[0] != 'M' || b[1] != 'Z') return false;
                int pe = BitConverter.ToInt32(b, 0x3C);
                if (pe < 0 || pe + 24 > b.Length || b[pe] != 'P' || b[pe + 1] != 'E' || b[pe + 2] != 0 || b[pe + 3] != 0) return false;
                machine = BitConverter.ToUInt16(b, pe + 4);
                int nsec = BitConverter.ToUInt16(b, pe + 6);
                int optSize = BitConverter.ToUInt16(b, pe + 20);
                int opt = pe + 24;
                bool plus = BitConverter.ToUInt16(b, opt) == 0x20b;
                int numDirs = BitConverter.ToInt32(b, opt + (plus ? 108 : 92));
                if (numDirs < 2) return true;
                uint impRva = BitConverter.ToUInt32(b, opt + (plus ? 112 : 96) + 8);
                if (impRva == 0) return true;
                int secs = opt + optSize;
                Func<uint, int> off = rva =>
                {
                    for (int i = 0; i < nsec; i++)
                    {
                        int s = secs + 40 * i;
                        uint vs = BitConverter.ToUInt32(b, s + 8), va = BitConverter.ToUInt32(b, s + 12);
                        uint raw = BitConverter.ToUInt32(b, s + 16), ptr = BitConverter.ToUInt32(b, s + 20);
                        uint size = Math.Max(vs, raw);
                        if (rva >= va && rva < va + size) return (int)(rva - va + ptr);
                    }
                    return -1;
                };
                for (int d = off(impRva); d >= 0 && d + 20 <= b.Length && imports.Count < 1024; d += 20)
                {
                    uint nameRva = BitConverter.ToUInt32(b, d + 12), first = BitConverter.ToUInt32(b, d + 16);
                    if (nameRva == 0 && first == 0) break;
                    int n = off(nameRva);
                    if (n < 0) break;
                    int e = n;
                    while (e < b.Length && b[e] != 0) e++;
                    imports.Add(Encoding.ASCII.GetString(b, n, e - n));
                }
                return true;
            }
            catch { return true; }   // a truncated table: keep what was read
        }

        private static string RedistUrl(ushort m)
        {
            switch (m)
            {
                case X86: return "https://aka.ms/vs/17/release/vc_redist.x86.exe";
                case X64: return "https://aka.ms/vs/17/release/vc_redist.x64.exe";
                case Arm64: return "https://aka.ms/vs/17/release/vc_redist.arm64.exe";
                default: return null;   // Microsoft publishes no current redistributable for ARM32
            }
        }

        /// <summary>Checks this machine against the payload. <paramref name="exists"/> answers "is this file there"
        /// (null = the real file system) — it lets the check be tested against a machine that lacks a runtime.</summary>
        internal static List<Req> Check(Func<string, bool> exists)
        {
            if (exists == null) exists = File.Exists;
            var reqs = new List<Req>();
            string os = OsArch();
            Version ver = OsVersion();
            reqs.Add(new Req { Level = Level.Ok, Text = "Windows " + ver + " on " + OsArchName(os) });

            // .NET Framework 4.7+ — the app targets it (this Setup itself needs only the 4.0 Client Profile)
            int release = 0; bool full = false;
            try
            {
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"))
                {
                    if (k != null)
                    {
                        object inst = k.GetValue("Install"), rel = k.GetValue("Release");
                        full = inst is int && (int)inst == 1;
                        if (rel is int) release = (int)rel;
                    }
                }
            }
            catch { }
            if (full && release >= Net47Release) reqs.Add(new Req { Level = Level.Ok, Text = ".NET Framework " + NetName(release) });
            else reqs.Add(new Req
            {
                Level = Level.Missing,
                Text = (full ? ".NET Framework " + NetName(release) + " is installed; " + Program.AppName + " needs 4.7 or later"
                             : ".NET Framework 4 (full) is not installed") + " - " + Program.AppName + " will not start",
                Fix = "Install .NET Framework 4.8 (or any 4.7+)",
                Url = "https://dotnet.microsoft.com/download/dotnet-framework"
            });

            // native binaries in the payload: can they run here, and is everything they import available? The four
            // wintun\<arch>\wintun.dll are alternatives — only the one(s) the app would load on this PC count.
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var files = Payload.List();
            foreach (var f in files) names.Add(Path.GetFileName(f.Name));
            var wintunArchs = WintunArchs(os);
            var blocked = new List<string>();
            var wintunOk = new List<string>();
            var needs = new SortedDictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);   // "kind|machine|dll" -> users
            foreach (var f in files)
            {
                string ext = Path.GetExtension(f.Name).ToLowerInvariant();
                if (ext != ".exe" && ext != ".dll") continue;
                string label = f.Name;
                bool wintun = f.Name.StartsWith(@"wintun\", StringComparison.OrdinalIgnoreCase);
                if (wintun)
                {
                    string arch = f.Name.Split('\\').Length >= 3 ? f.Name.Split('\\')[1] : "";
                    if (Array.IndexOf(wintunArchs, arch.ToLowerInvariant()) < 0) continue;
                }
                ushort m; List<string> imps;
                if (!ParsePe(Payload.ReadAll(f), out m, out imps)) continue;
                bool managed = imps.Count == 1 && Program.Eq(imps[0], "mscoree.dll");
                if (managed) continue;   // MSIL (AnyCPU) — runs wherever .NET does
                string why = CannotRun(m, os, ver);
                if (why != null) { if (!wintun) blocked.Add(label + " (" + MachineName(m) + "): " + why); continue; }
                if (wintun) wintunOk.Add(label);
                foreach (var dll in imps)
                {
                    if (names.Contains(dll)) continue;
                    string kind = Kind(dll);
                    if (kind == "apiset") continue;
                    string key = kind + "|" + m + "|" + (kind == "ucrt" ? "ucrtbase.dll" : dll.ToLowerInvariant());
                    List<string> users;
                    if (!needs.TryGetValue(key, out users)) needs[key] = users = new List<string>();
                    if (!users.Contains(label)) users.Add(label);
                }
            }

            if (blocked.Count > 0)
                reqs.Add(new Req { Level = Level.Blocked, Text = "This package's programs cannot run on this PC:\n    " + string.Join("\n    ", blocked.ToArray()) });
            reqs.Add(wintunOk.Count > 0
                ? new Req { Level = Level.Ok, Text = "TUN driver (Wintun) for this PC: " + string.Join(", ", wintunOk.ToArray()) }
                : new Req { Level = Level.Warn, Text = "No Wintun DLL in this package runs on this PC - full-tunnel (TUN) mode will be unavailable; the system proxy mode still works" });

            int sysChecked = 0, sysMissing = 0;
            foreach (var kv in needs)
            {
                var p = kv.Key.Split('|');
                string kind = p[0]; ushort m = ushort.Parse(p[1]); string dll = p[2];
                string dir = SystemDirFor(m, os);
                bool ok = exists(Path.Combine(dir, dll));
                if (kind == "system") { sysChecked++; if (!ok) sysMissing++; }
                string by = " - needed by " + string.Join(", ", kv.Value.ToArray());
                if (kind == "ucrt")
                    reqs.Add(ok
                        ? new Req { Level = Level.Ok, Text = "Universal C Runtime (" + MachineName(m) + ")" + by }
                        : new Req
                        {
                            Level = Level.Missing,
                            Text = "Universal C Runtime (" + MachineName(m) + ") is missing" + by,
                            Fix = "Install the Microsoft Visual C++ 2015-2022 Redistributable (" + MachineName(m) + "), which adds it on Windows 7/8.1, or Windows Update KB2999226",
                            Url = RedistUrl(m)
                        });
                else if (kind == "vc")
                    reqs.Add(ok
                        ? new Req { Level = Level.Ok, Text = "Visual C++ runtime " + dll + " (" + MachineName(m) + ")" + by }
                        : new Req
                        {
                            Level = Level.Missing,
                            Text = "Visual C++ runtime " + dll + " (" + MachineName(m) + ") is missing" + by,
                            Fix = "Install the Microsoft Visual C++ 2015-2022 Redistributable (" + MachineName(m) + ")",
                            Url = RedistUrl(m)
                        });
                else if (!ok)   // an ordinary Windows DLL: only worth a line when it is absent
                    reqs.Add(new Req
                    {
                        Level = Level.Missing,
                        Text = "Windows component " + dll + " (" + MachineName(m) + ") is missing" + by,
                        Fix = "This Windows edition lacks it; the program that needs it will not start"
                    });
            }
            if (sysChecked > 0 && sysMissing == 0)
                reqs.Add(new Req { Level = Level.Ok, Text = "Windows components the TUN driver imports: all " + sysChecked + " present" });
            return reqs;
        }

        internal static string NetName(int release)
        {
            if (release >= 533320) return "4.8.1";
            if (release >= 528040) return "4.8";
            if (release >= 461808) return "4.7.2";
            if (release >= 461308) return "4.7.1";
            if (release >= 460798) return "4.7";
            if (release >= 394802) return "4.6.2";
            if (release >= 394254) return "4.6.1";
            if (release >= 393295) return "4.6";
            if (release >= 379893) return "4.5.2";
            if (release >= 378675) return "4.5.1";
            if (release >= 378389) return "4.5";
            return "4.0";
        }

        internal static int ExitCode(List<Req> reqs)
        {
            int code = 0;
            foreach (var r in reqs)
            {
                if (r.Level == Level.Blocked) return 2;
                if (r.Level == Level.Missing || r.Level == Level.Warn) code = 3;
            }
            return code;
        }

        internal static string Tag(Level l)
        {
            switch (l) { case Level.Ok: return "[ OK ]"; case Level.Warn: return "[WARN]"; case Level.Missing: return "[MISSING]"; default: return "[CANNOT RUN]"; }
        }

        internal static string Format(List<Req> reqs)
        {
            var sb = new StringBuilder();
            foreach (var r in reqs)
            {
                sb.Append(Tag(r.Level)).Append(' ').Append(r.Text.Replace("\n", "\r\n")).Append("\r\n");
                if (r.Fix != null) sb.Append("      -> ").Append(r.Fix).Append("\r\n");
                if (r.Url != null) sb.Append("      ").Append(r.Url).Append("\r\n");
            }
            return sb.ToString();
        }
    }

    // ── a running CS-Ray: it holds the files, and may own the system proxy or the TUN adapter ─────────────────
    internal static class InUse
    {
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(int access, bool inherit, int pid);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);
        private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        private static string ImagePath(Process p)
        {
            IntPtr h = IntPtr.Zero;
            try
            {
                h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, p.Id);
                if (h == IntPtr.Zero) return null;
                var sb = new StringBuilder(1024); int n = sb.Capacity;
                return QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString() : null;
            }
            catch { return null; }
            finally { if (h != IntPtr.Zero) CloseHandle(h); }
        }

        /// <summary>Null when no CS-Ray runs from <paramref name="dir"/>, else a sentence saying one does. A CS-Ray whose
        /// path cannot be read (e.g. the elevated TUN instance) counts as running from there: closing it is the user's
        /// call — it is never killed, because it may own the system proxy or the TUN adapter.</summary>
        internal static string Check(string dir)
        {
            if (!Directory.Exists(dir)) return null;
            string full;
            try { full = Path.GetFullPath(dir).TrimEnd('\\') + "\\"; } catch { return null; }
            // A running image cannot be opened for writing. This also catches a CS-Ray started through a junction, subst
            // or mapped drive, whose reported path doesn't start with `dir`.
            string exe = Path.Combine(full, Program.ExeName);
            if (File.Exists(exe))
            {
                try { using (new FileStream(exe, FileMode.Open, FileAccess.ReadWrite, FileShare.Read)) { } }
                catch (IOException ex) when (!(ex is FileNotFoundException) && !(ex is DirectoryNotFoundException))
                { return Program.AppName + " is running from " + dir + "."; }
                catch { }
            }
            bool unknown = false;
            foreach (var p in Process.GetProcessesByName(Program.ProcessName))
            {
                try
                {
                    if (p.Id == Process.GetCurrentProcess().Id) continue;
                    string img = ImagePath(p);
                    if (img == null) unknown = true;
                    else if (img.StartsWith(full, StringComparison.OrdinalIgnoreCase))
                        return Program.AppName + " is running from " + dir + ".";
                }
                finally { p.Dispose(); }
            }
            return unknown ? Program.AppName + " is running (possibly from " + dir + ")." : null;
        }
    }

    /// <summary>
    /// Where Setup may write and what it may delete. The install folder is replaced on every (re)install and removed on
    /// uninstall, so a folder of the user's — typed into the path box, or given on the command line — must never be one:
    /// drive roots and the well-known shell folders are refused outright, and an existing non-empty folder is only
    /// replaced when it is an installed CS-Ray (uninstall.exe + CS-Ray.exe in it).
    /// </summary>
    internal static class SafeTarget
    {
        internal static string Problem(string dir)
        {
            string full;
            try { full = Path.GetFullPath((dir ?? "").Trim()).TrimEnd('\\'); }
            catch (Exception ex) { return "Not a usable folder: " + ex.Message; }
            if (full.Length == 0) return "Choose an install folder.";
            if (full.IndexOfAny(new[] { '%', '^' }) >= 0) return "The folder name can't contain % or ^.";   // uninstall's cmd would expand them
            string root = (Path.GetPathRoot(full) ?? "").TrimEnd('\\');
            if (root.Length == 0 || root.Equals(full, StringComparison.OrdinalIgnoreCase)) return "Choose a folder for " + Program.AppName + ", not a whole drive.";
            foreach (var f in Protected())
                if (f.Equals(full, StringComparison.OrdinalIgnoreCase))
                    return full + " is a system or personal folder. Choose a folder of its own, e.g. " + Path.Combine(full, Program.InstallFolderName) + ".";
            if (!Directory.Exists(full) || IsEmpty(full) || IsInstalledCopy(full)) return null;
            return full + " already holds other files. Choose an empty folder, or the folder " + Program.AppName + " is installed in.";
        }

        /// <summary>The folder holds an installed CS-Ray: the program and the uninstall.exe Setup drops next to it.</summary>
        internal static bool IsInstalledCopy(string dir)
        {
            try { return File.Exists(Path.Combine(dir, "uninstall.exe")) && File.Exists(Path.Combine(dir, Program.ExeName)); }
            catch { return false; }
        }

        private static bool IsEmpty(string dir)
        {
            try { using (var e = Directory.EnumerateFileSystemEntries(dir).GetEnumerator()) return !e.MoveNext(); }
            catch { return false; }
        }

        private static IEnumerable<string> Protected()
        {
            var sf = new[]
            {
                Environment.SpecialFolder.Windows, Environment.SpecialFolder.System, Environment.SpecialFolder.ProgramFiles,
                Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.UserProfile, Environment.SpecialFolder.DesktopDirectory,
                Environment.SpecialFolder.MyDocuments, Environment.SpecialFolder.MyMusic, Environment.SpecialFolder.MyPictures,
                Environment.SpecialFolder.MyVideos, Environment.SpecialFolder.ApplicationData, Environment.SpecialFolder.LocalApplicationData,
                Environment.SpecialFolder.CommonApplicationData, Environment.SpecialFolder.Programs, Environment.SpecialFolder.StartMenu,
                Environment.SpecialFolder.Startup, Environment.SpecialFolder.Favorites,
            };
            var list = new List<string>();
            foreach (var f in sf)
            {
                try { string p = Environment.GetFolderPath(f); if (!string.IsNullOrEmpty(p)) list.Add(Path.GetFullPath(p).TrimEnd('\\')); } catch { }
            }
            try
            {
                string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                if (!string.IsNullOrEmpty(profile)) list.Add(Path.Combine(profile, "Downloads"));   // no SpecialFolder for it on .NET 4.0
                string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (!string.IsNullOrEmpty(local)) list.Add(Path.Combine(local, "Programs"));
            }
            catch { }
            return list;
        }
    }

    internal static class Installer
    {
        internal static void Install(string targetDir, bool desktopShortcut, Action<string> progress)
        {
            Report(progress, "Preparing...");
            string refused = SafeTarget.Problem(targetDir);
            if (refused != null) throw new InvalidOperationException(refused);
            targetDir = Path.GetFullPath(targetDir.Trim()).TrimEnd('\\');   // one spelling for the files, shortcuts and uninstall entry
            var files = Payload.List();
            if (!files.Exists(f => Program.Eq(f.Name, Program.ExeName))) throw new InvalidDataException("This Setup carries no " + Program.ExeName + ".");

            // Check the whole package BEFORE touching the folder: a damaged Setup must not take a working install down.
            Report(progress, "Checking the package...");
            var data = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            using (var sha = SHA256.Create())
                foreach (var f in files)
                {
                    var bytes = Payload.ReadAll(f);
                    string got = Payload.Hex(sha.ComputeHash(bytes));
                    if (!string.Equals(got, f.Sha256, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException(f.Name + " in this Setup is damaged (SHA-256 " + got + ", expected " + f.Sha256 + "). Download Setup again.");
                    data[f.Name] = bytes;
                }

            // The folder is new, empty or an installed CS-Ray (SafeTarget). Each file is written beside the old one and then
            // swapped in, so an interrupted install leaves whole files and a working uninstall.exe; nothing else in the
            // folder (a beside-exe profiles.json, files the user keeps there) is touched.
            Directory.CreateDirectory(targetDir);
            int i = 0;
            foreach (var f in files)
            {
                Report(progress, "Installing " + (++i) + " of " + files.Count + ": " + f.Name);
                string dest = Path.Combine(targetDir, f.Name);
                string d = Path.GetDirectoryName(dest);
                if (!string.IsNullOrEmpty(d)) Directory.CreateDirectory(d);
                string tmp = dest + ".new";
                try
                {
                    File.WriteAllBytes(tmp, data[f.Name]);
                    if (File.Exists(dest)) File.Delete(dest);
                    File.Move(tmp, dest);
                }
                catch
                {
                    try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }   // don't leave a half step behind
                    throw;
                }
            }
            Owned.RemoveRetired(targetDir, files);   // files only older versions shipped

            string exe = Path.Combine(targetDir, Program.ExeName);
            string uninst = Path.Combine(targetDir, "uninstall.exe");

            Report(progress, "Creating shortcuts...");
            File.Copy(Application.ExecutablePath, uninst, true);   // uninstall.exe = this Setup (uninstall mode only)
            string programs = Environment.GetFolderPath(Environment.SpecialFolder.Programs);
            Shortcut.Create(Path.Combine(programs, Program.AppName + ".lnk"), exe, null, targetDir, exe, Program.ShortcutDesc);
            if (desktopShortcut)
            {
                string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                Shortcut.Create(Path.Combine(desktop, Program.AppName + ".lnk"), exe, null, targetDir, exe, Program.ShortcutDesc);
            }

            Report(progress, "Registering...");
            RegisterUninstall(targetDir, exe, uninst);
            Report(progress, "Done.");
        }

        private static void RegisterUninstall(string dir, string exe, string uninst)
        {
            try
            {
                using (var k = Registry.CurrentUser.CreateSubKey(Program.UninstallKey))
                {
                    if (k == null) return;
                    k.SetValue("DisplayName", Program.AppName);
                    k.SetValue("DisplayVersion", Info.AppVersion);
                    k.SetValue("Publisher", Program.Publisher);
                    k.SetValue("DisplayIcon", exe);
                    k.SetValue("InstallLocation", dir);
                    k.SetValue("UninstallString", "\"" + uninst + "\" --uninstall \"" + dir + "\"");
                    k.SetValue("NoModify", 1, RegistryValueKind.DWord);
                    k.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                    try { k.SetValue("EstimatedSize", (int)DirSizeKB(dir), RegistryValueKind.DWord); } catch { }
                }
            }
            catch { /* uninstall entry is best-effort */ }
        }

        private static long DirSizeKB(string dir)
        {
            long total = 0;
            foreach (var f in Directory.GetFiles(dir, "*", SearchOption.AllDirectories))
                try { total += new FileInfo(f).Length; } catch { }
            return total / 1024;
        }

        private static void Report(Action<string> p, string s) { if (p != null) p(s); }
    }

    /// <summary>The files Setup owns in an install folder: this package's (payload.list, which uninstall.exe carries too),
    /// uninstall.exe, and what older versions shipped. Upgrade and uninstall remove only these, so anything else in the
    /// folder — a beside-exe profiles.json, files the user put there — stays.</summary>
    internal static class Owned
    {
        // Shipped by 1.x builds and no longer (the MaterialSkin UI, the old Bouncy Castle package, the two-file installer).
        private static readonly string[] Retired = { "MaterialSkin.dll", "BouncyCastle.Crypto.dll", "CS-Ray.pdb", "payload.zip" };
        private static readonly string[] Dirs = { @"wintun\x86", @"wintun\amd64", @"wintun\arm", @"wintun\arm64", "wintun" };

        internal static void RemoveRetired(string dir, List<PayloadFile> files)
        {
            foreach (var name in Retired)
                if (!files.Exists(f => Program.Eq(f.Name, name))) Del(Path.Combine(dir, name));
        }

        internal static void RemoveAll(string dir, List<PayloadFile> files)
        {
            foreach (var f in files) { Del(Path.Combine(dir, f.Name)); Del(Path.Combine(dir, f.Name + ".new")); }   // .new: an install cut off mid-swap
            foreach (var name in Retired) Del(Path.Combine(dir, name));
            foreach (var sub in Dirs) { try { Directory.Delete(Path.Combine(dir, sub), false); } catch { } }   // only if empty now
        }

        private static void Del(string f) { try { if (File.Exists(f)) File.Delete(f); } catch { } }
    }

    internal static class Uninstaller
    {
        internal static bool Run(string dir)
        {
            if (!SafeTarget.IsInstalledCopy(dir)) return false;   // never rmdir a folder that is not an installed CS-Ray
            // OWNERSHIP: the shortcut names, the uninstall key and the Run value are fixed, so another install of the
            // app (a copy in another folder) may own them. Remove only what points INTO the folder being removed.
            RemoveShortcutIfOurs(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs), Program.AppName + ".lnk"), dir);
            RemoveShortcutIfOurs(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), Program.AppName + ".lnk"), dir);
            RemoveUninstallKeyIfOurs(dir);
            RemoveRunValueIfOurs(dir);
            StaleProxy.TurnOff();
            DelFile(Path.Combine(Path.GetTempPath(), "csray.log"));   // transient log (written only under --autostart)
            Owned.RemoveAll(dir, Payload.List());
            SelfDeleteDir(dir);   // uninstall.exe and the then-empty folder last (uninstall.exe may be running from it)
            return true;
        }

        // POLICY: PRESERVE the user's settings — Documents\CS-Ray (or AppData\CS-Ray) profiles.json is never touched.

        /// <summary>True when <paramref name="path"/> is <paramref name="dir"/> or inside it. Unreadable or empty
        /// counts as NOT ours: leaving a stale entry is recoverable, deleting another install's is not.</summary>
        internal static bool Inside(string path, string dir)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(dir)) return false;
            try
            {
                string d = Path.GetFullPath(dir).TrimEnd('\\');
                string p = Path.GetFullPath(path.Trim().Trim('"')).TrimEnd('\\');
                return p.Equals(d, StringComparison.OrdinalIgnoreCase) || p.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        /// <summary>The program path of a command line: a quoted first token, or everything before " -" / " /".</summary>
        internal static string ExeOf(string command)
        {
            command = (command ?? "").Trim();
            if (command.StartsWith("\""))
            {
                int q = command.IndexOf('"', 1);
                return q > 0 ? command.Substring(1, q - 1) : command.Trim('"');
            }
            int cut = command.IndexOf(" -", StringComparison.Ordinal);
            if (cut < 0) cut = command.IndexOf(" /", StringComparison.Ordinal);
            return cut > 0 ? command.Substring(0, cut) : command;
        }

        private static void RemoveShortcutIfOurs(string lnk, string dir)
        {
            try { if (File.Exists(lnk) && Inside(Shortcut.TargetOf(lnk), dir)) File.Delete(lnk); } catch { }
        }

        private static void RemoveUninstallKeyIfOurs(string dir)
        {
            try
            {
                string loc;
                using (var k = Registry.CurrentUser.OpenSubKey(Program.UninstallKey))
                    loc = k != null ? k.GetValue("InstallLocation") as string : null;
                if (Inside(loc, dir) && Inside(dir, loc)) Registry.CurrentUser.DeleteSubKeyTree(Program.UninstallKey);
            }
            catch { }
        }

        // The app's own "start at login" toggle writes HKCU Run\CS-Ray = "<exe>" --autostart; it would point at the
        // exe being deleted.
        private static void RemoveRunValueIfOurs(string dir)
        {
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(Program.RunKey, true))
                {
                    if (k == null) return;
                    string cmd = k.GetValue(Program.RunValue) as string;
                    if (cmd != null && Inside(ExeOf(cmd), dir)) k.DeleteValue(Program.RunValue, false);
                }
            }
            catch { }
        }

        private static void DelFile(string f) { try { if (File.Exists(f)) File.Delete(f); } catch { } }

        private static void SelfDeleteDir(string dir)
        {
            try
            {
                // uninstall.exe may be running from inside `dir`, so a detached cmd waits for it to exit (with a second try
                // for a slow device), deletes it, and removes the folder only if it is empty now: rmdir without /s never
                // deletes what isn't ours. Its working folder is System32, never `dir` (a process's current folder can't
                // be removed).
                string u = Path.Combine(dir, "uninstall.exe");
                var psi = new ProcessStartInfo("cmd.exe",
                    "/c ping 127.0.0.1 -n 4 >nul & del /f /q \"" + u + "\" & ping 127.0.0.1 -n 4 >nul & del /f /q \"" + u + "\" & rmdir \"" + dir + "\"");
                psi.WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.System);
                psi.CreateNoWindow = true; psi.UseShellExecute = false; psi.WindowStyle = ProcessWindowStyle.Hidden;
                Process.Start(psi);
            }
            catch { }
        }
    }

    /// <summary>A CS-Ray that crashed or was killed while "system proxy" was on leaves Windows pointing at a local port
    /// nothing listens on any more — no web pages load. CS-Ray's value is exactly
    /// "http=127.0.0.1:P;https=127.0.0.1:P;socks=127.0.0.1:P"; only that, while enabled, is switched off.</summary>
    internal static class StaleProxy
    {
        private const string KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        [DllImport("wininet.dll", SetLastError = true)] private static extern bool InternetSetOption(IntPtr h, int option, IntPtr buffer, int length);

        internal static bool IsCsRayValue(string v) { int port; return IsCsRayValue(v, out port); }

        internal static bool IsCsRayValue(string v, out int portNumber)
        {
            portNumber = 0;
            if (string.IsNullOrEmpty(v)) return false;
            var parts = v.Split(';');
            if (parts.Length != 3) return false;
            string port = null;
            string[] want = { "http=127.0.0.1:", "https=127.0.0.1:", "socks=127.0.0.1:" };
            for (int i = 0; i < 3; i++)
            {
                if (!parts[i].StartsWith(want[i], StringComparison.Ordinal)) return false;
                string p = parts[i].Substring(want[i].Length);
                int n;
                if (!int.TryParse(p, out n) || n <= 0 || n > 65535 || (port != null && p != port)) return false;
                port = p;
                portNumber = n;
            }
            return true;
        }

        // Something accepts connections on 127.0.0.1:port (a CS-Ray we can't see, or another proxy using that port).
        private static bool Listening(int port)
        {
            try
            {
                using (var c = new System.Net.Sockets.TcpClient())
                {
                    var ar = c.BeginConnect(System.Net.IPAddress.Loopback, port, null, null);
                    bool done = ar.AsyncWaitHandle.WaitOne(700);
                    if (!done) return false;
                    try { c.EndConnect(ar); return true; } catch { return false; }
                }
            }
            catch { return false; }
        }

        internal static void TurnOff()
        {
            try
            {
                // Only a STALE value: no CS-Ray runs anywhere (any running copy may own it — e.g. a portable one), and
                // nothing listens on its port any more.
                if (Process.GetProcessesByName(Program.ProcessName).Length > 0) return;
                using (var k = Registry.CurrentUser.OpenSubKey(KeyPath, true))
                {
                    if (k == null) return;
                    object en = k.GetValue("ProxyEnable");
                    int port;
                    if (!(en is int) || (int)en == 0 || !IsCsRayValue(k.GetValue("ProxyServer") as string, out port)) return;
                    if (Listening(port)) return;
                    k.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
                }
                InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);   // INTERNET_OPTION_SETTINGS_CHANGED
                InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);   // INTERNET_OPTION_REFRESH
            }
            catch { }
        }
    }

    /// <summary>Creates a .lnk via the shell's IShellLink COM object (works on RT desktop).</summary>
    internal static class Shortcut
    {
        internal static void Create(string lnkPath, string target, string args, string workDir, string iconPath, string desc)
        {
            try
            {
                var link = (IShellLinkW)new CShellLink();
                link.SetPath(target);
                if (!string.IsNullOrEmpty(args)) link.SetArguments(args);
                if (!string.IsNullOrEmpty(workDir)) link.SetWorkingDirectory(workDir);
                if (!string.IsNullOrEmpty(iconPath)) link.SetIconLocation(iconPath, 0);
                if (!string.IsNullOrEmpty(desc)) link.SetDescription(desc);
                ((IPersistFile)link).Save(lnkPath, true);
            }
            catch { /* shortcut is best-effort */ }
        }

        /// <summary>The target path a .lnk points at, or null when it cannot be read.</summary>
        internal static string TargetOf(string lnkPath)
        {
            try
            {
                var link = (IShellLinkW)new CShellLink();
                ((IPersistFile)link).Load(lnkPath, 0);
                var sb = new StringBuilder(1024);
                link.GetPath(sb, sb.Capacity, IntPtr.Zero, 0);
                return sb.Length > 0 ? sb.ToString() : null;
            }
            catch { return null; }
        }

        [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
        private class CShellLink { }

        [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("000214F9-0000-0000-C000-000000000046")]
        private interface IShellLinkW
        {
            void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile, int cch, IntPtr pfd, int fFlags);
            void GetIDList(out IntPtr ppidl);
            void SetIDList(IntPtr pidl);
            void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName, int cch);
            void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
            void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszDir, int cch);
            void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
            void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszArgs, int cch);
            void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
            void GetHotkey(out short pwHotkey);
            void SetHotkey(short wHotkey);
            void GetShowCmd(out int piShowCmd);
            void SetShowCmd(int iShowCmd);
            void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszIconPath, int cch, out int piIcon);
            void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
            void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, int dwReserved);
            void Resolve(IntPtr hwnd, int fFlags);
            void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
        }

        [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("0000010b-0000-0000-C000-000000000046")]
        private interface IPersistFile
        {
            void GetClassID(out Guid pClassID);
            [PreserveSig] int IsDirty();
            void Load([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, int dwMode);
            void Save([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, [MarshalAs(UnmanagedType.Bool)] bool fRemember);
            void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string pszFileName);
            void GetCurFile([MarshalAs(UnmanagedType.LPWStr)] out string ppszFileName);
        }
    }

    /// <summary>The install wizard, plus a "Check requirements" button. The check only informs: Install is always
    /// enabled and never runs it.</summary>
    internal sealed class InstallForm : Form
    {
        private readonly TextBox _path, _reqs;
        private readonly CheckBox _desktop;
        private readonly Button _install, _cancel, _browse, _check;
        private readonly Label _status;
        private readonly ProgressBar _bar;
        private readonly FlowLayoutPanel _links;
        private static readonly Color Accent = Color.FromArgb(126, 87, 194);   // CS-Ray purple

        public InstallForm()
        {
            Text = Program.AppName + " " + Info.AppVersion + " Setup";
            try { using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("setup.icon.ico")) if (s != null) Icon = new Icon(s); } catch { }
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false; MinimizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            AutoScaleMode = AutoScaleMode.Font;
            Font = new Font("Segoe UI", 9f);
            ClientSize = new Size(560, 470);
            BackColor = Color.White;

            var header = new Panel { Dock = DockStyle.Top, Height = 64, BackColor = Accent };
            var title = new Label { Dock = DockStyle.Fill, ForeColor = Color.White, Font = new Font("Segoe UI", 14f, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(18, 0, 0, 0), Text = "Install " + Program.AppName + " " + Info.AppVersion };
            header.Controls.Add(title);

            var lbl = new Label { Left = 18, Top = 80, Width = 524, Height = 18, Text = "Install location (per-user, no admin needed):" };
            _path = new TextBox { Left = 18, Top = 100, Width = 430, Text = Program.DefaultDir() };
            _browse = new Button { Left = 458, Top = 98, Width = 84, Height = 26, Text = "Browse..." };
            _browse.Click += (s, e) => { using (var d = new FolderBrowserDialog()) { try { d.SelectedPath = _path.Text; } catch { } if (d.ShowDialog(this) == DialogResult.OK) _path.Text = Path.Combine(d.SelectedPath, Program.InstallFolderName); } };
            _desktop = new CheckBox { Left = 18, Top = 132, Width = 300, Text = "Create a desktop shortcut", Checked = true };

            var rl = new Label { Left = 18, Top = 164, Width = 524, Height = 18, Text = "Requirements (optional check - installing does not depend on it):" };
            _reqs = new TextBox { Left = 18, Top = 184, Width = 524, Height = 150, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, BackColor = Color.White, Font = new Font("Consolas", 8.5f),
                                  Text = "Press \"Check requirements\" to see whether this PC has what " + Program.AppName + " needs:\r\n.NET Framework 4.7 or later, and what the TUN driver (Wintun) uses." };
            _links = new FlowLayoutPanel { Left = 18, Top = 338, Width = 524, Height = 44, FlowDirection = FlowDirection.TopDown, WrapContents = false };

            _status = new Label { Left = 18, Top = 386, Width = 524, Height = 18, ForeColor = Color.Gray, Text = "" };
            _bar = new ProgressBar { Left = 18, Top = 406, Width = 524, Height = 14, Style = ProgressBarStyle.Marquee, Visible = false, MarqueeAnimationSpeed = 30 };
            _check = new Button { Left = 18, Top = 430, Width = 150, Height = 28, Text = "Check requirements" };
            _install = new Button { Left = 380, Top = 430, Width = 84, Height = 28, Text = "Install" };
            _cancel = new Button { Left = 468, Top = 430, Width = 74, Height = 28, Text = "Cancel" };
            _check.Click += (s, e) => RunCheck();
            _install.Click += OnInstall;
            _cancel.Click += (s, e) => Close();

            Controls.Add(header);
            Controls.Add(lbl); Controls.Add(_path); Controls.Add(_browse); Controls.Add(_desktop);
            Controls.Add(rl); Controls.Add(_reqs); Controls.Add(_links);
            Controls.Add(_status); Controls.Add(_bar); Controls.Add(_check); Controls.Add(_install); Controls.Add(_cancel);
            AcceptButton = _install; CancelButton = _cancel;
            // Closing the window mid-install would kill the extraction thread between files.
            FormClosing += (s, e) => { if (_busy && e.CloseReason == CloseReason.UserClosing) e.Cancel = true; };
        }

        private bool _busy;

        private void RunCheck()
        {
            _status.ForeColor = Color.Gray;
            _status.Text = "Checking requirements...";
            _check.Enabled = false;
            _bar.Visible = true;
            var t = new Thread(() =>
            {
                List<Req> rep = null; Exception err = null;
                try { rep = Requirements.Check(null); } catch (Exception ex) { err = ex; }
                try
                {
                    BeginInvoke((Action)(() =>
                    {
                        if (!_busy) { _bar.Visible = false; _check.Enabled = true; }   // an install started meanwhile owns them
                        if (err != null) { _reqs.Text = "The check failed: " + err.Message; _status.Text = ""; return; }
                        ShowReport(rep);
                    }));
                }
                catch { }
            }) { IsBackground = true };
            t.Start();
        }

        private void ShowReport(List<Req> rep)
        {
            _reqs.Text = Requirements.Format(rep);
            _links.Controls.Clear();
            foreach (var r in rep)
            {
                if (r.Url == null) continue;
                var url = r.Url;
                var ll = new LinkLabel { AutoSize = true, Text = "Get: " + url, Margin = new Padding(0, 0, 0, 2) };
                ll.LinkClicked += (s, e) => { try { Process.Start(url); } catch { } };
                _links.Controls.Add(ll);
            }
            int code = Requirements.ExitCode(rep);
            _status.ForeColor = code == 0 ? Color.Gray : Color.DarkOrange;
            _status.Text = code == 0 ? "Everything needed is present."
                         : code == 2 ? "This package's programs cannot run on this PC - see above. Installing is still allowed."
                         : "Something is missing - see above. Installing is still allowed.";
        }

        private void OnInstall(object sender, EventArgs e)
        {
            string dir = (_path.Text ?? "").Trim();
            if (string.IsNullOrEmpty(dir)) { MessageBox.Show(this, "Choose an install location."); return; }
            string refused = SafeTarget.Problem(dir);
            if (refused != null) { MessageBox.Show(this, refused, "Setup", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            string busy;
            while ((busy = InUse.Check(dir)) != null)
                if (MessageBox.Show(this, busy + "\n\nClose it (tray icon > Exit), then press Retry.", "Setup", MessageBoxButtons.RetryCancel, MessageBoxIcon.Warning) != DialogResult.Retry) return;

            bool desktop = _desktop.Checked;
            SetBusy(true);
            var t = new Thread(() =>
            {
                Exception err = null;
                try { Installer.Install(dir, desktop, msg => { try { BeginInvoke((Action)(() => _status.Text = msg)); } catch { } }); }
                catch (Exception ex) { err = ex; }
                try { BeginInvoke((Action)(() => Finished(dir, err))); } catch { }
            }) { IsBackground = true };
            t.Start();
        }

        private void Finished(string dir, Exception err)
        {
            // First thing: the install is over, so the close guard must stop blocking. (It used to stay on, which
            // cancelled the Close() below and every click on the window's X after it.)
            SetBusy(false);
            if (err != null)
            {
                MessageBox.Show(this, "Install failed:\n\n" + err.Message, "Setup", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            if (MessageBox.Show(this, Program.AppName + " was installed.\n\nLaunch it now?", "Setup",
                MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                try { Process.Start(Path.Combine(dir, Program.ExeName)); } catch { }
            Close();
        }

        private void SetBusy(bool busy)
        {
            _busy = busy;
            _install.Enabled = _cancel.Enabled = _browse.Enabled = _path.Enabled = _desktop.Enabled = _check.Enabled = !busy;
            _bar.Visible = busy;
        }
    }
}

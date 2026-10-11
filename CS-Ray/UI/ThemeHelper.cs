using System;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;

namespace CS_Ray.UI
{
    /// <summary>How the app decides light vs. dark: follow the OS, or a fixed override.</summary>
    public enum ThemeMode { System, Light, Dark }

    /// <summary>
    /// Reads the Windows accent color + light/dark preference and raises <see cref="ThemeChanged"/> when either
    /// changes at runtime. Holds the app-wide <see cref="Mode"/>. Ported from TelegArm's proven ThemeHelper —
    /// resolve light/dark in ONE place so System and a manual override never drift between forms, and branch the
    /// accent read by OS version (8.1/RT keeps its accent in a DIFFERENT registry key than Win10/11).
    /// </summary>
    public static class ThemeHelper
    {
        private const string DwmKey = @"Software\Microsoft\Windows\DWM";
        private const string ExplorerAccentKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Accent";
        private const string PersonalizeKey = @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";

        private static readonly Color DefaultAccent = Color.FromArgb(0, 120, 215); // Windows default blue

        private static ThemeMode _mode = ThemeMode.System;

        public static ThemeMode Mode => _mode;

        /// <summary>Sets the mode WITHOUT notifying — use once at startup before any form reads the theme.</summary>
        public static void InitMode(ThemeMode mode) => _mode = mode;

        /// <summary>Sets the mode and raises <see cref="ThemeChanged"/> if it actually changed.</summary>
        public static void SetMode(ThemeMode mode)
        {
            if (_mode == mode) return;
            _mode = mode;
            ThemeChanged?.Invoke();
        }

        /// <summary>Resolved dark/light: Dark/Light are fixed; System reads the OS preference.</summary>
        public static bool IsDark =>
            _mode == ThemeMode.Dark || (_mode == ThemeMode.System && IsDarkMode());

        /// <summary>
        /// The single accent-resolution entry point for the whole app. Platform-branched because the user's chosen
        /// accent lives in different registry keys on different Windows versions:
        ///   • Windows 10/11    → HKCU\...\DWM\AccentColor
        ///   • Windows 8.1 / RT → HKCU\...\Explorer\Accent\AccentColor  (DWM\AccentColor doesn't exist there; the
        ///     DWM key only holds ColorizationColor — the composed frame TINT, not the picked swatch)
        /// Both are DWORDs in AABBGGRR (ABGR) byte order — low byte is red. Alpha is dropped (opaque). Never throws:
        /// any failure falls back to the DWM read, then the Windows default blue.
        /// </summary>
        public static Color GetWindowsAccentColor()
        {
            if (!IsWindows10OrGreater())
            {
                LogAccentDiagOnce();   // one-shot [ACCENT] truth line so the 8.1 read + decode is verifiable by log
                Color? c81 = ReadAbgrDword(ExplorerAccentKey, "AccentColor");
                if (c81.HasValue) return c81.Value;
            }
            return ReadAbgrDword(DwmKey, "AccentColor") ?? DefaultAccent;
        }

        /// <summary>Reads an HKCU DWORD accent value stored as AABBGGRR (ABGR, low byte = red) → opaque Color, or
        /// null if the key/value is missing or unreadable (so callers can fall back).</summary>
        private static Color? ReadAbgrDword(string subKey, string valueName)
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(subKey))
                {
                    if (key?.GetValue(valueName) is int dword)
                    {
                        int r = dword & 0xFF;
                        int g = (dword >> 8) & 0xFF;
                        int b = (dword >> 16) & 0xFF;
                        return Color.FromArgb(r, g, b);
                    }
                }
            }
            catch { /* fall through to null */ }
            return null;
        }

        // One-shot diagnostic for the 8.1 read: dumps the raw Explorer\Accent\AccentColor DWORD + BOTH decodes so
        // the byte order that yields the picked swatch is verifiable from the log (asABGR expected to match; asARGB
        // shown for contrast), plus whether DWM\AccentColor — the key the pre-fix read used — even exists on device.
        private static bool _accentDiagLogged;
        private static void LogAccentDiagOnce()
        {
            if (_accentDiagLogged) return;
            _accentDiagLogged = true;
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(ExplorerAccentKey))
                {
                    if (key?.GetValue("AccentColor") is int d)
                    {
                        int argbR = (d >> 16) & 0xFF, argbG = (d >> 8) & 0xFF, argbB = d & 0xFF;
                        int abgrR = d & 0xFF, abgrG = (d >> 8) & 0xFF, abgrB = (d >> 16) & 0xFF;
                        Debug.WriteLine("[ACCENT] Explorer\\Accent\\AccentColor=0x" + ((uint)d).ToString("X8")
                            + "  asARGB=" + argbR + "," + argbG + "," + argbB
                            + "  asABGR=" + abgrR + "," + abgrG + "," + abgrB);
                    }
                    else Debug.WriteLine("[ACCENT] Explorer\\Accent\\AccentColor MISSING");
                }
                using (var dwm = Registry.CurrentUser.OpenSubKey(DwmKey))
                {
                    object raw = dwm?.GetValue("AccentColor");
                    Debug.WriteLine("[ACCENT] DWM\\AccentColor=" + (raw is int dd ? "0x" + ((uint)dd).ToString("X8") : "MISSING")
                        + "  (source of the pre-fix read)");
                }
            }
            catch (Exception ex) { Debug.WriteLine("[ACCENT] diag failed: " + ex.Message); }
        }

        /// <summary>True when Windows uses the dark app theme (AppsUseLightTheme == 0).</summary>
        public static bool IsDarkMode()
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(PersonalizeKey))
                {
                    if (key?.GetValue("AppsUseLightTheme") is int v)
                        return v == 0;
                }
            }
            catch { /* default light */ }
            return false;
        }

        /// <summary>Raised when the accent color or light/dark preference changes.</summary>
        public static event Action ThemeChanged;

        private static bool _listening;

        public static void StartListening()
        {
            if (_listening) return;
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
            _listening = true;
        }

        public static void StopListening()
        {
            if (!_listening) return;
            SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
            _listening = false;
        }

        // Re-color plain WinForms controls (TextBox/ComboBox/CheckBox/Button/Label/Panel/ListBox) to match the
        // resolved dark/light. MaterialSkin.Controls.* self-theme — they're skipped. Shared by the main form body
        // and the settings popup so both stay consistent on a theme flip.
        public static void RecolorBody(Control root)
        {
            if (root == null) return;
            bool dark = IsDark;
            Color bg = dark ? Color.FromArgb(48, 48, 48) : Color.White;
            Color field = dark ? Color.FromArgb(60, 60, 60) : Color.White;
            Color fg = dark ? Color.Gainsboro : Color.Black;
            root.BackColor = bg;
            RecolorChildren(root, dark, bg, field, fg);
        }

        // Tag-aware: Labels tagged "accent" take the Windows accent, "dim" a muted gray; Panels tagged "div" become a
        // border line, "card" get the page bg + a repaint (their rounded border is owner-drawn). Owner-painted
        // controls (RoundedButton / ToggleSwitch) just invalidate. One pass shared by the main body, settings, drawer.
        private static void RecolorChildren(Control parent, bool dark, Color bg, Color field, Color fg)
        {
            foreach (Control c in parent.Controls)
            {
                if (c.GetType().Namespace == "MaterialSkin.Controls") continue; // self-themed
                if (c is RoundedButton || c is ToggleSwitch) { c.Invalidate(); RecolorChildren(c, dark, bg, field, fg); continue; }
                string tag = c.Tag as string;
                if (c is TextBox tb) { tb.BackColor = field; tb.ForeColor = fg; }
                else if (c is ListBox lb) { lb.BackColor = field; lb.ForeColor = fg; }
                else if (c is ComboBox cb) { cb.BackColor = field; cb.ForeColor = fg; }
                else if (c is CheckBox chk) { chk.ForeColor = fg; }
                else if (c is Button btn) { btn.FlatStyle = FlatStyle.Flat; btn.BackColor = field; btn.ForeColor = fg; }
                else if (c is Label lbl)
                {
                    if (tag == "accent") lbl.ForeColor = GetWindowsAccentColor();
                    else if (tag == "dim") lbl.ForeColor = dark ? Color.FromArgb(150, 150, 158) : Color.FromArgb(120, 120, 128);
                    else lbl.ForeColor = fg;
                }
                else if (c is Panel pnl)
                {
                    if (tag == "div") pnl.BackColor = dark ? Color.FromArgb(58, 58, 64) : Color.FromArgb(232, 232, 236);
                    else { pnl.BackColor = bg; if (tag == "card") pnl.Invalidate(); }
                }
                RecolorChildren(c, dark, bg, field, fg);
            }
        }

        private static void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
        {
            // Accent always follows the OS; the OS light/dark switch only moves the app while Mode == System
            // (a manual override is left untouched).
            if (e.Category == UserPreferenceCategory.Color)
                NotifyAccentChanged();   // route through the debounce so it coalesces with the WM_DWMCOLORIZATION path
            else if (e.Category == UserPreferenceCategory.General && _mode == ThemeMode.System)
                ThemeChanged?.Invoke();
        }

        // ── Live accent-change fan-out (Part 1.2) ──
        // Called from BOTH MainForm's WM_DWMCOLORIZATIONCOLORCHANGED handler (the reliable signal — it fires on 8.1
        // AND 10/11 when the accent/colorization changes) and the SystemEvents Color category. Fires ThemeChanged so
        // every subscriber re-reads GetWindowsAccentColor() and recolors live — no restart. Debounced: a single user
        // change often emits the notification several times, so repeats within ~300ms collapse to one recolor.
        private static int _lastAccentTick;
        public static void NotifyAccentChanged()
        {
            int now = Environment.TickCount;
            if (_lastAccentTick != 0 && unchecked((uint)(now - _lastAccentTick)) < 300) return;   // coalesce bursts
            _lastAccentTick = now;
            try
            {
                Debug.WriteLine("[ACCENT] change os=" + OsLabel()
                    + " → picked 0x" + ((uint)GetWindowsAccentColor().ToArgb()).ToString("X8"));
            }
            catch { }
            ThemeChanged?.Invoke();
        }

        // ── OS version via RtlGetVersion (Environment.OSVersion caps at 6.2 on an unmanifested app) ──
        [StructLayout(LayoutKind.Sequential)]
        private struct RTL_OSVERSIONINFOW
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
        }

        [DllImport("ntdll.dll")]
        private static extern int RtlGetVersion(ref RTL_OSVERSIONINFOW versionInfo);

        private static int _osMajor = -1, _osMinor, _osBuild;
        private static void EnsureOsVersion()
        {
            if (_osMajor >= 0) return;
            try
            {
                var vi = new RTL_OSVERSIONINFOW();
                vi.dwOSVersionInfoSize = (uint)Marshal.SizeOf(typeof(RTL_OSVERSIONINFOW));
                if (RtlGetVersion(ref vi) == 0)   // STATUS_SUCCESS
                {
                    _osMajor = (int)vi.dwMajorVersion; _osMinor = (int)vi.dwMinorVersion; _osBuild = (int)vi.dwBuildNumber;
                    return;
                }
            }
            catch { /* fall through to managed best-effort */ }
            try { var v = Environment.OSVersion.Version; _osMajor = v.Major; _osMinor = v.Minor; _osBuild = v.Build; }
            catch { _osMajor = 6; _osMinor = 3; _osBuild = 0; }   // assume 8.1 on total failure (safest for the read branch)
        }

        /// <summary>True on Windows 10 or newer (major &gt;= 10). Branches both the accent read and the log label.</summary>
        public static bool IsWindows10OrGreater() { EnsureOsVersion(); return _osMajor >= 10; }

        private static string OsLabel()
        {
            EnsureOsVersion();
            if (_osMajor >= 10) return _osBuild >= 22000 ? "11" : "10";
            if (_osMajor == 6 && _osMinor == 3) return "8.1";
            return _osMajor + "." + _osMinor;
        }
    }
}

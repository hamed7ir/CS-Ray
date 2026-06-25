using System;
using System.Drawing;
using System.Windows.Forms;
using Microsoft.Win32;

namespace CS_Ray.UI
{
    /// <summary>How the app decides light vs. dark: follow the OS, or a fixed override.</summary>
    public enum ThemeMode { System, Light, Dark }

    /// <summary>
    /// Reads the Windows accent color + light/dark preference and raises <see cref="ThemeChanged"/> when either
    /// changes at runtime. Holds the app-wide <see cref="Mode"/>. (Ported verbatim from TelegArm's proven
    /// ThemeHelper — resolve light/dark in ONE place so System and a manual override never drift between forms.)
    /// </summary>
    public static class ThemeHelper
    {
        private const string DwmKey = @"Software\Microsoft\Windows\DWM";
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

        /// <summary>Reads HKCU\...\DWM\AccentColor (DWORD in AABBGGRR byte order).</summary>
        public static Color GetWindowsAccentColor()
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(DwmKey))
                {
                    if (key?.GetValue("AccentColor") is int dword)
                    {
                        int r = dword & 0xFF;
                        int g = (dword >> 8) & 0xFF;
                        int b = (dword >> 16) & 0xFF;
                        return Color.FromArgb(r, g, b);
                    }
                }
            }
            catch { /* default on any failure */ }
            return DefaultAccent;
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
        // resolved dark/light. MaterialSkin.Controls.* self-theme — they're skipped. Shared by the main form
        // body and the hamburger popup so both stay consistent on a theme flip.
        public static void RecolorBody(Control root)
        {
            if (root == null) return;
            bool dark = IsDark;
            Color bg = dark ? Color.FromArgb(48, 48, 48) : Color.White;
            Color field = dark ? Color.FromArgb(60, 60, 60) : Color.White;
            Color fg = dark ? Color.Gainsboro : Color.Black;
            root.BackColor = bg;
            RecolorChildren(root, bg, field, fg);
        }

        private static void RecolorChildren(Control parent, Color bg, Color field, Color fg)
        {
            foreach (Control c in parent.Controls)
            {
                if (c.GetType().Namespace == "MaterialSkin.Controls") continue; // self-themed
                if (c is TextBox tb) { tb.BackColor = field; tb.ForeColor = fg; }
                else if (c is ListBox lb) { lb.BackColor = field; lb.ForeColor = fg; }
                else if (c is ComboBox cb) { cb.BackColor = field; cb.ForeColor = fg; }
                else if (c is CheckBox chk) { chk.ForeColor = fg; }
                else if (c is Button btn) { btn.FlatStyle = FlatStyle.Flat; btn.BackColor = field; btn.ForeColor = fg; }
                else if (c is Label lbl) { lbl.ForeColor = fg; }
                else if (c is Panel pnl) { pnl.BackColor = bg; }
                RecolorChildren(c, bg, field, fg);
            }
        }

        private static void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
        {
            // Accent always follows the OS; the OS light/dark switch only moves the app while Mode == System
            // (a manual override is left untouched).
            if (e.Category == UserPreferenceCategory.Color)
                ThemeChanged?.Invoke();
            else if (e.Category == UserPreferenceCategory.General && _mode == ThemeMode.System)
                ThemeChanged?.Invoke();
        }
    }
}

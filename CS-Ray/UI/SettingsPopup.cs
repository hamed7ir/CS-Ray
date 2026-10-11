using System;
using System.Drawing;
using System.Windows.Forms;
using MaterialSkin;
using MaterialSkin.Controls;

namespace CS_Ray.UI
{
    /// <summary>
    /// Tabbed settings window. MaterialForm with the FULL accent action bar (like the main window). Two flat
    /// group-style tabs (General / Subscriptions) using the same <see cref="GroupTabStrip"/> as the main form —
    /// NOT MaterialButton pills. It owns no logic: MainForm fills <see cref="GeneralPage"/> / <see cref="SubsPage"/>
    /// with its already-wired controls. Created once and re-shown (never disposed) so hosted controls persist.
    /// </summary>
    public sealed class SettingsPopup : MaterialForm
    {
        private readonly MaterialSkinManager _skin;
        private readonly TabControl _tabs;       // hidden backing model for the strip
        private readonly GroupTabStrip _strip;
        private readonly Panel _host;

        public Panel GeneralPage { get; }
        public Panel SubsPage { get; }

        public SettingsPopup()
        {
            _skin = MaterialSkinManager.Instance;
            _skin.AddFormToManage(this);
            if (IconHelper.App != null) Icon = IconHelper.App; // window icon (taskbar / Alt-Tab)

            Text = "CS-Ray — Settings";            // shown in the accent action bar
            AutoScaleMode = AutoScaleMode.Font;
            Font = FontHelper.Ui(9f);
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = false; MinimizeBox = false; Sizable = false;
            ClientSize = new Size(600, 640);
            KeyPreview = true;
            KeyDown += (s, e) => { if (e.KeyCode == Keys.Escape) Hide(); };

            // Hidden backing TabControl drives the flat strip.
            _tabs = new TabControl { Visible = false };
            _tabs.TabPages.Add(new TabPage("General"));
            _tabs.TabPages.Add(new TabPage("Subscriptions"));
            Controls.Add(_tabs);

            _host = new Panel { Dock = DockStyle.Fill }; // added first → docks last, takes leftover space
            Controls.Add(_host);

            var top = new Panel { Dock = DockStyle.Top, Height = 38 };
            _strip = new GroupTabStrip(FontHelper.Ui(10f, FontStyle.Bold)) { Dock = DockStyle.Fill };
            _strip.BaseTabControl = _tabs;
            _strip.SelectedTabChanged += (s, e) => ShowPage();
            top.Controls.Add(_strip);
            Controls.Add(top);

            var footer = new Panel { Dock = DockStyle.Bottom, Height = 50 };
            var close = new MaterialButton { Text = "Close", Type = MaterialButton.MaterialButtonType.Contained, AutoSize = false, Width = 100, Height = 36 };
            close.Click += (s, e) => Hide();
            footer.Resize += (s, e) => close.Location = new Point(footer.ClientSize.Width - 116, 8);
            footer.Controls.Add(close);
            Controls.Add(footer);

            GeneralPage = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Visible = true };
            SubsPage = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Visible = false };
            _host.Controls.Add(GeneralPage);
            _host.Controls.Add(SubsPage);

            _tabs.SelectedIndex = 0;

            ApplyTheme();
            ThemeHelper.ThemeChanged += OnThemeChanged;
            FormClosed += (s, e) => ThemeHelper.ThemeChanged -= OnThemeChanged;
            FormClosing += (s, e) => { if (e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; Hide(); } };
        }

        private void ShowPage()
        {
            bool gen = _tabs.SelectedIndex == 0;
            GeneralPage.Visible = gen;
            SubsPage.Visible = !gen;
            if (gen) GeneralPage.BringToFront(); else SubsPage.BringToFront();
        }

        private void ApplyTheme()
        {
            _skin.Theme = ThemeHelper.IsDark ? MaterialSkinManager.Themes.DARK : MaterialSkinManager.Themes.LIGHT;
            var win = ThemeHelper.GetWindowsAccentColor();
            var accent = (Primary)(uint)win.ToArgb();
            // Singleton-trap fix: the MaterialSkin Accent slot carries the SAME Windows accent, not LightBlue200.
            _skin.ColorScheme = new ColorScheme(accent, accent, accent, (Accent)(uint)win.ToArgb(), TextShade.WHITE);
            ThemeHelper.RecolorBody(_host);
            _strip.Invalidate();
        }

        private void OnThemeChanged()
        {
            if (IsDisposed) return;
            try { BeginInvoke((Action)(() => { ApplyTheme(); Invalidate(true); })); } catch { }
        }

        /// <summary>Show modally on the General tab.</summary>
        public void Open(IWin32Window owner)
        {
            _tabs.SelectedIndex = 0;
            ShowPage();
            ThemeHelper.RecolorBody(_host);
            _strip.Invalidate();
            ShowDialog(owner);
        }
    }
}

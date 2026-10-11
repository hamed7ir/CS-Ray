using System;
using System.Drawing;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>
    /// Tabbed settings window: a <see cref="ThemedDialog"/> (accent title bar + Close footer) with two flat group-style
    /// tabs (General / Subscriptions) using the same <see cref="GroupTabStrip"/> as the main form. Each page is a
    /// <see cref="ThemedScrollPanel"/> (owner-drawn scrollbar — RT 8.1's native one can't go dark). It owns no logic:
    /// MainForm fills <see cref="GeneralPage"/> / <see cref="SubsPage"/> (the scroll panels' hosts) with its
    /// already-wired controls. Created once and re-shown (never disposed) so hosted controls persist.
    /// </summary>
    public sealed class SettingsPopup : ThemedDialog
    {
        private readonly TabControl _tabs;       // hidden backing model for the strip
        private readonly GroupTabStrip _strip;
        private readonly Panel _host;
        private readonly ThemedScrollPanel _genScroll, _subsScroll;

        public Panel GeneralPage => _genScroll.Host;
        public Panel SubsPage => _subsScroll.Host;

        public SettingsPopup() : base("CS-Ray — Settings", scrollBody: false)
        {
            KeyPreview = true;
            KeyDown += (s, e) => { if (e.KeyCode == Keys.Escape) Hide(); };

            // Hidden backing TabControl drives the flat strip.
            _tabs = new TabControl { Visible = false };
            _tabs.TabPages.Add(new TabPage("General"));
            _tabs.TabPages.Add(new TabPage("Subscriptions"));
            Controls.Add(_tabs);

            _host = new Panel { Dock = DockStyle.Fill }; // added first → docks last, takes leftover space
            Content.Controls.Add(_host);

            var tabFont = FontHelper.Ui(10f, FontStyle.Bold);
            var top = new Panel { Dock = DockStyle.Top, Height = Math.Max(DrawHelper.Px(38), tabFont.Height + DrawHelper.Px(18)) };
            _strip = new GroupTabStrip(tabFont) { Dock = DockStyle.Fill };
            _strip.BaseTabControl = _tabs;
            _strip.SelectedTabChanged += (s, e) => ShowPage();
            top.Controls.Add(_strip);
            Content.Controls.Add(top);

            var close = AddFooterButton("Close", RoundedButtonKind.Primary);
            close.Click += (s, e) => Hide();

            _genScroll = new ThemedScrollPanel { Dock = DockStyle.Fill, Visible = true };
            _subsScroll = new ThemedScrollPanel { Dock = DockStyle.Fill, Visible = false };
            _host.Controls.Add(_genScroll);
            _host.Controls.Add(_subsScroll);

            ClientSize = new Size(DrawHelper.Px(600), DrawHelper.Px(640));   // pages are laid out in DrawHelper.Px too
            _tabs.SelectedIndex = 0;

            ApplyTheme();
            ThemeHelper.ThemeChanged += OnThemeChanged;
            FormClosed += (s, e) => ThemeHelper.ThemeChanged -= OnThemeChanged;
            FormClosing += (s, e) => { if (e.CloseReason == CloseReason.UserClosing) { e.Cancel = true; Hide(); } };
        }

        private void ShowPage()
        {
            bool gen = _tabs.SelectedIndex == 0;
            _genScroll.Visible = gen;
            _subsScroll.Visible = !gen;
            if (gen) _genScroll.BringToFront(); else _subsScroll.BringToFront();
        }

        private void ApplyTheme()
        {
            ThemeHelper.RecolorBody(_host);
            _strip.Invalidate();
        }

        private void OnThemeChanged()
        {
            if (IsDisposed || !IsHandleCreated) return;   // closed → Open() recolors the pages before showing
            try { BeginInvoke((Action)(() => { ApplyTheme(); Invalidate(true); })); } catch { }
        }

        /// <summary>Show modally on the General tab.</summary>
        public void Open(IWin32Window owner)
        {
            // Re-clamp per open (the owner may be on another monitor): never taller than ~92% of the work area —
            // the pages scroll instead of the Close footer falling off-screen.
            Rectangle wa;
            try { wa = owner is Control oc ? Screen.FromControl(oc).WorkingArea : Screen.FromPoint(Cursor.Position).WorkingArea; }
            catch { wa = Screen.PrimaryScreen.WorkingArea; }
            ClientSize = new Size(DrawHelper.Px(600), Math.Min(DrawHelper.Px(640), (int)(wa.Height * 0.92)));
            _tabs.SelectedIndex = 0;
            ShowPage();
            _genScroll.RelayoutContent();
            _subsScroll.RelayoutContent();
            ThemeHelper.RecolorBody(_host);
            _strip.Invalidate();
            ShowDialog(owner);
        }
    }
}

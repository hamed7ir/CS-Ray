using System;
using System.Diagnostics;
using System.Drawing;
using System.Reflection;
using System.Windows.Forms;
using MaterialSkin;
using MaterialSkin.Controls;

namespace CS_Ray.UI
{
    /// <summary>
    /// Themed About dialog (MaterialForm, accent action bar + app icon): the app icon, name + version, a short
    /// description, a strong PRIVACY note (collects zero data / sends nothing), the GPL/license line, and a clickable
    /// GitHub link. Replaces the old plain MessageBox. Follows the SubEditDialog layout pattern (absolute positions
    /// offset by the action-bar TopInset); plain Labels take the MaterialSkin background so they blend with the form.
    /// </summary>
    public sealed class AboutDialog : MaterialForm
    {
        private const string RepoUrl = "https://github.com/hamed7ir/CS-Ray";

        private readonly PictureBox _pic;
        private readonly Label _name, _ver, _desc, _privacy, _license;
        private readonly LinkLabel _link;
        private readonly MaterialButton _btnClose;

        public AboutDialog()
        {
            var skin = MaterialSkinManager.Instance;
            skin.AddFormToManage(this);
            if (IconHelper.App != null) Icon = IconHelper.App;
            skin.Theme = ThemeHelper.IsDark ? MaterialSkinManager.Themes.DARK : MaterialSkinManager.Themes.LIGHT;
            var win = ThemeHelper.GetWindowsAccentColor();
            var accent = (Primary)(uint)win.ToArgb();
            skin.ColorScheme = new ColorScheme(accent, accent, accent, (Accent)(uint)win.ToArgb(), TextShade.WHITE);

            Text = "About CS-Ray";
            AutoScaleMode = AutoScaleMode.Font;
            Font = FontHelper.Ui(9f);
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = false; MinimizeBox = false; Sizable = false;
            KeyPreview = true;
            KeyDown += (s, e) => { if (e.KeyCode == Keys.Escape) Close(); };

            bool dark = ThemeHelper.IsDark;
            Color bg = skin.BackgroundColor;                                             // match the form body exactly
            Color fg = dark ? Color.FromArgb(232, 232, 236) : Color.FromArgb(33, 33, 38);
            Color dim = dark ? Color.FromArgb(150, 150, 158) : Color.FromArgb(120, 120, 128);
            Color safe = dark ? Color.FromArgb(104, 190, 130) : Color.FromArgb(38, 140, 86); // trust green for privacy

            _pic = new PictureBox { Size = new Size(76, 76), SizeMode = PictureBoxSizeMode.StretchImage, BackColor = bg };
            try { if (IconHelper.App != null) _pic.Image = new Icon(IconHelper.App, 76, 76).ToBitmap(); } catch { }

            _name = MakeLabel("CS-Ray", FontHelper.Ui(17f, FontStyle.Bold), fg, bg, 30);
            _ver = MakeLabel("version " + VersionString(), FontHelper.Ui(9f), dim, bg, 20);
            _desc = MakeLabel(
                "Pure-managed C# proxy client for legacy ARM32 Windows.\nVLESS · VMess · Shadowsocks · TUN full-tunnel · subscriptions.",
                FontHelper.Ui(9f), fg, bg, 44);
            _privacy = MakeLabel(
                "This app collects ZERO data and sends nothing anywhere.\nNo telemetry, no analytics, no phone-home — it connects ONLY to the servers you add.",
                FontHelper.Ui(9f, FontStyle.Bold), safe, bg, 46);
            _link = new LinkLabel
            {
                Text = RepoUrl, AutoSize = false, Height = 20, TextAlign = ContentAlignment.MiddleCenter, BackColor = bg,
                Font = FontHelper.Ui(9f), LinkColor = win, ActiveLinkColor = win, VisitedLinkColor = win,
                LinkBehavior = LinkBehavior.HoverUnderline
            };
            _link.LinkClicked += (s, e) => { try { Process.Start(RepoUrl); } catch { } };
            _license = MakeLabel("Free & open-source (GPLv3) — audit it on GitHub. © 2026 Hamed.", FontHelper.Ui(8f), dim, bg, 16);

            _btnClose = new MaterialButton { Text = "Close", Type = MaterialButton.MaterialButtonType.Contained, AutoSize = false, Width = 110, Height = 36 };
            _btnClose.Click += (s, e) => Close();

            Controls.Add(_pic); Controls.Add(_name); Controls.Add(_ver); Controls.Add(_desc);
            Controls.Add(_privacy); Controls.Add(_link); Controls.Add(_license); Controls.Add(_btnClose);
            AcceptButton = _btnClose; CancelButton = _btnClose;

            Relayout();
        }

        private static Label MakeLabel(string text, Font font, Color fore, Color back, int h)
            => new Label { Text = text, AutoSize = false, Height = h, TextAlign = ContentAlignment.MiddleCenter, Font = font, ForeColor = fore, BackColor = back };

        // MaterialForm reserves its accent action bar via Padding.Top (fallback 64 before it's known).
        private int TopInset => Math.Max(64, Padding.Top);

        protected override void OnLoad(EventArgs e) { base.OnLoad(e); Relayout(); }

        private void Relayout()
        {
            const int W = 468;
            int cx = W / 2;
            int y = TopInset + 16;
            _pic.Location = new Point(cx - _pic.Width / 2, y); y += _pic.Height + 8;
            Row(_name, W, ref y, 2);
            Row(_ver, W, ref y, 12);
            Row(_desc, W, ref y, 12);
            Row(_privacy, W, ref y, 10);
            Row(_link, W, ref y, 4);
            Row(_license, W, ref y, 16);
            _btnClose.Location = new Point(cx - _btnClose.Width / 2, y); y += _btnClose.Height + 16;
            ClientSize = new Size(W, y);
        }

        private static void Row(Control c, int w, ref int y, int gap)
        {
            c.SetBounds(16, y, w - 32, c.Height);
            y += c.Height + gap;
        }

        private static string VersionString()
        {
            try { var v = Assembly.GetExecutingAssembly().GetName().Version; return v.Major + "." + v.Minor + "." + v.Build; }
            catch { return "1.1.0"; }
        }
    }
}

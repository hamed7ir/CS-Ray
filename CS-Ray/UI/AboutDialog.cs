using System;
using System.Diagnostics;
using System.Drawing;
using System.Reflection;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>
    /// Themed About dialog (<see cref="ThemedDialog"/>: accent title bar + footer): the app icon, name + version, a
    /// short description, a strong PRIVACY note (collects zero data / sends nothing), the GPL/license line, and a
    /// clickable GitHub link. Centered rows at absolute positions in the body; recolors live with the theme.
    /// </summary>
    public sealed class AboutDialog : ThemedDialog
    {
        private const string RepoUrl = "https://github.com/hamed7ir/CS-Ray";

        private readonly PictureBox _pic;
        private readonly Label _name, _ver, _desc, _privacy, _license;
        private readonly LinkLabel _link;
        private readonly RoundedButton _btnClose;

        public AboutDialog() : base("About CS-Ray")
        {
            KeyPreview = true;
            KeyDown += (s, e) => { if (e.KeyCode == Keys.Escape) Close(); };

            _pic = new PictureBox { Size = new Size(DrawHelper.Px(76), DrawHelper.Px(76)), SizeMode = PictureBoxSizeMode.StretchImage };
            try { if (IconHelper.App != null) _pic.Image = new Icon(IconHelper.App, _pic.Width, _pic.Height).ToBitmap(); } catch { }

            _name = MakeLabel("CS-Ray", FontHelper.Ui(17f, FontStyle.Bold));
            _ver = MakeLabel("version " + VersionString(), FontHelper.Ui(9f));
            _desc = MakeLabel(
                "A proxy client written only in C#, so it runs on old ARM32 Windows too.\nVLESS, VMess, Shadowsocks, REALITY, XHTTP, full tunnel and subscriptions.",
                FontHelper.Ui(9f));
            _privacy = MakeLabel(
                "This app collects no data and sends nothing anywhere.\nNo telemetry, no analytics. It only connects to the servers you add.",
                FontHelper.Ui(9f, FontStyle.Bold));
            _link = new LinkLabel
            {
                Text = RepoUrl, AutoSize = false, TextAlign = ContentAlignment.MiddleCenter,
                Font = FontHelper.Ui(9f), LinkBehavior = LinkBehavior.HoverUnderline
            };
            _link.LinkClicked += (s, e) => { try { Process.Start(RepoUrl); } catch { } };
            _license = MakeLabel("Free and open source (GPLv3). All the code is on GitHub. © 2026 Hamed.", FontHelper.Ui(8f));

            foreach (Control c in new Control[] { _pic, _name, _ver, _desc, _privacy, _link, _license }) Body.Host.Controls.Add(c);

            _btnClose = AddFooterButton("Close", RoundedButtonKind.Primary, DialogResult.Cancel);
            AcceptButton = _btnClose; CancelButton = _btnClose;

            ApplyDialogTheme();
            Relayout();
        }

        private static Label MakeLabel(string text, Font font)
            => new Label { Text = text, AutoSize = false, TextAlign = ContentAlignment.MiddleCenter, Font = font, UseMnemonic = false }; // "&" is literal

        protected override void ApplyDialogTheme()
        {
            base.ApplyDialogTheme();
            if (_name == null) return; // base ctor runs this before the rows exist
            var p = ThemeHelper.Palette();
            Color safe = p.Dark ? Color.FromArgb(104, 190, 130) : Color.FromArgb(38, 140, 86); // trust green for privacy
            foreach (Control c in new Control[] { _pic, _name, _ver, _desc, _privacy, _link, _license }) c.BackColor = p.Surface;
            _name.ForeColor = p.Text; _desc.ForeColor = p.Text;
            _ver.ForeColor = p.Dim; _license.ForeColor = p.Dim;
            _privacy.ForeColor = safe;
            _link.LinkColor = _link.ActiveLinkColor = _link.VisitedLinkColor = p.AccentText;
        }

        // Rows are centered at font-derived heights (each label's text measured at its own font).
        private void Relayout()
        {
            int w = DrawHelper.Px(468);
            int y = DrawHelper.Px(16);
            _pic.Location = new Point((w - _pic.Width) / 2, y); y += _pic.Height + DrawHelper.Px(8);
            Row(_name, w, ref y, DrawHelper.Px(2));
            Row(_ver, w, ref y, DrawHelper.Px(12));
            Row(_desc, w, ref y, DrawHelper.Px(12));
            Row(_privacy, w, ref y, DrawHelper.Px(10));
            Row(_link, w, ref y, DrawHelper.Px(4));
            Row(_license, w, ref y, DrawHelper.Px(12));
            FitToContent(w, y);
        }

        private static void Row(Control c, int w, ref int y, int gap)
        {
            int inner = w - 2 * DrawHelper.Px(16);
            int h = TextRenderer.MeasureText(c.Text, c.Font, new Size(inner, int.MaxValue), TextFormatFlags.WordBreak).Height + DrawHelper.Px(4);
            c.SetBounds(DrawHelper.Px(16), y, inner, h);
            y += h + gap;
        }

        private static string VersionString()
        {
            try { var v = Assembly.GetExecutingAssembly().GetName().Version; return v.Major + "." + v.Minor + "." + v.Build; }
            catch { return "2.0.0"; }
        }
    }
}

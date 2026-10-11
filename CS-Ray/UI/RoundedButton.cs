using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>How a <see cref="RoundedButton"/> is coloured (its role), so a destructive button stays red and a
    /// list-row stays subtle rather than everything becoming accent-blue.</summary>
    public enum RoundedButtonKind { Primary, Secondary, Neutral, Danger }

    /// <summary>
    /// A rounded, accent-aware button that matches the MaterialButton look (rounded + live Windows accent) but keeps
    /// STANDARD Button metrics and text casing (no uppercase, no ripple, no auto-height) so it drops into existing
    /// pixel layouts without shifting them. Reads the accent + dark/light from <see cref="ThemeHelper"/> and
    /// recolours live on <see cref="ThemeHelper.ThemeChanged"/>. Ported from TelegArm's RoundedButton (kept in the
    /// flat CS_Ray.UI namespace — no Controls sub-namespace — so the CS1061 `Controls.RoundedButtonKind` trap can't
    /// arise). Field type stays <see cref="Button"/> at call sites (this derives from it), so Text/Enabled/Click work.
    ///   Primary   = accent-filled   (the main action: Start / Save / Add)
    ///   Secondary = accent-outlined  (secondary action: Test / Cancel / Update)
    ///   Neutral   = subtle surface    (low-emphasis: Clear log / utility)
    ///   Danger    = red               (destructive: Remove / Delete — NEVER forced to accent)
    /// </summary>
    public sealed class RoundedButton : Button
    {
        private RoundedButtonKind _kind = RoundedButtonKind.Primary;
        private int _radius = 8;
        private bool _hover, _down;

        public RoundedButtonKind Kind { get { return _kind; } set { _kind = value; Invalidate(); } }
        public int Radius { get { return _radius; } set { _radius = value; Invalidate(); } }

        public RoundedButton()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer, true);
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            Cursor = Cursors.Hand;
            ThemeHelper.ThemeChanged += OnThemeChanged;
        }

        private void OnThemeChanged() { if (!IsDisposed && IsHandleCreated) { try { BeginInvoke((Action)Invalidate); } catch { } } }

        protected override void Dispose(bool disposing)
        {
            if (disposing) ThemeHelper.ThemeChanged -= OnThemeChanged;
            base.Dispose(disposing);
        }

        protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { _hover = false; _down = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { _down = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { _down = false; Invalidate(); base.OnMouseUp(e); }
        protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            bool dark = ThemeHelper.IsDark;
            Color accent = ThemeHelper.GetWindowsAccentColor();
            Color pbg = Parent != null ? Parent.BackColor : (dark ? Color.FromArgb(48, 48, 48) : Color.White);
            g.Clear(pbg);   // so the rounded corners reveal the surface behind, not a square in the wrong shade

            Color fill, text; Color border = Color.Empty;
            switch (_kind)
            {
                case RoundedButtonKind.Danger:
                    fill = Color.FromArgb(222, 74, 74); text = Color.White; break;
                case RoundedButtonKind.Neutral:
                    fill = dark ? Color.FromArgb(60, 60, 64) : Color.FromArgb(234, 234, 238);
                    text = dark ? Color.FromArgb(230, 230, 234) : Color.FromArgb(35, 35, 40); break;
                case RoundedButtonKind.Secondary:
                    fill = pbg; text = accent; border = accent; break;
                default:   // Primary
                    fill = accent; text = Color.White; break;
            }

            if (!Enabled)
            {
                fill = dark ? Color.FromArgb(55, 55, 58) : Color.FromArgb(226, 226, 229);
                text = dark ? Color.FromArgb(120, 120, 124) : Color.FromArgb(150, 150, 154);
                border = Color.Empty;
            }
            else if (_down) fill = Blend(fill, Color.Black, 0.16f);
            else if (_hover) fill = _kind == RoundedButtonKind.Secondary ? Blend(pbg, accent, 0.12f)
                                                                         : Blend(fill, Color.White, dark ? 0.10f : 0.06f);

            var r = new Rectangle(0, 0, Math.Max(1, Width - 1), Math.Max(1, Height - 1));
            using (var path = RoundedRect(r, _radius))
            {
                using (var b = new SolidBrush(fill)) g.FillPath(b, path);
                if (border != Color.Empty && Enabled) using (var p = new Pen(border, 1.4f)) g.DrawPath(p, path);
            }
            var flags = TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix;
            bool left = TextAlign == ContentAlignment.MiddleLeft || TextAlign == ContentAlignment.TopLeft || TextAlign == ContentAlignment.BottomLeft;
            bool right = TextAlign == ContentAlignment.MiddleRight || TextAlign == ContentAlignment.TopRight || TextAlign == ContentAlignment.BottomRight;
            flags |= left ? TextFormatFlags.Left : right ? TextFormatFlags.Right : TextFormatFlags.HorizontalCenter;
            var tr = new Rectangle(Padding.Left + (left ? 8 : 2), 0, Math.Max(1, Width - Padding.Left - Padding.Right - (left ? 10 : 4)), Height);
            TextRenderer.DrawText(g, Text ?? "", Font, tr, text, flags);
        }

        // Self-contained rounded-rect path (TelegArm's RoundedButton pulled this from a shared DrawHelper; CS-Ray has
        // no such helper, so inline it to keep the control dependency-free).
        private static GraphicsPath RoundedRect(Rectangle r, int radius)
        {
            int d = Math.Max(1, radius) * 2;
            if (d > r.Width) d = Math.Max(1, r.Width);
            if (d > r.Height) d = Math.Max(1, r.Height);
            var path = new GraphicsPath();
            path.AddArc(r.X, r.Y, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }

        private static Color Blend(Color a, Color b, float t)
        {
            return Color.FromArgb(
                (int)(a.R + (b.R - a.R) * t),
                (int)(a.G + (b.G - a.G) * t),
                (int)(a.B + (b.B - a.B) * t));
        }
    }
}

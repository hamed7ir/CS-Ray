using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>
    /// Owner-drawn on/off slider (like TelegArm's Night Mode toggle) that replaces WinForms CheckBox across CS-Ray.
    /// Accent-aware — reads ThemeHelper's Windows accent + dark/light and recolors live on ThemeChanged, like
    /// RoundedButton. DROP-IN for CheckBox: exposes Checked (get/set) + CheckedChanged, and — exactly like CheckBox —
    /// the setter raises CheckedChanged whenever the value actually CHANGES (programmatic OR via a click), so existing
    /// code that assigns .Checked to drive a handler keeps working unchanged.
    /// </summary>
    public sealed class ToggleSwitch : Control
    {
        private bool _checked;
        private bool _hover;

        public event EventHandler CheckedChanged;

        public bool Checked
        {
            get { return _checked; }
            set
            {
                if (_checked == value) return;
                _checked = value;
                Invalidate();
                CheckedChanged?.Invoke(this, EventArgs.Empty);
            }
        }

        public ToggleSwitch()
        {
            Size = new Size(DrawHelper.Px(44), DrawHelper.Px(24));   // 44x24 design px at the system DPI
            Cursor = Cursors.Hand;
            TabStop = false;            // opt-in per use (a dialog form sets TabStop = true for keyboard access)
            AccessibleRole = AccessibleRole.CheckButton;
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
                     | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            ThemeHelper.ThemeChanged += OnThemeChanged;
        }

        // Keyboard: Space flips it like a CheckBox (when it's a tab stop and focused).
        protected override void OnKeyUp(KeyEventArgs e) { base.OnKeyUp(e); if (e.KeyCode == Keys.Space) { Checked = !Checked; e.Handled = true; } }
        protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
        protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); Invalidate(); }

        private void OnThemeChanged() { if (!IsDisposed && IsHandleCreated) { try { BeginInvoke((Action)Invalidate); } catch { } } }

        protected override void Dispose(bool disposing)
        {
            if (disposing) ThemeHelper.ThemeChanged -= OnThemeChanged;
            base.Dispose(disposing);
        }

        protected override void OnMouseEnter(EventArgs e) { _hover = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { _hover = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnClick(EventArgs e) { base.OnClick(e); Checked = !Checked; }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var pal = ThemeHelper.Palette();
            bool dark = pal.Dark;
            Color accent = pal.Accent;
            g.Clear(Parent != null ? Parent.BackColor : (dark ? Color.FromArgb(48, 48, 48) : Color.White));

            var track = new Rectangle(0, 0, Width - 1, Height - 1);
            Color off = dark ? Color.FromArgb(78, 78, 84) : Color.FromArgb(198, 198, 205);
            Color on = accent;
            if (_hover)
            {
                on = DrawHelper.Blend(on, Color.White, dark ? 0.12f : 0.08f);
                off = DrawHelper.Blend(off, dark ? Color.White : Color.Black, 0.08f);
            }
            using (var b = new SolidBrush(_checked ? on : off))
            using (var path = DrawHelper.RoundedRect(track, Height / 2))
                g.FillPath(b, path);

            int inset = Math.Max(2, Height / 6);   // 4px at the 24px design height
            int knob = Height - 2 * inset;
            int kx = _checked ? Width - knob - inset : inset;
            using (var b = new SolidBrush(Color.White))
                g.FillEllipse(b, kx, inset, knob, knob);

            if (Focused && ShowFocusCues)   // keyboard focus cue: a dotted ring just inside the track
                using (var pen = new Pen(_checked ? Color.White : pal.AccentText, 1f) { DashStyle = DashStyle.Dot })
                using (var path = DrawHelper.RoundedRect(Rectangle.Inflate(track, -2, -2), Math.Max(1, Height / 2 - 2)))
                    g.DrawPath(pen, path);
        }
    }
}

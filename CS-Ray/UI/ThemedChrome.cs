using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>
    /// Shared pieces of the borderless themed chrome (ported from DroidFinestra's Helpers/ThemedChrome.cs): the app
    /// icon on every window, plus the accent <see cref="ThemedTitleBar"/>. <see cref="ThemedForm"/> (main window)
    /// and <see cref="ThemedDialog"/> (modal dialogs) build on these. Replaces MaterialForm's chrome.
    /// </summary>
    internal static class ThemedChrome
    {
        /// <summary>Puts the app icon (icon.ico) on a form so the taskbar / Alt-Tab show it. RT-safe no-op if the
        /// icon can't be loaded (the form still opens).</summary>
        public static void SetAppIcon(Form form)
        {
            if (form == null || IconHelper.App == null) return;
            try { form.Icon = IconHelper.App; } catch { }
        }
    }

    /// <summary>
    /// The accent title bar of a borderless themed window, owner-painted as ONE control (title + glyph buttons, no
    /// child controls): white title on the Windows accent, flat minimize / maximize-restore / close glyphs drawn with
    /// GDI+ lines (no font/emoji dependency → identical on RT 8.1 and 10/11) with DroidFinestra's lighter hover wash.
    /// Dragging the bar moves the window via the native caption move (smooth, Aero-snap aware); double-click toggles
    /// maximize when the maximize glyph is shown. Recolors live on <see cref="ThemeHelper.ThemeChanged"/>.
    /// </summary>
    public sealed class ThemedTitleBar : Control, ISelfThemed
    {
        private enum Glyph { None, Minimize, Maximize, Close }

        [DllImport("user32.dll")] private static extern bool ReleaseCapture();
        [DllImport("user32.dll")] private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
        private const int WM_NCLBUTTONDOWN = 0x00A1, HTCAPTION = 2, WM_NCHITTEST = 0x0084, HTTRANSPARENT = -1;

        private static readonly Font TitleFont = FontHelper.Ui(10.5f, FontStyle.Bold); // private ref (never reassigned)

        private string _title = "";
        private bool _showMin, _showMax, _showClose = true;
        private int _resizeEdge;
        private Glyph _hover = Glyph.None, _pressed = Glyph.None;
        private bool _restorePending;   // press on a MAXIMIZED bar: restore + move once it's dragged past the slop
        private Point _restoreStart;

        /// <summary>Bar height for the current DPI: compact like a native caption (32 design px — MaterialForm's 64px
        /// status + action bar is gone), font-derived so the title never clips.</summary>
        public static int PreferredBarHeight => Math.Max(DrawHelper.Px(32), TitleFont.Height + DrawHelper.Px(12));

        public string Title { get { return _title; } set { _title = value ?? ""; Invalidate(); } }
        public bool ShowMinimize { get { return _showMin; } set { if (_showMin != value) { _showMin = value; Invalidate(); } } }
        public bool ShowMaximize { get { return _showMax; } set { if (_showMax != value) { _showMax = value; Invalidate(); } } }
        public bool ShowClose { get { return _showClose; } set { if (_showClose != value) { _showClose = value; Invalidate(); } } }

        /// <summary>Width of the top/left/right edge strip that is hit-test TRANSPARENT so the owning form's resize
        /// border reaches over the bar (0 = none; set by <see cref="ThemedForm"/> while resizable + not maximized).</summary>
        public int ResizeEdge { get { return _resizeEdge; } set { _resizeEdge = Math.Max(0, value); } }

        public ThemedTitleBar()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
                     | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            SetStyle(ControlStyles.Selectable, false); // a drag/click on the bar must not steal focus from a field
            TabStop = false;
            Height = PreferredBarHeight;
            ThemeHelper.ThemeChanged += OnThemeChanged;
        }

        public void ApplyTheme() => Invalidate();

        private void OnThemeChanged() { if (!IsDisposed && IsHandleCreated) { try { BeginInvoke((Action)Invalidate); } catch { } } }

        protected override void Dispose(bool disposing)
        {
            if (disposing) ThemeHelper.ThemeChanged -= OnThemeChanged;
            base.Dispose(disposing);
        }

        private static int ButtonW => DrawHelper.Px(46);

        private int ButtonsWidth => ButtonW * ((_showClose ? 1 : 0) + (_showMax ? 1 : 0) + (_showMin ? 1 : 0));

        // Glyph buttons are laid out right-to-left: close, maximize, minimize.
        private Rectangle GlyphRect(Glyph g)
        {
            int x = Width, w = ButtonW;
            if (_showClose) { x -= w; if (g == Glyph.Close) return new Rectangle(x, 0, w, Height); }
            if (_showMax) { x -= w; if (g == Glyph.Maximize) return new Rectangle(x, 0, w, Height); }
            if (_showMin) { x -= w; if (g == Glyph.Minimize) return new Rectangle(x, 0, w, Height); }
            return Rectangle.Empty;
        }

        private Glyph HitGlyph(Point p)
        {
            if (GlyphRect(Glyph.Close).Contains(p)) return Glyph.Close;
            if (GlyphRect(Glyph.Maximize).Contains(p)) return Glyph.Maximize;
            if (GlyphRect(Glyph.Minimize).Contains(p)) return Glyph.Minimize;
            return Glyph.None;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            if (_restorePending && (e.Button & MouseButtons.Left) != 0)
            {
                var d = SystemInformation.DragSize;
                if (Math.Abs(Cursor.Position.X - _restoreStart.X) > d.Width / 2 || Math.Abs(Cursor.Position.Y - _restoreStart.Y) > d.Height / 2)
                {
                    _restorePending = false;
                    DragRestore(e.Location);
                }
                return;
            }
            var h = HitGlyph(e.Location);
            if (h != _hover) { _hover = h; Cursor = h != Glyph.None ? Cursors.Hand : Cursors.Default; Invalidate(); }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            if (_hover != Glyph.None || _pressed != Glyph.None) { _hover = Glyph.None; _pressed = Glyph.None; Cursor = Cursors.Default; Invalidate(); }
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (e.Button != MouseButtons.Left) return;
            var g = HitGlyph(e.Location);
            if (g != Glyph.None) { _pressed = g; Invalidate(); return; }
            if (e.Clicks >= 2) { _restorePending = false; ToggleMaximize(); return; }
            var f = FindForm();
            if (f != null && f.WindowState == FormWindowState.Maximized)
            {
                // Don't restore on the press itself (it may be the first click of a double-click) — wait for a drag.
                _restorePending = true;
                _restoreStart = Cursor.Position;
                return;
            }
            BeginDrag();
        }

        protected override void OnMouseUp(MouseEventArgs e)
        {
            base.OnMouseUp(e);
            _restorePending = false;
            var pressed = _pressed;
            _pressed = Glyph.None;
            Invalidate();
            if (pressed != Glyph.None && e.Button == MouseButtons.Left && HitGlyph(e.Location) == pressed) Activate(pressed);
        }

        private void Activate(Glyph g)
        {
            var f = FindForm();
            if (f == null) return;
            switch (g)
            {
                case Glyph.Minimize: f.WindowState = FormWindowState.Minimized; break;
                case Glyph.Maximize: ToggleMaximize(); break;
                case Glyph.Close: f.Close(); break; // a modal dialog's Close() → DialogResult.Cancel; MainForm's → hide to tray
            }
        }

        private void ToggleMaximize()
        {
            if (!_showMax) return;
            var f = FindForm();
            if (f == null) return;
            f.WindowState = f.WindowState == FormWindowState.Maximized ? FormWindowState.Normal : FormWindowState.Maximized;
        }

        // Hand the press to the window manager as a caption press → native move loop (works with touch-promoted mouse).
        private void BeginDrag()
        {
            var f = FindForm();
            if (f == null || f.WindowState == FormWindowState.Maximized) return;
            try { ReleaseCapture(); SendMessage(f.Handle, WM_NCLBUTTONDOWN, (IntPtr)HTCAPTION, IntPtr.Zero); } catch { }
        }

        // Drag-to-restore (what a native caption does): restore, keep the grab point at the same fraction of the bar
        // under the cursor, then continue as a normal caption move.
        private void DragRestore(Point grab)
        {
            var f = FindForm();
            if (f == null || f.WindowState != FormWindowState.Maximized) return;
            float frac = Width > 0 ? Math.Max(0f, Math.Min(1f, grab.X / (float)Width)) : 0.5f;
            f.WindowState = FormWindowState.Normal;
            var c = Cursor.Position;
            f.Location = new Point(c.X - (int)(f.Width * frac), c.Y - Math.Min(grab.Y, Height / 2));
            BeginDrag();
        }

        protected override void WndProc(ref Message m)
        {
            // Let the form's resize border reach over the bar's outer edges (hit-testing falls through to the parent).
            if (m.Msg == WM_NCHITTEST && _resizeEdge > 0)
            {
                int lp = unchecked((int)(long)m.LParam);
                var p = PointToClient(new Point((short)(lp & 0xFFFF), (short)((lp >> 16) & 0xFFFF)));
                if (p.Y < _resizeEdge || p.X < _resizeEdge || p.X >= Width - _resizeEdge)
                {
                    m.Result = (IntPtr)HTTRANSPARENT;
                    return;
                }
            }
            base.WndProc(ref m);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            var pal = ThemeHelper.Palette();
            Color accent = pal.Accent, on = pal.OnAccent;
            g.Clear(accent);

            int left = DrawHelper.Px(12);
            var tr = new Rectangle(left, 0, Math.Max(1, Width - ButtonsWidth - left - DrawHelper.Px(6)), Height);
            TextRenderer.DrawText(g, _title, TitleFont, tr, on,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine
                | TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);

            g.SmoothingMode = SmoothingMode.AntiAlias;
            foreach (var gl in new[] { Glyph.Minimize, Glyph.Maximize, Glyph.Close })
            {
                var r = GlyphRect(gl);
                if (r.IsEmpty) continue;
                if (_pressed == gl || (_hover == gl && _pressed == Glyph.None))
                    using (var b = new SolidBrush(DrawHelper.Blend(accent, on, _pressed == gl ? 0.28f : 0.18f)))
                        g.FillRectangle(b, r);
                DrawGlyph(g, gl, r, on);
            }
        }

        private void DrawGlyph(Graphics g, Glyph gl, Rectangle r, Color color)
        {
            int cx = r.X + r.Width / 2, cy = r.Y + r.Height / 2, s = DrawHelper.Px(5);
            using (var pen = new Pen(color, Math.Max(1.2f, 1.2f * DrawHelper.DpiScale)) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            {
                switch (gl)
                {
                    case Glyph.Close:
                        g.DrawLine(pen, cx - s, cy - s, cx + s, cy + s);
                        g.DrawLine(pen, cx + s, cy - s, cx - s, cy + s);
                        break;
                    case Glyph.Minimize:
                        g.DrawLine(pen, cx - s, cy, cx + s, cy);
                        break;
                    case Glyph.Maximize:
                        var f = FindForm();
                        if (f != null && f.WindowState == FormWindowState.Maximized)
                        {
                            int o = DrawHelper.Px(2); // restore: two offset squares
                            g.DrawRectangle(pen, cx - s, cy - s + o, 2 * s - o, 2 * s - o);
                            g.DrawLine(pen, cx - s + o, cy - s, cx + s, cy - s);
                            g.DrawLine(pen, cx + s, cy - s, cx + s, cy + s - o);
                        }
                        else g.DrawRectangle(pen, cx - s, cy - s, 2 * s, 2 * s);
                        break;
                }
            }
        }
    }
}

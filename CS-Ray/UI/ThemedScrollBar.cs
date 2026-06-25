using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>
    /// Slim, owner-painted vertical scrollbar (rendering + mouse logic ported from TelegArm's ThemedScrollBar)
    /// that gives a <see cref="ListBox"/> or a multiline <see cref="TextBox"/> a themed scrollbar identical on
    /// every Windows version — including Windows RT 8.1, whose OS scrollbar can't be dark-themed (stays white).
    /// It hides the control's native vertical scrollbar (ShowScrollBar) and drives the control's own scroll
    /// (TopIndex for a ListBox, EM_LINESCROLL for a TextBox).
    ///
    /// Attach: host the target <see cref="DockStyle.Fill"/> in a panel and add this docked
    /// <see cref="DockStyle.Right"/> (add the target first so it docks last and fills the leftover width).
    /// </summary>
    public sealed class ThemedScrollBar : Control
    {
        [DllImport("user32.dll")] private static extern bool ShowScrollBar(IntPtr hWnd, int wBar, bool bShow);
        [DllImport("user32.dll", CharSet = CharSet.Auto)] private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

        private const int SB_VERT = 1;
        private const int WM_VSCROLL = 0x0115, WM_MOUSEWHEEL = 0x020A, WM_KEYDOWN = 0x0100, WM_KEYUP = 0x0101, WM_LBUTTONUP = 0x0202, WM_SIZE = 0x0005;
        private const int EM_GETLINECOUNT = 0x00BA, EM_GETFIRSTVISIBLELINE = 0x00CE, EM_LINESCROLL = 0x00B6;
        private const int Thickness = 11;

        private readonly Control _target;
        private readonly bool _isList;
        private readonly TargetHook _hook;

        public bool IsDark { get; set; }
        public Color AccentColor { get; set; }

        private bool _dragging;
        private int _dragStart, _dragStartValue;
        private bool _hoverThumb;

        public ThemedScrollBar(Control target, bool dark, Color accent)
        {
            _target = target;
            _isList = target is ListBox;
            IsDark = dark; AccentColor = accent;
            Width = Thickness;
            TabStop = false;
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
                   | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);

            _hook = new TargetHook(this);
            if (target.IsHandleCreated) _hook.AssignHandle(target.Handle);
            target.HandleCreated += (s, e) => { try { _hook.AssignHandle(target.Handle); } catch { } HideNative(); Invalidate(); };
            target.HandleDestroyed += (s, e) => { try { _hook.ReleaseHandle(); } catch { } };
            target.SizeChanged += (s, e) => { HideNative(); Invalidate(); };
            if (target is TextBox tb) tb.TextChanged += (s, e) => { HideNative(); Invalidate(); };
        }

        /// <summary>Re-hide the native bar + repaint (call after programmatic content changes, e.g. list refill).</summary>
        internal void NotifyTargetChanged() { HideNative(); Invalidate(); }

        private void HideNative()
        {
            try { if (_target.IsHandleCreated) ShowScrollBar(_target.Handle, SB_VERT, false); } catch { }
        }

        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); HideNative(); }

        private int LineHeight()
        {
            int h = TextRenderer.MeasureText("Ag", _target.Font).Height;
            return h > 0 ? h : 13;
        }

        // total/view/value in the target's natural scroll units (items for a ListBox, lines for a TextBox).
        private void Metrics(out int total, out int view, out int value, out int maxVal)
        {
            if (_isList)
            {
                var lb = (ListBox)_target;
                int ih = lb.ItemHeight > 0 ? lb.ItemHeight : LineHeight();
                total = lb.Items.Count;
                view = Math.Max(1, lb.ClientSize.Height / ih);
                value = lb.TopIndex;
            }
            else
            {
                total = (int)SendMessage(_target.Handle, EM_GETLINECOUNT, IntPtr.Zero, IntPtr.Zero);
                view = Math.Max(1, _target.ClientSize.Height / LineHeight());
                value = (int)SendMessage(_target.Handle, EM_GETFIRSTVISIBLELINE, IntPtr.Zero, IntPtr.Zero);
            }
            if (total < 0) total = 0;
            maxVal = Math.Max(1, total - view);
            if (value < 0) value = 0; else if (value > maxVal) value = maxVal;
        }

        private bool Active { get { Metrics(out int t, out int v, out _, out _); return t > v && v > 0; } }

        private Rectangle ThumbRect()
        {
            Metrics(out int total, out int view, out int value, out int maxVal);
            if (total <= view || view <= 0) return Rectangle.Empty;
            int len = Height;
            int thumb = Math.Max(28, (int)((long)len * view / total));
            if (thumb >= len) return Rectangle.Empty;
            int off = (int)((long)(len - thumb) * value / maxVal);
            return new Rectangle(2, off, Width - 4, thumb);
        }

        private void ScrollTo(int value)
        {
            Metrics(out _, out _, out int cur, out int maxVal);
            if (value < 0) value = 0; else if (value > maxVal) value = maxVal;
            if (_isList) { try { ((ListBox)_target).TopIndex = value; } catch { } }
            else SendMessage(_target.Handle, EM_LINESCROLL, IntPtr.Zero, (IntPtr)(value - cur));
            HideNative();
            Invalidate();
        }

        private int _pxAccum; // carries sub-unit drag pixels so small finger pans aren't lost

        /// <summary>Touch drag-to-scroll: pan by a finger Δy in PIXELS (finger down = +). Converts to the
        /// target's scroll units (items / lines), accumulating the remainder so slow drags still move.</summary>
        public void ScrollByPixels(int fingerDeltaY)
        {
            int unit = _isList ? Math.Max(1, ((ListBox)_target).ItemHeight) : Math.Max(1, LineHeight());
            _pxAccum += fingerDeltaY;
            int units = _pxAccum / unit;
            if (units == 0) return;
            _pxAccum -= units * unit;
            Metrics(out _, out _, out int value, out _);
            ScrollTo(value - units); // finger down (+) → scroll toward the top
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (!Active) return;
            var t = ThumbRect();
            Metrics(out _, out int view, out int value, out _);
            if (t.Contains(e.Location)) { _dragging = true; _dragStart = e.Y; _dragStartValue = value; Capture = true; }
            else ScrollTo(value + (e.Y < t.Y ? -view : view)); // page on track click
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            if (_dragging)
            {
                var t = ThumbRect();
                Metrics(out _, out _, out _, out int maxVal);
                int denom = Math.Max(1, Height - t.Height);
                int dv = (int)((long)(e.Y - _dragStart) * maxVal / denom);
                ScrollTo(_dragStartValue + dv);
            }
            else { bool h = ThumbRect().Contains(e.Location); if (h != _hoverThumb) { _hoverThumb = h; Invalidate(); } }
        }

        protected override void OnMouseUp(MouseEventArgs e) { base.OnMouseUp(e); _dragging = false; Capture = false; }
        protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); if (_hoverThumb) { _hoverThumb = false; Invalidate(); } }

        protected override void OnMouseWheel(MouseEventArgs e)
        {
            Metrics(out _, out int view, out int value, out _);
            ScrollTo(value - Math.Sign(e.Delta) * Math.Max(1, view / 2));
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            HideNative(); // re-assert hidden in case the target re-showed its native bar (e.g. ListBox after refill)
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(IsDark ? Color.FromArgb(30, 30, 30) : Color.FromArgb(245, 245, 245));
            if (!Active) return;
            var t = ThumbRect();
            if (t == Rectangle.Empty) return;
            Color thumb = _dragging || _hoverThumb
                ? (IsDark ? Lighten(AccentColor) : AccentColor)
                : (IsDark ? Color.FromArgb(95, 95, 100) : Color.FromArgb(190, 190, 196));
            int radius = (Thickness - 4) / 2;
            using (var b = new SolidBrush(thumb))
            using (var path = RoundedRect(t, radius))
                g.FillPath(b, path);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) { try { _hook.ReleaseHandle(); } catch { } }
            base.Dispose(disposing);
        }

        private static Color Lighten(Color c)
            => Color.FromArgb(Math.Min(255, c.R + 40), Math.Min(255, c.G + 40), Math.Min(255, c.B + 40));

        private static GraphicsPath RoundedRect(Rectangle r, int radius)
        {
            var path = new GraphicsPath();
            int d = radius * 2;
            if (d <= 0 || d > r.Width || d > r.Height) { path.AddRectangle(r); path.CloseFigure(); return path; }
            path.AddArc(r.X, r.Y, d, d, 180, 90);
            path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }

        // Subclasses the target so user-driven scrolls (wheel / keys / native vscroll / resize) repaint the
        // themed bar — and so a wheel over a no-native-bar TextBox still scrolls it.
        private sealed class TargetHook : NativeWindow
        {
            private readonly ThemedScrollBar _bar;
            public TargetHook(ThemedScrollBar bar) { _bar = bar; }

            protected override void WndProc(ref Message m)
            {
                if (m.Msg == WM_MOUSEWHEEL && !_bar._isList)
                {
                    int delta = (short)((m.WParam.ToInt64() >> 16) & 0xFFFF);
                    SendMessage(_bar._target.Handle, EM_LINESCROLL, IntPtr.Zero, (IntPtr)(-Math.Sign(delta) * 3));
                    _bar.NotifyTargetChanged();
                    return; // a ScrollBars=None TextBox won't wheel-scroll on its own
                }
                base.WndProc(ref m);
                switch (m.Msg)
                {
                    case WM_VSCROLL:
                    case WM_MOUSEWHEEL:
                    case WM_KEYDOWN:
                    case WM_KEYUP:
                    case WM_LBUTTONUP:
                    case WM_SIZE:
                        _bar.NotifyTargetChanged();
                        break;
                }
            }
        }
    }
}

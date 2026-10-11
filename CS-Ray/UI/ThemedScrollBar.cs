using System;
using System.Collections.Generic;
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
        [DllImport("user32.dll")] private static extern IntPtr WindowFromPoint(POINT p);
        [DllImport("user32.dll")] private static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);
        [DllImport("user32.dll")] private static extern bool IsWindowEnabled(IntPtr hwnd);
        private const uint GA_ROOT = 2;
        [StructLayout(LayoutKind.Sequential)] private struct POINT { public int X, Y; }

        private const int SB_VERT = 1;
        private const int WM_VSCROLL = 0x0115, WM_MOUSEWHEEL = 0x020A, WM_KEYDOWN = 0x0100, WM_KEYUP = 0x0101, WM_LBUTTONUP = 0x0202, WM_SIZE = 0x0005;
        private const int EM_GETLINECOUNT = 0x00BA, EM_GETFIRSTVISIBLELINE = 0x00CE, EM_LINESCROLL = 0x00B6;
        private static int Thickness => DrawHelper.Px(11);   // 11 design px at the system DPI

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
            WheelRouter.Register(this);
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
            int thumb = Math.Max(DrawHelper.Px(28), (int)((long)len * view / total));
            if (thumb >= len) return Rectangle.Empty;
            int off = (int)((long)(len - thumb) * value / maxVal);
            int inset = Math.Max(2, Width / 5);
            return new Rectangle(inset, off, Width - 2 * inset, thumb);
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

        protected override void OnMouseWheel(MouseEventArgs e) => WheelScroll(e.Delta);

        private int _wheelAccum; // carries partial notches (precision touchpads send deltas < 120)

        /// <summary>Scroll the target by a WM_MOUSEWHEEL delta: the system "lines per notch" (3 by default) rows for a
        /// ListBox / lines for a TextBox, or a page in "one screen at a time" mode. The native ListBox can't do this
        /// itself — hiding its scrollbar (ShowScrollBar) removes WS_VSCROLL and it then ignores the wheel.</summary>
        internal void WheelScroll(int delta)
        {
            if (!_target.IsHandleCreated) return;
            _wheelAccum += delta;
            int notches = _wheelAccum / 120;
            if (notches == 0) return;
            _wheelAccum -= notches * 120;
            Metrics(out _, out int view, out int value, out _);
            int per = SystemInformation.MouseWheelScrollLines;
            int units = per < 0 ? Math.Max(1, view) : Math.Max(1, per);   // -1 = one screen per notch
            ScrollTo(value - notches * units);
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
            int radius = Math.Max(1, t.Width / 2);
            using (var b = new SolidBrush(thumb))
            using (var path = RoundedRect(t, radius))
                g.FillPath(b, path);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) { WheelRouter.Unregister(this); try { _hook.ReleaseHandle(); } catch { } }
            base.Dispose(disposing);
        }

        // ── Wheel routing by cursor position ──
        // Windows 8.1 / RT deliver WM_MOUSEWHEEL to the FOCUSED control, not the one under the pointer (10/11 do the
        // latter by default) — so hovering the server list while a button has focus wouldn't scroll it. One app-wide
        // pre-dispatch filter sends the wheel to whichever themed list / log is TOP-MOST under the message's point (a
        // list merely under a dialog never steals it — same top-level form check as ThemedScrollPanel).
        private static class WheelRouter
        {
            private static readonly List<ThemedScrollBar> Bars = new List<ThemedScrollBar>();
            private static Filter _filter;

            public static void Register(ThemedScrollBar b)
            {
                lock (Bars)
                {
                    Bars.Add(b);
                    if (_filter == null) { _filter = new Filter(); Application.AddMessageFilter(_filter); }
                }
            }

            public static void Unregister(ThemedScrollBar b)
            {
                lock (Bars)
                {
                    Bars.Remove(b);
                    if (Bars.Count == 0 && _filter != null) { try { Application.RemoveMessageFilter(_filter); } catch { } _filter = null; }
                }
            }

            private sealed class Filter : IMessageFilter
            {
                public bool PreFilterMessage(ref Message m)
                {
                    if (m.Msg != WM_MOUSEWHEEL) return false;
                    try
                    {
                        long lp = m.LParam.ToInt64();
                        POINT pt; pt.X = (short)(lp & 0xFFFF); pt.Y = (short)((lp >> 16) & 0xFFFF);
                        IntPtr hwnd = WindowFromPoint(pt);
                        if (hwnd == IntPtr.Zero) return false;
                        ThemedScrollBar hit = null;
                        lock (Bars)
                            foreach (var b in Bars)
                                if (!b.IsDisposed && b._target.IsHandleCreated && b._target.Visible
                                    && (hwnd == b._target.Handle || (b.IsHandleCreated && hwnd == b.Handle)))
                                { hit = b; break; }
                        if (hit == null) return false;
                        // A modal dialog disables its owner: don't scroll a list sitting behind it (Windows wouldn't).
                        IntPtr root = GetAncestor(hwnd, GA_ROOT);
                        if (root != IntPtr.Zero && !IsWindowEnabled(root)) return false;
                        int delta = (short)((m.WParam.ToInt64() >> 16) & 0xFFFF);
                        hit.WheelScroll(delta);
                        hit.NotifyTargetChanged();
                        return true;   // consumed — never also delivered to the focused control
                    }
                    catch { return false; }
                }
            }
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
                // Fallback for wheel messages that bypass the router (e.g. sent, not posted): neither a ScrollBars=None
                // TextBox nor a ListBox without WS_VSCROLL wheel-scrolls on its own.
                if (m.Msg == WM_MOUSEWHEEL)
                {
                    int delta = (short)((m.WParam.ToInt64() >> 16) & 0xFFFF);
                    _bar.WheelScroll(delta);
                    _bar.NotifyTargetChanged();
                    m.Result = IntPtr.Zero;
                    return;
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

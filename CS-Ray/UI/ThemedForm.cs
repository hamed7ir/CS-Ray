using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>
    /// Base for the main window: a borderless form with the accent <see cref="ThemedTitleBar"/> (title + minimize /
    /// maximize / close), a 1px edge line, and a resize border — replacing MaterialForm. Layout contract: the bar is
    /// pinned across the top (not docked) and <see cref="Control.Padding"/> reserves it, so a subclass just adds its
    /// own Dock=Fill content and it lands below the bar, inset by the thin resize strip. The strip is the form's own
    /// client area, so WM_NCHITTEST there returns the resize edges; the bar passes its outer edges through
    /// (<see cref="ThemedTitleBar.ResizeEdge"/>). Maximize is clamped to the monitor's WORK AREA (a borderless window
    /// would otherwise cover the taskbar). System-DPI + AutoScaleMode.Font; colors follow ThemeHelper live.
    /// </summary>
    public class ThemedForm : Form
    {
        private const int WM_NCHITTEST = 0x0084, WM_GETMINMAXINFO = 0x0024;
        private const int HTCLIENT = 1, HTLEFT = 10, HTRIGHT = 11, HTTOP = 12, HTTOPLEFT = 13, HTTOPRIGHT = 14,
                          HTBOTTOM = 15, HTBOTTOMLEFT = 16, HTBOTTOMRIGHT = 17;
        private const int WS_MAXIMIZEBOX = 0x00010000, WS_MINIMIZEBOX = 0x00020000, WS_SYSMENU = 0x00080000;

        [StructLayout(LayoutKind.Sequential)] private struct POINT { public int x, y; }
        [StructLayout(LayoutKind.Sequential)]
        private struct MINMAXINFO { public POINT ptReserved, ptMaxSize, ptMaxPosition, ptMinTrackSize, ptMaxTrackSize; }

        private readonly int _grip = DrawHelper.Px(5);   // resize strip width around the content
        private bool _resizable = true;

        /// <summary>The accent title bar (its title mirrors <see cref="Form.Text"/>).</summary>
        protected readonly ThemedTitleBar TitleBar;

        /// <summary>Whether the edges resize the window (default true). Maximize follows <see cref="Form.MaximizeBox"/>.</summary>
        public bool Resizable { get { return _resizable; } set { _resizable = value; UpdateChromeLayout(); } }

        public ThemedForm()
        {
            FormBorderStyle = FormBorderStyle.None;
            AutoScaleMode = AutoScaleMode.Font;
            DoubleBuffered = true;
            SetStyle(ControlStyles.ResizeRedraw, true);
            ThemedChrome.SetAppIcon(this);

            TitleBar = new ThemedTitleBar { ShowMinimize = true, ShowMaximize = true, ShowClose = true, Title = Text };
            Controls.Add(TitleBar);

            ApplyChromeTheme();
            ThemeHelper.ThemeChanged += OnChromeThemeChanged;
            UpdateChromeLayout();
        }

        // Taskbar click minimizes/restores and the taskbar menu works only with these styles; a borderless (no
        // WS_CAPTION / WS_THICKFRAME) window still draws no native frame with them.
        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                cp.Style |= WS_SYSMENU;
                if (MinimizeBox) cp.Style |= WS_MINIMIZEBOX;
                if (MaximizeBox) cp.Style |= WS_MAXIMIZEBOX;
                return cp;
            }
        }

        private void OnChromeThemeChanged()
        {
            if (IsDisposed || !IsHandleCreated) return;
            try { BeginInvoke((Action)ApplyChromeTheme); } catch { }
        }

        private void ApplyChromeTheme()
        {
            if (IsDisposed) return;
            BackColor = ThemeHelper.Palette().Surface; // the resize strip blends with the content
            TitleBar.Invalidate();
            Invalidate();
        }

        private void UpdateChromeLayout()
        {
            if (TitleBar == null || WindowState == FormWindowState.Minimized) return;
            bool max = WindowState == FormWindowState.Maximized;
            int edge = max ? 0 : _resizable ? _grip : 1;
            int bar = TitleBar.Height;
            Padding = new Padding(edge, bar, edge, edge);
            TitleBar.SetBounds(0, 0, ClientSize.Width, bar);
            TitleBar.ResizeEdge = !max && _resizable ? _grip : 0;
            TitleBar.ShowMinimize = MinimizeBox;
            TitleBar.ShowMaximize = MaximizeBox;
            TitleBar.Invalidate();
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            UpdateChromeLayout();
        }

        // Re-resolve here too: the base ctor ran before the subclass applied the persisted theme mode
        // (ThemeHelper.InitMode raises nothing), and the handle is created after that, before the first paint.
        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            ApplyChromeTheme();
            UpdateChromeLayout();
        }

        protected override void OnTextChanged(EventArgs e)
        {
            base.OnTextChanged(e);
            if (TitleBar != null) TitleBar.Title = Text;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            if (WindowState == FormWindowState.Maximized) return;
            using (var pen = new Pen(ThemeHelper.Palette().Border))
                e.Graphics.DrawRectangle(pen, 0, 0, ClientSize.Width - 1, ClientSize.Height - 1);
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == WM_NCHITTEST)
            {
                base.WndProc(ref m);
                if ((int)m.Result == HTCLIENT && _resizable && WindowState == FormWindowState.Normal)
                {
                    int lp = unchecked((int)(long)m.LParam);
                    int ht = EdgeHit(PointToClient(new Point((short)(lp & 0xFFFF), (short)((lp >> 16) & 0xFFFF))));
                    if (ht != 0) m.Result = (IntPtr)ht;
                }
                return;
            }
            if (m.Msg == WM_GETMINMAXINFO)
            {
                base.WndProc(ref m);   // keeps MinimumSize → ptMinTrackSize
                FitMaximizeToWorkArea(m.LParam);
                return;
            }
            base.WndProc(ref m);
        }

        private int EdgeHit(Point p)
        {
            int g = _grip;
            bool l = p.X < g, r = p.X >= ClientSize.Width - g, t = p.Y < g, b = p.Y >= ClientSize.Height - g;
            if (t && l) return HTTOPLEFT;
            if (t && r) return HTTOPRIGHT;
            if (b && l) return HTBOTTOMLEFT;
            if (b && r) return HTBOTTOMRIGHT;
            if (l) return HTLEFT;
            if (r) return HTRIGHT;
            if (t) return HTTOP;
            if (b) return HTBOTTOM;
            return 0;
        }

        // Max position is relative to the window's monitor origin; size = that monitor's work area (taskbar stays visible).
        private void FitMaximizeToWorkArea(IntPtr lParam)
        {
            try
            {
                var scr = Screen.FromHandle(Handle);
                Rectangle wa = scr.WorkingArea, mon = scr.Bounds;
                var mmi = (MINMAXINFO)Marshal.PtrToStructure(lParam, typeof(MINMAXINFO));
                mmi.ptMaxPosition.x = wa.Left - mon.Left;
                mmi.ptMaxPosition.y = wa.Top - mon.Top;
                mmi.ptMaxSize.x = wa.Width;
                mmi.ptMaxSize.y = wa.Height;
                Marshal.StructureToPtr(mmi, lParam, false);
            }
            catch { /* keep the system default */ }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) ThemeHelper.ThemeChanged -= OnChromeThemeChanged;
            base.Dispose(disposing);
        }
    }
}

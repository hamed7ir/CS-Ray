using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>
    /// A vertically scrollable container with an OWNER-DRAWN scrollbar (ported from DroidFinestra's
    /// UI/Controls/ThemedScrollPanel.cs; thumb colors match CS-Ray's <see cref="ThemedScrollBar"/>). RT 8.1's native
    /// scrollbars can't be dark-themed, so this paints its own and looks identical on every target. Add children to
    /// <see cref="Host"/> at absolute positions; the content height follows the lowest child automatically, or is set
    /// explicitly with <see cref="SetContentHeight"/> (needed when hidden children keep stale positions).
    ///
    /// Wheel over ANY child scrolls it (an app-wide message filter routes the wheel here when the cursor is over this
    /// panel AND the top-most window under the cursor belongs to the same form — so a panel merely UNDER a stacked
    /// dialog never steals it). A press-and-drag over the content also pans, which is what makes it usable by finger
    /// on a touchscreen (Windows promotes single-finger touch to mouse messages); a small threshold keeps taps as
    /// clicks, and over a text field only a clearly vertical drag pans (a mouse drag-select is preserved).
    /// </summary>
    public sealed class ThemedScrollPanel : Panel, IMessageFilter
    {
        [DllImport("user32.dll")] private static extern IntPtr WindowFromPoint(POINT p);
        [DllImport("user32.dll")] private static extern bool ReleaseCapture();
        [StructLayout(LayoutKind.Sequential)] private struct POINT { public int X, Y; }

        private readonly int _gutter = DrawHelper.Px(11);     // right-edge scrollbar lane
        private readonly int _thumbW = DrawHelper.Px(7);
        private readonly int _minThumb = DrawHelper.Px(28);
        private readonly int _wheelStep = DrawHelper.Px(54);
        private readonly int _dragThreshold = DrawHelper.Px(12); // movement before a content press becomes a pan

        private readonly Panel _view;       // the scrolled content surface; callers add to Host
        private int _scroll;                // current offset [0.._max]
        private int _max;                   // scrollable range (contentHeight - viewport), >= 0
        private bool _explicitHeight;       // SetContentHeight was used → don't auto-measure children
        private bool _thumbHover, _thumbDrag;
        private int _dragGrabDy;
        private bool _filtering;

        private bool _contentDragCandidate, _contentDragConfirmed, _contentDragOverTextBox;
        private int _contentDragStartX, _contentDragStartY, _contentDragStartScroll;

        /// <summary>The content surface — add child controls here.</summary>
        public Panel Host => _view;

        /// <summary>Width of the scrollbar lane on the right (always reserved, so content never reflows).</summary>
        public int GutterWidth => _gutter;

        public ThemedScrollPanel()
        {
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            _view = new Panel { Location = new Point(0, 0), Height = 0 };
            _view.ControlAdded += (s, e) => { HookFocus(e.Control); if (!_explicitHeight) RelayoutContent(); };
            _view.ControlRemoved += (s, e) => { if (!_explicitHeight) RelayoutContent(); };
            Controls.Add(_view);
            ApplyColors();
            ThemeHelper.ThemeChanged += OnThemeChanged;
        }

        private void OnThemeChanged()
        {
            if (IsDisposed || !IsHandleCreated) return;
            try { BeginInvoke((Action)(() => { ApplyColors(); Invalidate(); _view.Invalidate(true); })); } catch { }
        }

        private void ApplyColors()
        {
            Color bg = ThemeHelper.Palette().Surface;
            BackColor = bg;
            _view.BackColor = bg;
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            ApplyColors();
            if (!_filtering) { Application.AddMessageFilter(this); _filtering = true; }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                ThemeHelper.ThemeChanged -= OnThemeChanged;
                if (_filtering) { Application.RemoveMessageFilter(this); _filtering = false; }
            }
            base.Dispose(disposing);
        }

        /// <summary>Measures the content height from the lowest child and refreshes the scrollbar.</summary>
        public void RelayoutContent()
        {
            int contentH = 0;
            foreach (Control c in _view.Controls) contentH = Math.Max(contentH, c.Bottom);
            _view.Height = contentH;
            LayoutView();
        }

        /// <summary>Sets the content height explicitly (stops auto-measuring) and refreshes the scrollbar.</summary>
        public void SetContentHeight(int height)
        {
            _explicitHeight = true;
            _view.Height = Math.Max(0, height);
            LayoutView();
        }

        protected override void OnSizeChanged(EventArgs e)
        {
            base.OnSizeChanged(e);
            LayoutView();
        }

        private void LayoutView()
        {
            if (_view == null) return;   // early layout during construction
            int viewport = ClientSize.Height;
            _view.Width = Math.Max(0, ClientSize.Width - _gutter);
            _max = Math.Max(0, _view.Height - viewport);
            if (_scroll > _max) _scroll = _max;
            if (_scroll < 0) _scroll = 0;
            _view.Top = -_scroll;
            Invalidate();
        }

        private void ScrollTo(int value)
        {
            int v = Math.Max(0, Math.Min(_max, value));
            if (v == _scroll) return;
            _scroll = v;
            _view.Top = -_scroll;
            Invalidate();
        }

        /// <summary>Scrolls the minimum needed so content rows [y, y+h] are visible (keyboard focus moves).</summary>
        public void EnsureVisible(int y, int h)
        {
            int viewport = ClientSize.Height;
            if (y < _scroll) ScrollTo(y);
            else if (y + h > _scroll + viewport) ScrollTo(y + h - viewport);
        }

        // Keyboard focus landing on any descendant scrolls it into view — what an AutoScroll panel does natively.
        // Enter fires outer → inner, so the innermost focused control has the last word.
        private void HookFocus(Control c)
        {
            if (c == null) return;
            c.Enter += OnDescendantEnter;
            c.ControlAdded += (s, e) => HookFocus(e.Control);
            foreach (Control k in c.Controls) HookFocus(k);
        }

        private void OnDescendantEnter(object sender, EventArgs e)
        {
            var c = sender as Control;
            if (c == null || _max <= 0 || !c.IsHandleCreated || !_view.IsHandleCreated) return;
            var r = _view.RectangleToClient(c.RectangleToScreen(c.ClientRectangle)); // content coordinates
            EnsureVisible(r.Top, r.Height);
            if (_contentDragCandidate && !_contentDragConfirmed) _contentDragStartScroll = _scroll; // a press focused it: re-base the pan
        }

        // ── owner-drawn scrollbar ──
        private Rectangle TrackRect() => new Rectangle(ClientSize.Width - _gutter, 0, _gutter, ClientSize.Height);

        private Rectangle ThumbRect()
        {
            if (_max <= 0) return Rectangle.Empty;
            int viewport = ClientSize.Height;
            int thumbH = Math.Max(_minThumb, (int)((long)viewport * viewport / Math.Max(1, _view.Height)));
            thumbH = Math.Min(thumbH, viewport);
            int y = (int)((long)_scroll * (viewport - thumbH) / _max);
            int x = ClientSize.Width - _gutter + (_gutter - _thumbW) / 2;
            return new Rectangle(x, y, _thumbW, thumbH);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            if (_max <= 0) return;   // nothing to scroll → no scrollbar
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            var p = ThemeHelper.Palette();
            Color track = p.Dark ? Color.FromArgb(60, 60, 64) : Color.FromArgb(232, 232, 236);
            Color thumb = _thumbHover || _thumbDrag
                ? p.AccentText
                : (p.Dark ? Color.FromArgb(95, 95, 100) : Color.FromArgb(190, 190, 196));

            var tr = TrackRect();
            using (var tb = new SolidBrush(track))
            using (var tp = DrawHelper.RoundedRect(new Rectangle(tr.X + (_gutter - _thumbW) / 2, 2, _thumbW, Math.Max(1, tr.Height - 4)), _thumbW / 2))
                g.FillPath(tb, tp);

            var th = ThumbRect();
            if (th != Rectangle.Empty)
                using (var b = new SolidBrush(thumb))
                using (var path = DrawHelper.RoundedRect(th, _thumbW / 2))
                    g.FillPath(b, path);
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (_max <= 0) return;
            var th = ThumbRect();
            if (th.Contains(e.Location)) { _thumbDrag = true; _dragGrabDy = e.Y - th.Y; Capture = true; }
            else if (TrackRect().Contains(e.Location))
                ScrollTo(_scroll + (e.Y < th.Y ? -ClientSize.Height : ClientSize.Height));   // page
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            if (_thumbDrag)
            {
                int denom = Math.Max(1, ClientSize.Height - ThumbRect().Height);
                ScrollTo((int)((long)(e.Y - _dragGrabDy) * _max / denom));
                return;
            }
            bool hover = _max > 0 && ThumbRect().Contains(e.Location);
            if (hover != _thumbHover) { _thumbHover = hover; Invalidate(); }
        }

        protected override void OnMouseUp(MouseEventArgs e)
        {
            base.OnMouseUp(e);
            if (_thumbDrag) { _thumbDrag = false; Capture = false; Invalidate(); }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            if (_thumbHover) { _thumbHover = false; Invalidate(); }
        }

        public bool PreFilterMessage(ref Message m)
        {
            const int WM_MOUSEWHEEL = 0x020A, WM_LBUTTONDOWN = 0x0201, WM_MOUSEMOVE = 0x0200, WM_LBUTTONUP = 0x0202;
            const int MK_LBUTTON = 0x0001;

            if (!IsHandleCreated || !Visible) return false;

            if (m.Msg == WM_MOUSEWHEEL)
            {
                if (_max <= 0) return false;                      // nothing to scroll → let another panel try
                try
                {
                    if (!CursorOverThisPanel()) return false;
                    int delta = (short)((long)m.WParam >> 16);
                    // Proportional (not whole notches): precision touchpads / free-spin wheels send deltas < 120.
                    int step = (int)((long)delta * _wheelStep / 120);
                    if (step == 0) step = Math.Sign(delta);
                    ScrollTo(_scroll - step);
                    // Consumed even at either end: an unhandled wheel would go to the FOCUS window (not the one
                    // under the cursor) — e.g. silently cycle a focused combo's value.
                    return true;
                }
                catch { return false; }
            }

            if (m.Msg == WM_LBUTTONDOWN)
            {
                _contentDragCandidate = false;
                _contentDragConfirmed = false;
                if (_max <= 0 || m.HWnd == Handle) return false;   // our own thumb/track click
                try
                {
                    if (!CursorOverThisPanel()) return false;
                    _contentDragOverTextBox = Control.FromChildHandle(m.HWnd) is TextBoxBase;
                    _contentDragCandidate = true;
                    _contentDragStartX = Cursor.Position.X;
                    _contentDragStartY = Cursor.Position.Y;
                    _contentDragStartScroll = _scroll;
                    return false;   // don't consume — a plain tap/click must still reach the control
                }
                catch { return false; }
            }

            if (m.Msg == WM_MOUSEMOVE)
            {
                if (!_contentDragCandidate) return false;
                if (((long)m.WParam & MK_LBUTTON) == 0) { _contentDragCandidate = false; _contentDragConfirmed = false; return false; }
                int dy = Cursor.Position.Y - _contentDragStartY;
                if (!_contentDragConfirmed)
                {
                    if (Math.Abs(dy) < _dragThreshold) return false;
                    if (_contentDragOverTextBox && Math.Abs(dy) <= Math.Abs(Cursor.Position.X - _contentDragStartX)) return false;
                    _contentDragConfirmed = true;
                    ReleaseCapture();               // free a field/button that grabbed the mouse on the press
                }
                ScrollTo(_contentDragStartScroll - dy);
                return true;
            }

            if (m.Msg == WM_LBUTTONUP)
            {
                bool wasConfirmed = _contentDragConfirmed;
                _contentDragCandidate = false;
                _contentDragConfirmed = false;
                return wasConfirmed;   // swallow the release only after a real pan, so a tap still clicks
            }

            return false;
        }

        // Over THIS panel's client area AND the top-most window under the cursor is on the same form (stacked dialogs).
        private bool CursorOverThisPanel()
        {
            Point sp = Cursor.Position;
            if (!RectangleToScreen(ClientRectangle).Contains(sp)) return false;
            Form myForm = FindForm();
            if (myForm == null) return true;
            POINT p; p.X = sp.X; p.Y = sp.Y;
            Control top = Control.FromChildHandle(WindowFromPoint(p));
            return top != null && top.FindForm() == myForm;
        }
    }
}

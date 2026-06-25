using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using MaterialSkin;

namespace CS_Ray.UI
{
    /// <summary>
    /// Flat, owner-painted group tab strip (HotCornersWin's ScaledTabSelector approach): selected tab uses the
    /// Material accent, inactive tabs are muted with grey text, a darker-accent indicator underlines the active
    /// tab; hover highlight; click selects. Bound to a (hidden) backing <see cref="TabControl"/> so all existing
    /// group logic keeps driving it. Tabs that exceed the strip width SCROLL horizontally (mouse wheel, touch
    /// swipe via <see cref="TouchScroller"/>, and the selected tab auto-scrolls into view); edge fades hint more.
    /// </summary>
    internal sealed class GroupTabStrip : Control
    {
        private TabControl _baseTabControl;
        private readonly List<Rectangle> _tabRects = new List<Rectangle>(); // CONTENT space (x from 0; offset by _scrollX)
        private readonly Font _font;
        private const int IndicatorH = 3;
        private const int TabPad = 14;
        private const int FadeW = 16;
        private int _hoverIndex = -1;
        private int _scrollX;        // horizontal scroll offset (content px scrolled off the left)
        private int _contentWidth;   // total width of all tabs

        public event EventHandler SelectedTabChanged;
        public event EventHandler<int> TabRightClicked;

        public GroupTabStrip(Font font)
        {
            _font = font;            // keep our own ref — Control.Font gets reassigned by MaterialSkin once parented
            Font = font;
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint
                   | ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.Selectable, true);
            DoubleBuffered = true;
            TabStop = false; // selectable (so wheel works once clicked) but not in the Tab order
        }

        public TabControl BaseTabControl
        {
            get => _baseTabControl;
            set
            {
                if (_baseTabControl != null)
                {
                    _baseTabControl.SelectedIndexChanged -= OnBaseChanged;
                    _baseTabControl.ControlAdded -= OnBaseChanged;
                    _baseTabControl.ControlRemoved -= OnBaseChanged;
                }
                _baseTabControl = value;
                if (_baseTabControl != null)
                {
                    _baseTabControl.SelectedIndexChanged += OnBaseChanged;
                    _baseTabControl.ControlAdded += OnBaseChanged;
                    _baseTabControl.ControlRemoved += OnBaseChanged;
                }
                UpdateTabRects();
                Invalidate();
            }
        }

        private static MaterialSkinManager Skin => MaterialSkinManager.Instance;

        private void OnBaseChanged(object sender, EventArgs e) { UpdateTabRects(); EnsureSelectedVisible(); Invalidate(); }
        protected override void OnFontChanged(EventArgs e) { base.OnFontChanged(e); UpdateTabRects(); Invalidate(); }
        protected override void OnSizeChanged(EventArgs e) { base.OnSizeChanged(e); UpdateTabRects(); Invalidate(); }

        private void UpdateTabRects()
        {
            _tabRects.Clear();
            _contentWidth = 0;
            if (_baseTabControl == null) return;
            int x = 0;
            foreach (TabPage page in _baseTabControl.TabPages)
            {
                int w = TextRenderer.MeasureText(page.Text, _font).Width + TabPad * 2;
                _tabRects.Add(new Rectangle(x, 0, w, Height));
                x += w;
            }
            _contentWidth = x;
            ClampScroll();
        }

        private int MaxScroll => Math.Max(0, _contentWidth - Width);
        private void ClampScroll() { if (_scrollX < 0) _scrollX = 0; else if (_scrollX > MaxScroll) _scrollX = MaxScroll; }

        // Point (control space) → tab index, accounting for the horizontal scroll offset.
        private int HitTest(Point pt)
        {
            var content = new Point(pt.X + _scrollX, pt.Y);
            for (int i = 0; i < _tabRects.Count; i++) if (_tabRects[i].Contains(content)) return i;
            return -1;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            bool dark = Skin.Theme == MaterialSkinManager.Themes.DARK;
            Color inactiveBack = dark ? Color.FromArgb(50, 50, 50) : Color.FromArgb(224, 224, 224);
            Color inactiveText = dark ? Color.FromArgb(185, 185, 185) : Color.FromArgb(90, 90, 90);
            Color activeBack = Skin.ColorScheme.PrimaryColor;
            Color activeText = Color.White;
            Color indicator = Skin.ColorScheme.DarkPrimaryColor;

            g.Clear(inactiveBack);
            if (_baseTabControl == null) return;
            if (_tabRects.Count != _baseTabControl.TabCount) UpdateTabRects();

            int selected = _baseTabControl.SelectedIndex;
            for (int i = 0; i < _tabRects.Count; i++)
            {
                var rect = _tabRects[i]; rect.X -= _scrollX; // content → control space
                if (rect.Right < 0 || rect.X > Width) continue; // off-screen
                bool sel = i == selected;
                Color back = sel ? activeBack : (i == _hoverIndex ? Shade(inactiveBack, dark ? 0.12f : -0.06f) : inactiveBack);
                using (var b = new SolidBrush(back)) g.FillRectangle(b, rect);
                TextRenderer.DrawText(g, _baseTabControl.TabPages[i].Text, _font, rect,
                    sel ? activeText : inactiveText,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix);
                if (sel) using (var b = new SolidBrush(indicator)) g.FillRectangle(b, rect.X, Height - IndicatorH, rect.Width, IndicatorH);
            }

            // Edge fades hint that there's more to scroll.
            if (_scrollX > 0) DrawFade(g, inactiveBack, true);
            if (_scrollX < MaxScroll) DrawFade(g, inactiveBack, false);
        }

        private void DrawFade(Graphics g, Color bg, bool left)
        {
            var rect = left ? new Rectangle(0, 0, FadeW, Height) : new Rectangle(Width - FadeW, 0, FadeW, Height);
            using (var br = new LinearGradientBrush(rect, left ? bg : Color.FromArgb(0, bg), left ? Color.FromArgb(0, bg) : bg, LinearGradientMode.Horizontal))
                g.FillRectangle(br, rect);
        }

        private static Color Shade(Color c, float f)
        {
            if (f >= 0) return Color.FromArgb(c.A, (int)(c.R + (255 - c.R) * f), (int)(c.G + (255 - c.G) * f), (int)(c.B + (255 - c.B) * f));
            f = -f;
            return Color.FromArgb(c.A, (int)(c.R * (1 - f)), (int)(c.G * (1 - f)), (int)(c.B * (1 - f)));
        }

        // Select a tab (shared by mouse-left + touch-tap): set the backing index, scroll into view, raise the event.
        private void SetSelected(int i)
        {
            if (_baseTabControl == null || i < 0 || i >= _baseTabControl.TabCount) return;
            if (_baseTabControl.SelectedIndex != i)
            {
                _baseTabControl.SelectedIndex = i;
                EnsureVisible(i);
                SelectedTabChanged?.Invoke(this, EventArgs.Empty);
            }
            else EnsureVisible(i);
            Invalidate();
        }

        public void EnsureSelectedVisible() { if (_baseTabControl != null) EnsureVisible(_baseTabControl.SelectedIndex); }

        private void EnsureVisible(int i)
        {
            if (i < 0 || i >= _tabRects.Count) return;
            var r = _tabRects[i];
            if (r.X < _scrollX) _scrollX = r.X;
            else if (r.Right > _scrollX + Width) _scrollX = r.Right - Width;
            ClampScroll();
            Invalidate();
        }

        /// <summary>Touch swipe (horizontal): pan by a finger Δx (finger right = +) → reveal earlier tabs.</summary>
        public void TouchPan(int fingerDeltaX) { _scrollX -= fingerDeltaX; ClampScroll(); Invalidate(); }
        public void TouchTap(Point p) { int i = HitTest(p); if (i >= 0) SetSelected(i); }
        public void TouchLongPress(Point p) { int i = HitTest(p); if (i >= 0) TabRightClicked?.Invoke(this, i); }

        protected override void OnMouseWheel(MouseEventArgs e)
        {
            if (MaxScroll <= 0) return;
            _scrollX += -Math.Sign(e.Delta) * Math.Max(40, Width / 6); // wheel → horizontal scroll
            ClampScroll();
            Invalidate();
        }

        protected override void OnMouseClick(MouseEventArgs e)
        {
            base.OnMouseClick(e);
            try { Focus(); } catch { } // take focus so mouse-wheel horizontal scroll lands here
            int i = HitTest(e.Location);
            if (i < 0) return;
            if (e.Button == MouseButtons.Right) TabRightClicked?.Invoke(this, i);
            else SetSelected(i);
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            int hover = HitTest(e.Location);
            if (hover != _hoverIndex) { _hoverIndex = hover; Cursor = hover >= 0 ? Cursors.Hand : Cursors.Default; Invalidate(); }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            if (_hoverIndex != -1) { _hoverIndex = -1; Cursor = Cursors.Default; Invalidate(); }
        }
    }
}

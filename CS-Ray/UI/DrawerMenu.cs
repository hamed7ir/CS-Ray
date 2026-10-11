using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>
    /// TelegArm-style side drawer: a narrow owner-drawn card (<see cref="CardW"/> wide) that overlays the content on
    /// the left, with an accent header + a scrollable list of glyph/label rows. NO full-window snapshot or scrim (the
    /// lightweight approach) — the card is opaque and only as wide as itself, so the content to its right stays fully
    /// visible; MainForm's message filter closes it on an outside tap. Built fresh each open against the current
    /// theme. Rows carry a glyph, label, optional right-aligned value (e.g. the theme mode), an action, danger flag,
    /// or a separator.
    /// </summary>
    internal sealed class DrawerMenu : Control
    {
        public sealed class Row
        {
            public string Glyph, Label, Value;
            public Action Action;
            public bool IsDanger, Separator;
        }

        /// <summary>Card width: 288 design px at the system DPI.</summary>
        public static int CardW => DrawHelper.Px(288);

        // Font-derived row/header metrics (set in the ctor once the fonts exist) — nothing clips at 125-200%.
        private readonly int HeaderH, RowH, SepH;

        private readonly bool _dark;
        private readonly Color _accent;
        private readonly string _title, _subtitle;
        private readonly List<Row> _rows;
        private readonly Rectangle[] _rects;
        private readonly Font _fTitle, _fSub, _fGlyph, _fLabel, _fValue;
        private int _hover = -2;
        private int _scrollY, _contentH;
        private bool _pressed, _moved; private int _pressY, _pressScroll;

        public event Action CloseRequested;

        public DrawerMenu(bool dark, Color accent, string title, string subtitle, List<Row> rows)
        {
            _dark = dark; _accent = accent; _title = title; _subtitle = subtitle; _rows = rows;
            _rects = new Rectangle[rows.Count];
            _fTitle = FontHelper.Ui(14f, FontStyle.Bold);
            _fSub = FontHelper.Ui(8.75f);
            _fGlyph = FontHelper.Ui(12.5f);
            _fLabel = FontHelper.Ui(10.5f);
            _fValue = FontHelper.Ui(9f);
            HeaderH = DrawHelper.Px(14) + _fTitle.Height + DrawHelper.Px(2) + _fSub.Height + DrawHelper.Px(14);
            RowH = Math.Max(DrawHelper.Px(46), Math.Max(_fLabel.Height, _fGlyph.Height) + DrawHelper.Px(20));
            SepH = DrawHelper.Px(11);
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint
                     | ControlStyles.OptimizedDoubleBuffer | ControlStyles.Selectable, true);
            TabStop = false;
            Layout2();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _fTitle?.Dispose(); _fSub?.Dispose(); _fGlyph?.Dispose(); _fLabel?.Dispose(); _fValue?.Dispose();
            }
            base.Dispose(disposing);
        }

        protected override void OnSizeChanged(EventArgs e) { base.OnSizeChanged(e); Layout2(); Invalidate(); }

        private void Layout2()
        {
            int y = HeaderH + DrawHelper.Px(6);
            for (int i = 0; i < _rows.Count; i++)
            {
                int h = _rows[i].Separator ? SepH : RowH;
                _rects[i] = new Rectangle(0, y, CardW, h);
                y += h;
            }
            _contentH = y + DrawHelper.Px(6);
            _scrollY = Math.Min(_scrollY, MaxScroll());
        }

        private int MaxScroll() { return Math.Max(0, _contentH - Height); }
        private int ClampScroll(int v) { return Math.Max(0, Math.Min(v, MaxScroll())); }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == Keys.Escape) { CloseRequested?.Invoke(); return true; }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            if (_pressed)   // touch/mouse drag-scroll over the rows
            {
                if (Math.Abs(e.Y - _pressY) > DrawHelper.Px(6)) _moved = true;
                if (_moved) { _scrollY = ClampScroll(_pressScroll - (e.Y - _pressY)); Invalidate(); }
                return;
            }
            int h = HitTest(e.Location);
            if (h != _hover) { _hover = h; Cursor = h >= 0 ? Cursors.Hand : Cursors.Default; Invalidate(); }
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (e.X > CardW) { CloseRequested?.Invoke(); return; }   // defensive (control is card-width; filter handles outside)
            _pressed = true; _moved = false; _pressY = e.Y; _pressScroll = _scrollY;
        }

        protected override void OnMouseUp(MouseEventArgs e)
        {
            base.OnMouseUp(e);
            bool wasPressed = _pressed, moved = _moved;
            _pressed = false; _moved = false;
            if (!wasPressed || moved || e.X > CardW) return;   // a drag-scroll, not a tap
            int h = HitTest(e.Location);
            if (h >= 0 && !_rows[h].Separator) _rows[h].Action?.Invoke();
        }

        protected override void OnMouseWheel(MouseEventArgs e)
        {
            base.OnMouseWheel(e);
            int ns = ClampScroll(_scrollY - Math.Sign(e.Delta) * RowH);
            if (ns != _scrollY) { _scrollY = ns; _hover = -2; Invalidate(); }
        }

        private int HitTest(Point p)
        {
            if (p.X > CardW || p.Y < HeaderH) return -2;
            int py = p.Y + _scrollY;
            for (int i = 0; i < _rows.Count; i++)
                if (!_rows[i].Separator && _rects[i].Contains(new Point(p.X, py))) return i;
            return -2;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            Color card = _dark ? Color.FromArgb(36, 36, 39) : Color.FromArgb(250, 250, 252);
            using (var cb = new SolidBrush(card)) g.FillRectangle(cb, 0, 0, CardW, Height);
            using (var pen = new Pen(_dark ? Color.FromArgb(54, 54, 58) : Color.FromArgb(224, 224, 228)))
                g.DrawLine(pen, CardW - 1, 0, CardW - 1, Height);

            // Accent header: app title + subtitle.
            using (var hb = new SolidBrush(_accent)) g.FillRectangle(hb, 0, 0, CardW, HeaderH);
            int hx = DrawHelper.Px(20), hw = CardW - DrawHelper.Px(32), ty = DrawHelper.Px(14);
            Color on = ThemePalette.OnColor(_accent);
            TextRenderer.DrawText(g, _title, _fTitle, new Rectangle(hx, ty, hw, _fTitle.Height), on,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
            if (!string.IsNullOrEmpty(_subtitle))
                TextRenderer.DrawText(g, _subtitle, _fSub, new Rectangle(hx, ty + _fTitle.Height + DrawHelper.Px(2), hw, _fSub.Height), DrawHelper.Blend(on, _accent, 0.2f),
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);

            // Rows (scroll under the fixed header).
            var savedClip = g.Clip;
            g.SetClip(new Rectangle(0, HeaderH, CardW, Math.Max(0, Height - HeaderH)));
            Color fg = _dark ? Color.FromArgb(232, 232, 236) : Color.FromArgb(32, 32, 36);
            Color dim = _dark ? Color.FromArgb(150, 150, 158) : Color.FromArgb(120, 120, 128);
            Color danger = Color.FromArgb(222, 74, 74);
            for (int i = 0; i < _rows.Count; i++)
            {
                var row = _rows[i];
                var r = new Rectangle(0, _rects[i].Y - _scrollY, CardW, _rects[i].Height);
                if (r.Bottom < HeaderH || r.Y > Height) continue;
                if (row.Separator)
                {
                    using (var p = new Pen(_dark ? Color.FromArgb(52, 52, 56) : Color.FromArgb(232, 232, 236)))
                        g.DrawLine(p, DrawHelper.Px(16), r.Y + r.Height / 2, CardW - DrawHelper.Px(16), r.Y + r.Height / 2);
                    continue;
                }
                if (_hover == i)
                    using (var hb = new SolidBrush(_dark ? Color.FromArgb(48, 48, 52) : Color.FromArgb(237, 240, 244)))
                        g.FillRectangle(hb, r);
                Color rowFg = row.IsDanger ? danger : fg;
                if (!string.IsNullOrEmpty(row.Glyph))
                    TextRenderer.DrawText(g, row.Glyph, _fGlyph, new Rectangle(DrawHelper.Px(16), r.Y, DrawHelper.Px(30), r.Height), rowFg,
                        TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
                int lx = DrawHelper.Px(52), vw = string.IsNullOrEmpty(row.Value) ? 0 : DrawHelper.Px(116);
                TextRenderer.DrawText(g, row.Label, _fLabel, new Rectangle(lx, r.Y, CardW - lx - DrawHelper.Px(16) - vw, r.Height), rowFg,
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
                if (!string.IsNullOrEmpty(row.Value))
                    TextRenderer.DrawText(g, row.Value, _fValue, new Rectangle(CardW - DrawHelper.Px(16) - vw, r.Y, vw, r.Height), dim,
                        TextFormatFlags.Right | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
            }
            g.Clip = savedClip;
        }
    }
}

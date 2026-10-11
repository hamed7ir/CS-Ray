using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>Shared look + metrics of the themed input fields (<see cref="ThemedTextBox"/>, <see cref="ThemedComboBox"/>):
    /// an optional small caption above a rounded, bordered box (DroidFinestra's TextRow look) whose ring turns accent on
    /// focus. Heights are FONT-derived, so the fields grow with the system DPI instead of clipping. An empty caption
    /// (hint) means no caption line at all — the field is just the box (for inputs inside an already-titled row).</summary>
    internal static class FieldChrome
    {
        // Private font refs (never reassigned by anyone) shared by every field.
        public static readonly Font LabelFont = FontHelper.Ui(8.25f);
        public static readonly Font BoxFont = FontHelper.Ui(10f);
        public static readonly Font MenuFont = FontHelper.Ui(9.75f);

        public static int BoxHeight => BoxFont.Height + DrawHelper.Px(14);
        public static int InnerPadX => DrawHelper.Px(10);
        public static int ChevronWidth => DrawHelper.Px(28);

        public static int CaptionHeight(string caption) => string.IsNullOrEmpty(caption) ? 0 : LabelFont.Height + DrawHelper.Px(4);
        public static int FieldHeight(string caption) => string.IsNullOrEmpty(caption) ? BoxHeight : CaptionHeight(caption) + BoxHeight + DrawHelper.Px(2);
        public static Rectangle BoxRect(int width, string caption) => new Rectangle(0, CaptionHeight(caption), Math.Max(1, width - 1), BoxHeight - 1);

        /// <summary>Paints the caption (if any) + the field box (fill + ring) on the parent's background.</summary>
        public static void Paint(Graphics g, Control c, string caption, bool focused, ThemePalette p)
        {
            g.Clear(c.Parent != null ? c.Parent.BackColor : p.Surface);
            if (!string.IsNullOrEmpty(caption))
            {
                Color cap = !c.Enabled ? p.Dim : focused ? p.AccentText : p.Dim;
                TextRenderer.DrawText(g, caption, LabelFont, new Rectangle(DrawHelper.Px(2), 0, Math.Max(1, c.Width - DrawHelper.Px(4)), CaptionHeight(caption)), cap,
                    TextFormatFlags.Left | TextFormatFlags.Top | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);
            }

            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var path = DrawHelper.RoundedRect(BoxRect(c.Width, caption), DrawHelper.Px(6)))
            {
                using (var b = new SolidBrush(p.Field)) g.FillPath(b, path);
                Color ring = focused && c.Enabled ? p.AccentText : p.InputBorder;
                using (var pen = new Pen(ring, focused ? Math.Max(1.6f, 1.6f * DrawHelper.DpiScale) : 1f)) g.DrawPath(pen, path);
            }
        }

        /// <summary>The ▾ chevron at the right end of a field box.</summary>
        public static void PaintChevron(Graphics g, Rectangle box, Color color)
        {
            int cx = box.Right - ChevronWidth / 2, cy = box.Y + box.Height / 2, s = DrawHelper.Px(4);
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (var pen = new Pen(color, Math.Max(1.6f, 1.6f * DrawHelper.DpiScale)) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            {
                g.DrawLine(pen, cx - s, cy - s / 2, cx, cy + s / 2);
                g.DrawLine(pen, cx + s, cy - s / 2, cx, cy + s / 2);
            }
        }
    }

    /// <summary>
    /// Themed single-line text field replacing MaterialTextBox2 and the plain settings TextBoxes: an optional caption
    /// (<see cref="Hint"/>) above a bordered, dark-aware box hosting a borderless native TextBox (real editing, IME,
    /// clipboard). The ring + caption turn accent on focus. Optional <see cref="Suggestions"/> add a chevron that drops a
    /// themed pick-list (an editable combo — e.g. the DNS resolver). Fixed, font-derived height (like a TextBox).
    /// Self-themed (<see cref="ISelfThemed"/>) and live on <see cref="ThemeHelper.ThemeChanged"/>. Text / TextChanged
    /// forward to the inner box.
    /// </summary>
    public sealed class ThemedTextBox : Control, ISelfThemed
    {
        private readonly TextBox _box;
        private string _hint = "";
        private string[] _suggestions;
        private bool _focused, _dropped;
        private bool _swallowOpen;   // the press that just dismissed our open list landed on the chevron → don't reopen
        private int _swallowTick;

        public ThemedTextBox()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint
                     | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            SetStyle(ControlStyles.Selectable, false); // focus goes to the inner TextBox; Tab skips the frame
            TabStop = false;
            Cursor = Cursors.IBeam;

            _box = new TextBox { BorderStyle = BorderStyle.None, Font = FieldChrome.BoxFont };
            _box.GotFocus += (s, e) => { _focused = true; Invalidate(); };
            _box.LostFocus += (s, e) => { _focused = false; Invalidate(); };
            _box.TextChanged += (s, e) => OnTextChanged(e);
            _box.KeyDown += (s, e) =>
            {
                if (HasSuggestions && (e.KeyCode == Keys.F4 || (e.Alt && e.KeyCode == Keys.Down))) { OpenSuggestions(); e.Handled = true; }
            };
            Controls.Add(_box);

            Height = FieldChrome.FieldHeight(_hint);
            ApplyTheme();
            ThemeHelper.ThemeChanged += OnThemeChanged;
        }

        /// <summary>Caption shown above the box (MaterialTextBox2's Hint); also the field's accessible name. Empty =
        /// no caption line (the control is just the box).</summary>
        public string Hint
        {
            get { return _hint; }
            set { _hint = value ?? ""; _box.AccessibleName = _hint; Height = FieldChrome.FieldHeight(_hint); PerformLayout(); Invalidate(); }
        }

        /// <summary>Values offered from a chevron drop-down (null/empty = plain text field). Picking one sets Text.</summary>
        public string[] Suggestions { get { return _suggestions; } set { _suggestions = value; PerformLayout(); Invalidate(); } }

        private bool HasSuggestions => _suggestions != null && _suggestions.Length > 0;

        public override string Text
        {
            get { return _box != null ? _box.Text : base.Text; }
            set { if (_box != null) _box.Text = value ?? ""; else base.Text = value; }
        }

        public bool UseSystemPasswordChar { get { return _box.UseSystemPasswordChar; } set { _box.UseSystemPasswordChar = value; } }
        public bool ReadOnly { get { return _box.ReadOnly; } set { _box.ReadOnly = value; } }
        public int MaxLength { get { return _box.MaxLength; } set { _box.MaxLength = value; } }

        /// <summary>The hosted native TextBox (for selection / key handling).</summary>
        public TextBox InnerTextBox => _box;

        public new bool Focus() => _box.Focus();
        public void SelectAll() => _box.SelectAll();
        public void Clear() => _box.Clear();

        public void ApplyTheme()
        {
            var p = ThemeHelper.Palette();
            _box.BackColor = p.Field;
            _box.ForeColor = p.Text;
            Invalidate();
        }

        private void OnThemeChanged() { if (!IsDisposed && IsHandleCreated) { try { BeginInvoke((Action)ApplyTheme); } catch { } } }

        // A field hidden since creation has no handle, so a theme flip skipped it — catch up when it's first shown.
        protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); ApplyTheme(); }

        protected override void Dispose(bool disposing)
        {
            if (disposing) ThemeHelper.ThemeChanged -= OnThemeChanged;
            base.Dispose(disposing);
        }

        // Height is font-derived (a TextBox's own rule) — callers set Location / Width only.
        protected override void SetBoundsCore(int x, int y, int width, int height, BoundsSpecified specified)
            => base.SetBoundsCore(x, y, width, FieldChrome.FieldHeight(_hint), specified);

        protected override void OnLayout(LayoutEventArgs e)
        {
            base.OnLayout(e);
            if (_box == null) return;   // base ctor can lay out before the field exists
            var r = FieldChrome.BoxRect(Width, _hint);
            int pad = FieldChrome.InnerPadX, chevron = HasSuggestions ? FieldChrome.ChevronWidth : 0;
            _box.SetBounds(pad, r.Y + (r.Height - _box.Height) / 2 + 1, Math.Max(10, Width - 2 * pad - chevron), _box.Height);
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (e.Button == MouseButtons.Left) _box.Focus();
        }

        private bool OnChevron(Point p)
        {
            var r = FieldChrome.BoxRect(Width, _hint);
            return HasSuggestions && p.X >= r.Right - FieldChrome.ChevronWidth && p.Y >= r.Y;
        }

        // Open on the CLICK (release), like ThemedComboBox: a finger pan that starts on the chevron is claimed by the
        // scroll panel (which swallows the release), and a click that only dismissed our list doesn't reopen it.
        protected override void OnMouseClick(MouseEventArgs e)
        {
            base.OnMouseClick(e);
            if (e.Button != MouseButtons.Left || !OnChevron(e.Location)) return;
            bool swallow = _swallowOpen && unchecked((uint)(Environment.TickCount - _swallowTick)) < (uint)SystemInformation.DoubleClickTime;
            _swallowOpen = false;
            if (!swallow) OpenSuggestions();
        }

        protected override void OnMouseUp(MouseEventArgs e) { base.OnMouseUp(e); _swallowOpen = false; } // after MouseClick

        private void OpenSuggestions()
        {
            if (_dropped || !HasSuggestions || !Enabled) return;
            var menu = new ThemedContextMenuStrip { Font = FieldChrome.MenuFont, MinimumSize = new Size(Width, 0) };
            string cur = (_box.Text ?? "").Trim();
            foreach (var sug in _suggestions)
            {
                string v = sug;
                var it = new ToolStripMenuItem(v) { Checked = string.Equals(v, cur, StringComparison.OrdinalIgnoreCase) };
                it.Click += (s, ev) => { _box.Text = v; _box.Focus(); _box.SelectAll(); };
                menu.Items.Add(it);
            }
            menu.Closed += (s, ev) =>
            {
                _swallowOpen = ev.CloseReason == ToolStripDropDownCloseReason.AppClicked && OnChevron(PointToClient(Cursor.Position));
                _swallowTick = Environment.TickCount;
                _dropped = false;
                try { BeginInvoke((Action)menu.Dispose); } catch { menu.Dispose(); }
            };
            _dropped = true;
            menu.Show(this, new Point(0, Height));
        }

        protected override void OnEnabledChanged(EventArgs e) { base.OnEnabledChanged(e); Invalidate(); }

        protected override void OnPaint(PaintEventArgs e)
        {
            var p = ThemeHelper.Palette();
            FieldChrome.Paint(e.Graphics, this, _hint, _focused, p);
            if (HasSuggestions) FieldChrome.PaintChevron(e.Graphics, FieldChrome.BoxRect(Width, _hint), _focused && Enabled ? p.AccentText : p.Dim);
        }
    }
}

using System;
using System.Collections;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>
    /// Themed drop-down list replacing MaterialComboBox (DropDownList semantics): the same caption + bordered box as
    /// <see cref="ThemedTextBox"/>, painted as ONE owner-drawn control, opening a <see cref="ThemedContextMenuStrip"/>
    /// of the items (DroidFinestra's ChoiceRow pattern) — so the closed box and the open list are both dark-aware on
    /// every OS, unlike a native ComboBox frame. Mirrors the ComboBox members CS-Ray uses: Items (Add / AddRange /
    /// Clear), SelectedIndex, SelectedItem (an item not in the list leaves the selection unchanged, exactly like
    /// ComboBox) and SelectedIndexChanged. Keyboard: Up/Down step, Space / F4 / Alt+Down open.
    /// </summary>
    public sealed class ThemedComboBox : Control, ISelfThemed
    {
        /// <summary>The item list (owner-aware: edits repaint and keep the selection in range).</summary>
        public sealed class ItemCollection : IEnumerable<object>
        {
            private readonly ThemedComboBox _owner;
            private readonly List<object> _list = new List<object>();
            internal ItemCollection(ThemedComboBox owner) { _owner = owner; }

            public int Count => _list.Count;
            public object this[int index] => _list[index];
            public int IndexOf(object item) => _list.IndexOf(item);
            public void Add(object item) { _list.Add(item); _owner.Invalidate(); }
            public void AddRange(IEnumerable<object> items) { if (items != null) _list.AddRange(items); _owner.Invalidate(); }
            public void Clear() { _list.Clear(); _owner.SelectedIndex = -1; _owner.Invalidate(); }
            public IEnumerator<object> GetEnumerator() => _list.GetEnumerator();
            IEnumerator IEnumerable.GetEnumerator() => _list.GetEnumerator();
        }

        private readonly ItemCollection _items;
        private int _index = -1;
        private string _hint = "";
        private bool _focused, _dropped;
        private bool _swallowOpen;   // the press that just dismissed our open list landed on us → don't reopen on its click
        private int _swallowTick;    // when it was set — honored only briefly, so a lost mouse-up can't make it stale

        public event EventHandler SelectedIndexChanged;

        public ThemedComboBox()
        {
            SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer
                     | ControlStyles.ResizeRedraw | ControlStyles.Selectable, true);
            TabStop = true;
            Cursor = Cursors.Hand;
            AccessibleRole = AccessibleRole.ComboBox;
            _items = new ItemCollection(this);
            Height = FieldChrome.FieldHeight(_hint);
            ThemeHelper.ThemeChanged += OnThemeChanged;
        }

        public ItemCollection Items => _items;

        /// <summary>Caption shown above the box (MaterialComboBox's Hint); also the accessible name.</summary>
        public string Hint { get { return _hint; } set { _hint = value ?? ""; AccessibleName = _hint; Height = FieldChrome.FieldHeight(_hint); Invalidate(); } }

        public int SelectedIndex
        {
            get { return _index; }
            set
            {
                if (value < -1 || value >= _items.Count) throw new ArgumentOutOfRangeException(nameof(value));
                if (_index == value) return;
                _index = value;
                AccessibleDescription = Display(_index);   // screen readers announce the current choice
                Invalidate();
                SelectedIndexChanged?.Invoke(this, EventArgs.Empty);
            }
        }

        public object SelectedItem
        {
            get { return _index >= 0 && _index < _items.Count ? _items[_index] : null; }
            set
            {
                if (value == null) { SelectedIndex = -1; return; }
                int i = _items.IndexOf(value);
                if (i != -1) SelectedIndex = i;   // not in the list → unchanged (ComboBox semantics)
            }
        }

        private string Display(int i) => i >= 0 && i < _items.Count ? (_items[i]?.ToString() ?? "") : "";

        public void ApplyTheme() => Invalidate();

        private void OnThemeChanged() { if (!IsDisposed && IsHandleCreated) { try { BeginInvoke((Action)Invalidate); } catch { } } }

        protected override void Dispose(bool disposing)
        {
            if (disposing) ThemeHelper.ThemeChanged -= OnThemeChanged;
            base.Dispose(disposing);
        }

        protected override void SetBoundsCore(int x, int y, int width, int height, BoundsSpecified specified)
            => base.SetBoundsCore(x, y, width, FieldChrome.FieldHeight(_hint), specified);

        protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); _focused = true; Invalidate(); }
        protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); _focused = false; Invalidate(); }
        protected override void OnEnabledChanged(EventArgs e) { base.OnEnabledChanged(e); Invalidate(); }

        protected override bool IsInputKey(Keys keyData)
        {
            switch (keyData & Keys.KeyCode)
            {
                case Keys.Up: case Keys.Down: return true;
            }
            return base.IsInputKey(keyData);
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);
            if (e.KeyCode == Keys.F4 || e.KeyCode == Keys.Space || (e.Alt && e.KeyCode == Keys.Down)) { OpenDropDown(); e.Handled = true; }
            else if (e.KeyCode == Keys.Down) { if (_index < _items.Count - 1) SelectedIndex = _index + 1; e.Handled = true; }
            else if (e.KeyCode == Keys.Up) { if (_index > 0) SelectedIndex = _index - 1; e.Handled = true; }
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            if (e.Button == MouseButtons.Left) Focus();
        }

        // Open on the CLICK (release), like DroidFinestra's ChoiceRow: a finger/mouse pan that starts on the box is
        // claimed by the scroll panel (which swallows the release), so it scrolls instead of popping the list.
        protected override void OnMouseClick(MouseEventArgs e)
        {
            base.OnMouseClick(e);
            if (e.Button != MouseButtons.Left) return;
            bool swallow = _swallowOpen && unchecked((uint)(Environment.TickCount - _swallowTick)) < (uint)SystemInformation.DoubleClickTime;
            _swallowOpen = false;
            if (swallow) return; // this click only dismissed our list → toggle closed
            OpenDropDown();
        }

        protected override void OnMouseUp(MouseEventArgs e) { base.OnMouseUp(e); _swallowOpen = false; } // after MouseClick

        private void OpenDropDown()
        {
            if (_dropped || _items.Count == 0 || !Enabled) return;
            var menu = new ThemedContextMenuStrip { Font = FieldChrome.MenuFont, MinimumSize = new Size(Width, 0) };
            for (int i = 0; i < _items.Count; i++)
            {
                int ii = i;
                var it = new ToolStripMenuItem(Display(i)) { Checked = i == _index };
                it.Click += (s, ev) => SelectedIndex = ii;
                menu.Items.Add(it);
            }
            menu.Closed += (s, ev) =>
            {
                _swallowOpen = ev.CloseReason == ToolStripDropDownCloseReason.AppClicked
                               && RectangleToScreen(ClientRectangle).Contains(Cursor.Position);
                _swallowTick = Environment.TickCount;
                _dropped = false;
                Invalidate();
                try { BeginInvoke((Action)menu.Dispose); } catch { menu.Dispose(); } // after any item Click has run
            };
            _dropped = true;
            Invalidate();
            menu.Show(this, new Point(0, Height));
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            var p = ThemeHelper.Palette();
            bool hot = _focused || _dropped;
            FieldChrome.Paint(g, this, _hint, hot, p);

            var box = FieldChrome.BoxRect(Width, _hint);
            int pad = FieldChrome.InnerPadX, chevronW = FieldChrome.ChevronWidth;
            var tr = new Rectangle(box.X + pad, box.Y, Math.Max(1, box.Width - pad - chevronW), box.Height);
            TextRenderer.DrawText(g, Display(_index), FieldChrome.BoxFont, tr, Enabled ? p.Text : p.Dim,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine
                | TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);

            FieldChrome.PaintChevron(g, box, hot && Enabled ? p.AccentText : p.Dim);
        }
    }
}

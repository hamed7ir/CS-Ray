using System;
using System.Drawing;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>
    /// Base for CS-Ray's modal dialogs (ported from DroidFinestra's UI/ThemedDialog.cs; replaces MaterialForm): the
    /// borderless accent <see cref="ThemedTitleBar"/> (title + ✕ + drag), a <see cref="Content"/> area holding a
    /// scrollable <see cref="Body"/> (owner-drawn scrollbar) and a right-aligned <see cref="Footer"/> for the action
    /// buttons. Dock-based (Top bar + Bottom footer + Fill content) so it holds together under DPI; a 1px frame (the
    /// form's own BackColor showing through its Padding) + a drop shadow keep it distinct from the window behind it.
    /// Recolors live on <see cref="ThemeHelper.ThemeChanged"/>. DroidFinestra's touch-keyboard inset / WM_ACTIVATE
    /// refocus fixes are intentionally not ported (CS-Ray is a desktop proxy UI).
    /// </summary>
    public class ThemedDialog : Form
    {
        private const int CS_DROPSHADOW = 0x00020000;

        private static readonly Font ButtonFont = FontHelper.Ui(9.75f, FontStyle.Bold);

        /// <summary>The accent title bar (its title mirrors <see cref="Form.Text"/>).</summary>
        protected readonly ThemedTitleBar TitleBar;

        /// <summary>The area between the title bar and the footer. Holds <see cref="Body"/> when the dialog scrolls;
        /// subclasses that lay out their own regions (tabs) add Dock-ed controls here instead.</summary>
        protected readonly Panel Content;

        /// <summary>Scrollable body — add rows to <c>Body.Host</c> at absolute positions. Null when constructed with
        /// <c>scrollBody: false</c>.</summary>
        protected readonly ThemedScrollPanel Body;

        /// <summary>Right-aligned action-button strip (see <see cref="AddFooterButton"/>).</summary>
        protected readonly FlowLayoutPanel Footer;

        protected ThemedDialog(string title, bool scrollBody = true)
        {
            FormBorderStyle = FormBorderStyle.None;
            ShowInTaskbar = false;
            MinimizeBox = false;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            AutoScaleMode = AutoScaleMode.Font;
            Font = FontHelper.Ui(9f);
            DoubleBuffered = true;
            Padding = new Padding(1);   // 1px frame: the form BackColor (border color) shows through
            ThemedChrome.SetAppIcon(this);

            TitleBar = new ThemedTitleBar { Dock = DockStyle.Top, ShowMinimize = false, ShowMaximize = false, ShowClose = true };
            Footer = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                FlowDirection = FlowDirection.RightToLeft,
                WrapContents = false,
                Height = DrawHelper.Px(36) + 2 * DrawHelper.Px(10),
                Padding = new Padding(0, DrawHelper.Px(10), DrawHelper.Px(14), DrawHelper.Px(10))
            };
            Content = new Panel { Dock = DockStyle.Fill };
            if (scrollBody)
            {
                Body = new ThemedScrollPanel { Dock = DockStyle.Fill };
                Content.Controls.Add(Body);
            }

            Controls.Add(Content);   // Fill — added first so it docks last, between the bar and the footer
            Controls.Add(Footer);    // Bottom
            Controls.Add(TitleBar);  // Top
            Text = title ?? "";      // → TitleBar.Title (OnTextChanged); also the taskbar / Alt-Tab caption

            ApplyDialogTheme();
            ThemeHelper.ThemeChanged += OnDialogThemeChanged;
        }

        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                cp.ClassStyle |= CS_DROPSHADOW;
                return cp;
            }
        }

        protected override void OnTextChanged(EventArgs e)
        {
            base.OnTextChanged(e);
            if (TitleBar != null) TitleBar.Title = Text;
        }

        private void OnDialogThemeChanged()
        {
            if (IsDisposed || !IsHandleCreated) return;
            try { BeginInvoke((Action)ApplyDialogTheme); } catch { }
        }

        // ShowDialog DESTROYS the handle when it returns, so a re-shown dialog (Settings is created once) missed every
        // theme change made while it was closed — the stale-footer bug. Catch up whenever the handle is (re)created.
        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            ApplyDialogTheme();
        }

        /// <summary>Re-applies the chrome colors (frame, content, footer). Override to recolor subclass content; call
        /// base first. Runs at construction and on every ThemeChanged.</summary>
        protected virtual void ApplyDialogTheme()
        {
            if (IsDisposed) return;
            var p = ThemeHelper.Palette();
            BackColor = p.Border;          // the 1px Padding ring = the frame line
            Content.BackColor = p.Surface;
            Footer.BackColor = p.Footer;
            TitleBar.Invalidate();
            Footer.Invalidate(true);       // RoundedButtons repaint their corners against the footer color
        }

        /// <summary>Adds a footer action button; the first added is the RIGHTMOST. A non-None <paramref name="result"/>
        /// closes the modal dialog with that result on click (Button.DialogResult).</summary>
        protected RoundedButton AddFooterButton(string text, RoundedButtonKind kind, DialogResult result = DialogResult.None)
        {
            int w = Math.Max(DrawHelper.Px(100), TextRenderer.MeasureText(text ?? "", ButtonFont).Width + DrawHelper.Px(32));
            var b = new RoundedButton
            {
                Text = text,
                Kind = kind,
                Font = ButtonFont,
                Size = new Size(w, DrawHelper.Px(36)),
                Margin = new Padding(DrawHelper.Px(8), 0, 0, 0)
            };
            if (result != DialogResult.None) b.DialogResult = result;
            Footer.Controls.Add(b);
            return b;
        }

        private int _fitW = -1, _fitH;

        /// <summary>Sizes the dialog so <see cref="Body"/> shows a <paramref name="hostWidth"/> × <paramref
        /// name="contentHeight"/> content area (plus the scrollbar lane), capped to ~92% of the work area of the screen
        /// it will appear on — beyond that the body scrolls instead of the dialog running off-screen. Re-applied in
        /// OnLoad (the owner — hence the screen — is only known once ShowDialog runs). If already visible, it's nudged
        /// up so its bottom stays on screen. Without a Body, sizes the Content area to the given size.</summary>
        protected void FitToContent(int hostWidth, int contentHeight)
        {
            _fitW = hostWidth; _fitH = contentHeight;
            ApplyFit();
        }

        private void ApplyFit()
        {
            int w = _fitW + (Body != null ? Body.GutterWidth : 0) + Padding.Horizontal;
            int h = Padding.Vertical + TitleBar.Height + Footer.Height + _fitH;
            Rectangle wa = TargetWorkArea();
            ClientSize = new Size(w, Math.Min(h, (int)(wa.Height * 0.92)));
            Body?.SetContentHeight(_fitH);
            if (IsHandleCreated && Visible && Bottom > wa.Bottom) Top = Math.Max(wa.Top, wa.Bottom - Height);
        }

        // The screen the dialog is on: its owner's (CenterParent), else its own once shown, else the cursor's.
        private Rectangle TargetWorkArea()
        {
            try
            {
                if (Owner != null) return Screen.FromControl(Owner).WorkingArea;
                if (IsHandleCreated && Visible) return Screen.FromControl(this).WorkingArea;
                return Screen.FromPoint(Cursor.Position).WorkingArea;
            }
            catch { return Screen.PrimaryScreen.WorkingArea; }
        }

        // Before base.OnLoad: a modal dialog is centered there, so it centers the final (re-capped) size.
        protected override void OnLoad(EventArgs e)
        {
            if (_fitW >= 0) ApplyFit();
            base.OnLoad(e);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) ThemeHelper.ThemeChanged -= OnDialogThemeChanged;
            base.Dispose(disposing);
        }
    }
}

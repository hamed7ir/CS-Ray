using System;
using System.Drawing;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>
    /// Shares a server or a subscription: the link as a QR code to scan with a phone, the link itself, and a Copy
    /// button. The link carries the server's secret (id / password), so it only goes to the clipboard and the screen,
    /// never to the log or a file. When there's nothing to share, the dialog just says why.
    /// </summary>
    public sealed class ShareDialog : ThemedDialog
    {
        private readonly string _link;
        private readonly Label _name, _note;
        private readonly QrView _qr;
        private readonly ThemedTextBox _txt;
        private readonly RoundedButton _btnCopy, _btnClose;
        private readonly Timer _copiedTimer;

        /// <param name="title">Window title ("Share server" / "Share subscription").</param>
        /// <param name="name">What is shared, shown above the code.</param>
        /// <param name="link">The link, or null when it can't be shared.</param>
        /// <param name="reason">Why it can't be shared (used when <paramref name="link"/> is null).</param>
        /// <param name="warning">The note under the link (who can use it); null = the server wording.</param>
        public ShareDialog(string title, string name, string link, string reason, string warning = null) : base(title)
        {
            _link = link;
            KeyPreview = true;
            KeyDown += (s, e) => { if (e.KeyCode == Keys.Escape) Close(); };

            _name = new Label { Text = name ?? "", AutoSize = false, TextAlign = ContentAlignment.MiddleCenter, Font = FontHelper.Ui(11f, FontStyle.Bold), UseMnemonic = false, AutoEllipsis = true };
            Body.Host.Controls.Add(_name);

            if (link != null)
            {
                _qr = new QrView();
                _qr.SetPayload(link);
                string warn = warning ?? "Anyone who has this link can use the server. Only send it to people you trust.";
                if (!_qr.HasCode) { _qr.Dispose(); _qr = null; warn = "This link is too long for a QR code, but you can copy it.\n" + warn; }
                _txt = new ThemedTextBox { Text = link, ReadOnly = true };
                _note = new Label { Text = warn, AutoSize = false, TextAlign = ContentAlignment.MiddleCenter, Font = FontHelper.Ui(8.5f), UseMnemonic = false };
                if (_qr != null) Body.Host.Controls.Add(_qr);
                Body.Host.Controls.Add(_txt);
                Body.Host.Controls.Add(_note);
            }
            else
            {
                _note = new Label { Text = reason ?? "This can't be shared.", AutoSize = false, TextAlign = ContentAlignment.MiddleCenter, Font = FontHelper.Ui(9.5f), UseMnemonic = false };
                Body.Host.Controls.Add(_note);
            }

            if (link != null)
            {
                _btnCopy = AddFooterButton("Copy link", RoundedButtonKind.Primary);   // rightmost
                _btnCopy.Click += (s, e) => Copy();
                _btnClose = AddFooterButton("Close", RoundedButtonKind.Secondary, DialogResult.Cancel);
                AcceptButton = _btnCopy;
            }
            else
            {
                _btnClose = AddFooterButton("Close", RoundedButtonKind.Primary, DialogResult.Cancel);
                AcceptButton = _btnClose;
            }
            CancelButton = _btnClose;

            _copiedTimer = new Timer { Interval = 1500 };
            _copiedTimer.Tick += (s, e) => { _copiedTimer.Stop(); if (_btnCopy != null && !_btnCopy.IsDisposed) _btnCopy.Text = "Copy link"; };

            ApplyDialogTheme();
            Relayout();
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            if (_txt != null)
            {
                // Show the start of the link (the scheme and server), not wherever the caret was left.
                var box = _txt.InnerTextBox;
                box.SelectionStart = 0; box.SelectionLength = 0; box.ScrollToCaret();
            }
            _btnCopy?.Focus();   // not the text box: a focused read-only box would select the whole secret
        }

        private void Copy()
        {
            try
            {
                Clipboard.SetDataObject(_link, true, 5, 100);   // retries while another app holds the clipboard
                _btnCopy.Text = "Copied";
                _copiedTimer.Stop(); _copiedTimer.Start();
            }
            catch (Exception)
            {
                _btnCopy.Text = "Couldn't copy";
                _copiedTimer.Stop(); _copiedTimer.Start();
            }
        }

        protected override void ApplyDialogTheme()
        {
            base.ApplyDialogTheme();
            if (_name == null) return;   // the base constructor runs this before the controls exist
            var p = ThemeHelper.Palette();
            _name.BackColor = p.Surface; _name.ForeColor = p.Text;
            _note.BackColor = p.Surface; _note.ForeColor = p.Dim;
        }

        private void Relayout()
        {
            int pad = DrawHelper.Px(20);
            int side = DrawHelper.Px(280);
            if (_qr != null)
            {
                // At least 3 px per module (phone cameras struggle below that); a long link makes a bigger code.
                int n = _qr.ModuleCount;
                side = n * Math.Max(3, DrawHelper.Px(300) / n);
            }
            int w = Math.Max(DrawHelper.Px(420), side + 2 * pad);
            int inner = w - 2 * pad;
            int y = DrawHelper.Px(14);

            int nameH = _name.Font.Height + DrawHelper.Px(6);
            _name.SetBounds(pad, y, inner, nameH); y += nameH + DrawHelper.Px(10);
            if (_qr != null) { _qr.SetBounds((w - side) / 2, y, side, side); y += side + DrawHelper.Px(14); }
            if (_txt != null) { _txt.SetBounds(pad, y, inner, 0); y += _txt.Height + DrawHelper.Px(8); }
            int noteH = TextRenderer.MeasureText(_note.Text, _note.Font, new Size(inner, int.MaxValue), TextFormatFlags.WordBreak).Height + DrawHelper.Px(4);
            _note.SetBounds(pad, y, inner, noteH); y += noteH + DrawHelper.Px(12);
            FitToContent(w, y);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _copiedTimer.Dispose();
            base.Dispose(disposing);
        }
    }
}

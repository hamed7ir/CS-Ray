using System;
using System.Drawing;
using System.Windows.Forms;

namespace CS_Ray.UI
{
    /// <summary>
    /// Tiny themed dialog to add / rename / re-point a subscription (Name + URL). A <see cref="ThemedDialog"/> (accent
    /// title bar + OK/Cancel footer). Used by the Subscriptions tab "Add"/"Edit" and the tab right-click "Rename…".
    /// </summary>
    public sealed class SubEditDialog : ThemedDialog
    {
        private readonly ThemedTextBox _txtName, _txtUrl;
        private readonly RoundedButton _btnOk, _btnCancel;

        public string ResultName { get; private set; }
        public string ResultUrl { get; private set; }

        public SubEditDialog(string title, string name, string url) : base(title)
        {
            _txtName = new ThemedTextBox { Hint = "Name", Text = name ?? "" };
            _txtUrl = new ThemedTextBox { Hint = "Subscription URL", Text = url ?? "" };
            Body.Host.Controls.Add(_txtName);
            Body.Host.Controls.Add(_txtUrl);

            _btnOk = AddFooterButton("OK", RoundedButtonKind.Primary);               // rightmost
            _btnCancel = AddFooterButton("Cancel", RoundedButtonKind.Secondary, DialogResult.Cancel);
            _btnOk.Click += (s, e) =>
            {
                var u = (_txtUrl.Text ?? "").Trim();
                if (u.Length == 0) return; // URL required
                ResultName = (_txtName.Text ?? "").Trim();
                ResultUrl = u;
                DialogResult = DialogResult.OK;
                Close();
            };
            AcceptButton = _btnOk; CancelButton = _btnCancel;

            Relayout();
        }

        private void Relayout()
        {
            int x = DrawHelper.Px(24), w = DrawHelper.Px(470), gap = DrawHelper.Px(12);
            int y = DrawHelper.Px(14);
            _txtName.SetBounds(x, y, w - 2 * x, 0); y += _txtName.Height + gap;
            _txtUrl.SetBounds(x, y, w - 2 * x, 0); y += _txtUrl.Height + DrawHelper.Px(6);
            FitToContent(w, y);
        }
    }
}

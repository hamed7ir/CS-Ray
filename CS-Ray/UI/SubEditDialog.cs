using System;
using System.Drawing;
using System.Windows.Forms;
using MaterialSkin;
using MaterialSkin.Controls;

namespace CS_Ray.UI
{
    /// <summary>
    /// Tiny themed dialog to add / rename / re-point a subscription (Name + URL). MaterialForm with the full
    /// accent action bar. Used by the Subscriptions tab "Add"/"Edit" and the tab right-click "Rename…".
    /// </summary>
    public sealed class SubEditDialog : MaterialForm
    {
        private const int X = 24, FieldW = 422, FieldGap = 64;

        private readonly MaterialTextBox2 _txtName, _txtUrl;
        private readonly MaterialButton _btnOk, _btnCancel;

        public string ResultName { get; private set; }
        public string ResultUrl { get; private set; }

        public SubEditDialog(string title, string name, string url)
        {
            var skin = MaterialSkinManager.Instance;
            skin.AddFormToManage(this);
            skin.Theme = ThemeHelper.IsDark ? MaterialSkinManager.Themes.DARK : MaterialSkinManager.Themes.LIGHT;
            var accent = (Primary)(uint)ThemeHelper.GetWindowsAccentColor().ToArgb();
            skin.ColorScheme = new ColorScheme(accent, accent, accent, Accent.LightBlue200, TextShade.WHITE);

            Text = title;                       // shown in the full accent action bar
            AutoScaleMode = AutoScaleMode.Font;
            Font = FontHelper.Ui(9f);
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = false; MinimizeBox = false; Sizable = false;

            _txtName = new MaterialTextBox2 { Hint = "Name", Text = name ?? "", Width = FieldW };
            _txtUrl = new MaterialTextBox2 { Hint = "Subscription URL", Text = url ?? "", Width = FieldW };
            _btnOk = new MaterialButton { Text = "OK", Type = MaterialButton.MaterialButtonType.Contained, AutoSize = false, Width = 100, Height = 36 };
            _btnCancel = new MaterialButton { Text = "Cancel", Type = MaterialButton.MaterialButtonType.Outlined, AutoSize = false, Width = 100, Height = 36 };

            _btnOk.Click += (s, e) =>
            {
                var u = (_txtUrl.Text ?? "").Trim();
                if (u.Length == 0) return; // URL required
                ResultName = (_txtName.Text ?? "").Trim();
                ResultUrl = u;
                DialogResult = DialogResult.OK;
                Close();
            };
            _btnCancel.Click += (s, e) => { DialogResult = DialogResult.Cancel; Close(); };

            Controls.Add(_txtName);
            Controls.Add(_txtUrl);
            Controls.Add(_btnOk);
            Controls.Add(_btnCancel);
            AcceptButton = _btnOk; CancelButton = _btnCancel;

            Relayout();
        }

        // MaterialForm reserves its accent action bar via Padding.Top (fallback 64 before it's known).
        private int TopInset => Math.Max(64, Padding.Top);

        protected override void OnLoad(EventArgs e) { base.OnLoad(e); Relayout(); }

        private void Relayout()
        {
            int y = TopInset + 12;
            _txtName.Location = new Point(X, y); y += FieldGap;
            _txtUrl.Location = new Point(X, y); y += FieldGap;      // clears the URL field — no overlap
            _btnOk.Location = new Point(470 - X - _btnOk.Width, y);
            _btnCancel.Location = new Point(_btnOk.Left - 8 - _btnCancel.Width, y);
            ClientSize = new Size(470, y + _btnOk.Height + 16);
        }
    }
}

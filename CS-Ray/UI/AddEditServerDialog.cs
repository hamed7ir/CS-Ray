using System;
using System.Drawing;
using System.Windows.Forms;
using MaterialSkin;
using MaterialSkin.Controls;
using CS_Ray.Core.Config;
using CS_Ray.Core.Protocol;

namespace CS_Ray.UI
{
    /// <summary>
    /// Protocol-adaptive Add/Edit server dialog. A themed MaterialForm (same ThemeHelper dark/light + accent +
    /// Roboto as the main window, per TelegArm's dialog pattern). Shows ONLY the fields the chosen protocol+
    /// transport needs: VLESS/VMess (tcp/ws/xhttp + UUID/SNI/TLS), Shadowsocks (cipher+password), and the plain
    /// SOCKS5/HTTP(S) outbound proxies (address/port + optional user/pass). Produces a <see cref="ProxyProfile"/>
    /// on OK (the SAME model the rest of the app uses); null on Cancel.
    /// </summary>
    public sealed class AddEditServerDialog : MaterialForm
    {
        private const int W = 430;
        private const int FieldX = 24;
        private const int FieldW = W - 48;

        // SS ciphers the engine supports (AEAD only) — same set LinkParser accepts.
        private static readonly string[] SsMethods = { "chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm" };

        private readonly MaterialComboBox _cboProtocol = NewCombo("Protocol");
        private readonly MaterialComboBox _cboNetwork = NewCombo("Network (transport)");
        private readonly MaterialComboBox _cboSsMethod = NewCombo("Encryption (SS method)");
        private readonly MaterialTextBox2 _txtName = NewText("Name (optional — defaults to address)");
        private readonly MaterialTextBox2 _txtAddress = NewText("Address (host or IP)");
        private readonly MaterialTextBox2 _txtPort = NewText("Port");
        private readonly MaterialTextBox2 _txtUuid = NewText("UUID");
        private readonly MaterialTextBox2 _txtAlterId = NewText("AlterId (0 only — AEAD)");
        private readonly MaterialTextBox2 _txtUser = NewText("Username (optional)");
        private readonly MaterialTextBox2 _txtPassword = NewText("Password");
        private readonly MaterialTextBox2 _txtWsHost = NewText("Host (ws/xhttp)");
        private readonly MaterialTextBox2 _txtWsPath = NewText("Path (ws/xhttp)");
        private readonly MaterialTextBox2 _txtSni = NewText("SNI (TLS server name)");
        private readonly MaterialSwitch _swTls = new MaterialSwitch { Text = "TLS", AutoSize = true };
        private readonly MaterialSwitch _swInsecure = new MaterialSwitch { Text = "Allow insecure (skip cert check)", AutoSize = true };
        private readonly MaterialLabel _lblError = new MaterialLabel { AutoSize = false, ForeColor = Color.Firebrick };
        private readonly MaterialLabel _lblNote = new MaterialLabel { AutoSize = false, ForeColor = Color.Firebrick }; // unsupported-server note
        private readonly MaterialButton _btnOk = new MaterialButton { Text = "Save", Type = MaterialButton.MaterialButtonType.Contained, AutoSize = false, Width = 100, Height = 36 };
        private readonly MaterialButton _btnCancel = new MaterialButton { Text = "Cancel", Type = MaterialButton.MaterialButtonType.Outlined, AutoSize = false, Width = 90, Height = 36 };

        private readonly string _editId;     // non-null when editing (keep Id/Group)
        private readonly string _editGroup;
        private readonly bool _unsupported;  // editing a recognized-but-unsupported server → show a read-only note
        private readonly string _noteText;

        /// <summary>The profile produced on OK (null on Cancel).</summary>
        public ProxyProfile Result { get; private set; }

        public AddEditServerDialog(ProxyProfile existing)
        {
            _editId = existing?.Id;
            _editGroup = existing?.Group;
            _unsupported = existing != null && existing.Unsupported;
            _noteText = existing?.UnsupportedReason;

            var skin = MaterialSkinManager.Instance;
            skin.AddFormToManage(this);
            skin.Theme = ThemeHelper.IsDark ? MaterialSkinManager.Themes.DARK : MaterialSkinManager.Themes.LIGHT;
            var accent = (Primary)(uint)ThemeHelper.GetWindowsAccentColor().ToArgb();
            skin.ColorScheme = new ColorScheme(accent, accent, accent, Accent.LightBlue200, TextShade.WHITE);

            Text = existing == null ? "Add Server" : "Edit Server"; // shown in the full accent action bar
            AutoScaleMode = AutoScaleMode.Font;
            Font = FontHelper.Ui(9f);
            StartPosition = FormStartPosition.CenterParent;
            MaximizeBox = false; MinimizeBox = false; Sizable = false;
            KeyPreview = true;
            KeyDown += (s, e) => { if (e.KeyCode == Keys.Escape) { DialogResult = DialogResult.Cancel; Close(); } };

            _cboProtocol.Items.AddRange(new object[] { "vless", "vmess", "shadowsocks", "socks", "http", "https" });
            _cboNetwork.Items.AddRange(new object[] { "tcp", "ws", "xhttp" });
            _cboSsMethod.Items.AddRange(SsMethods);
            _txtPort.Width = 120;

            foreach (var c in new Control[] { _cboProtocol, _cboNetwork, _cboSsMethod, _txtName, _txtAddress,
                _txtPort, _txtUuid, _txtAlterId, _txtUser, _txtPassword, _txtWsPath, _txtWsHost, _txtSni,
                _swTls, _swInsecure, _lblError, _btnOk, _btnCancel })
            { c.Width = c.Width > 0 ? c.Width : FieldW; Controls.Add(c); }
            foreach (var t in new[] { _txtName, _txtAddress, _txtUuid, _txtAlterId, _txtUser, _txtPassword, _txtWsPath, _txtWsHost, _txtSni })
                t.Width = FieldW;
            _txtPort.Width = 120;
            _cboProtocol.Width = _cboNetwork.Width = _cboSsMethod.Width = FieldW;
            _lblError.Width = FieldW;

            _lblNote.Width = FieldW; _lblNote.Visible = _unsupported;
            if (_unsupported) _lblNote.Text = "⚠ " + (_noteText ?? "Unsupported by the managed engine") + " — view only.";
            Controls.Add(_lblNote);

            _cboProtocol.SelectedIndexChanged += (s, e) => Relayout();
            _cboNetwork.SelectedIndexChanged += (s, e) => Relayout();
            _btnOk.Click += OnOk;
            _btnCancel.Click += (s, e) => { DialogResult = DialogResult.Cancel; Close(); };

            if (existing != null) LoadFrom(existing);
            else { _cboProtocol.SelectedIndex = 0; _cboNetwork.SelectedIndex = 0; _cboSsMethod.SelectedIndex = 0; _txtWsPath.Text = "/"; }

            Relayout();
        }

        private string Proto => (_cboProtocol.SelectedItem as string) ?? "vless";
        private string Net => (_cboNetwork.SelectedItem as string) ?? "tcp";

        // MaterialForm reserves its accent action bar via Padding.Top; start content below it (fallback 64 before
        // the handle/padding is known — OnLoad re-runs Relayout once the real value is set).
        private int TopInset => Math.Max(64, Padding.Top);

        protected override void OnLoad(EventArgs e) { base.OnLoad(e); Relayout(); }

        private void Relayout()
        {
            bool vless = Proto == "vless", vmess = Proto == "vmess", ss = Proto == "shadowsocks";
            bool socks = Proto == "socks", http = Proto == "http", https = Proto == "https";
            bool vlessLike = vless || vmess;
            bool proxyLike = socks || http || https;
            bool xhttp = vlessLike && Net == "xhttp";
            bool ws = vlessLike && Net == "ws";
            bool wsOrXhttp = ws || xhttp;

            int y = TopInset + 8; // below the accent action bar
            if (_unsupported) { _lblNote.Location = new Point(FieldX, y); _lblNote.Height = 34; y += 40; }
            Place(_cboProtocol, ref y, 50, true);
            Place(_txtName, ref y, 50, true);
            Place(_txtAddress, ref y, 50, true);
            Place(_txtPort, ref y, 50, true);
            Place(_txtUuid, ref y, 50, vlessLike);
            Place(_txtAlterId, ref y, 50, vmess);
            Place(_cboSsMethod, ref y, 50, ss);
            Place(_txtUser, ref y, 50, proxyLike);                 // socks/http(s): optional auth
            Place(_txtPassword, ref y, 50, ss || proxyLike);       // SS password OR proxy password
            Place(_cboNetwork, ref y, 50, vlessLike);
            Place(_txtWsHost, ref y, 50, wsOrXhttp);
            Place(_txtWsPath, ref y, 50, wsOrXhttp);
            Place(_txtSni, ref y, 50, vlessLike || https);         // vless TLS/xhttp + https-proxy TLS
            Place(_swTls, ref y, 34, vlessLike && !xhttp);         // xhttp implies TLS — hide the toggle
            Place(_swInsecure, ref y, 34, vlessLike || https);

            _lblError.Location = new Point(FieldX, y); _lblError.Height = 24; _lblError.Visible = true; y += 28;
            _btnOk.Location = new Point(W - 24 - _btnOk.Width, y);
            _btnCancel.Location = new Point(_btnOk.Left - 8 - _btnCancel.Width, y);
            y += 48;

            ClientSize = new Size(W, y + 8);
        }

        private static void Place(Control c, ref int y, int h, bool visible)
        {
            c.Visible = visible;
            if (!visible) return;
            c.Location = new Point(FieldX, y);
            y += h;
        }

        private void OnOk(object sender, EventArgs e)
        {
            string err = Validate(out var p);
            if (err != null) { _lblError.Text = err; return; }
            Result = p;
            DialogResult = DialogResult.OK;
            Close();
        }

        private string Validate(out ProxyProfile p)
        {
            p = null;
            string addr = (_txtAddress.Text ?? "").Trim();
            if (addr.Length == 0) return "Address is required.";
            if (!int.TryParse((_txtPort.Text ?? "").Trim(), out int port) || port < 1 || port > 65535)
                return "Port must be a number 1–65535.";

            string proto = Proto;
            string name = (_txtName.Text ?? "").Trim(); if (name.Length == 0) name = addr;
            var prof = new ProxyProfile { Protocol = proto, Server = addr, Port = port, Name = name };

            if (proto == "shadowsocks")
            {
                if ((_txtPassword.Text ?? "").Length == 0) return "Password is required.";
                prof.SsMethod = (_cboSsMethod.SelectedItem as string) ?? SsMethods[0];
                prof.Password = _txtPassword.Text;
                prof.Network = "tcp";
            }
            else if (proto == "socks" || proto == "http" || proto == "https")
            {
                // Plain proxy: address/port required; user/pass optional. https = CONNECT over TLS to the proxy.
                prof.Network = "tcp";
                prof.ProxyUser = (_txtUser.Text ?? "").Trim();
                prof.ProxyPass = _txtPassword.Text ?? "";
                if (proto == "https")
                {
                    prof.UseTls = true;
                    prof.Sni = (_txtSni.Text ?? "").Trim();
                    prof.AllowInsecure = _swInsecure.Checked;
                }
            }
            else // vless / vmess
            {
                string uuid = (_txtUuid.Text ?? "").Trim();
                if (uuid.Length == 0) return "UUID is required.";
                try { VlessProtocol.ParseUuid(uuid); } catch { return "UUID is malformed (need 32 hex / 8-4-4-4-12)."; }
                if (proto == "vmess")
                {
                    if (!int.TryParse((_txtAlterId.Text ?? "0").Trim(), out int aid) || aid != 0)
                        return "Only AlterId 0 (AEAD VMess) is supported.";
                    prof.VmessSecurity = "auto";
                }
                prof.Uuid = uuid;
                prof.Network = Net;
                prof.Sni = (_txtSni.Text ?? "").Trim();
                prof.AllowInsecure = _swInsecure.Checked;
                prof.UseTls = (Net == "xhttp") || _swTls.Checked; // xhttp implies TLS
                if (Net == "ws" || Net == "xhttp")
                {
                    prof.WsPath = string.IsNullOrEmpty(_txtWsPath.Text) ? "/" : _txtWsPath.Text.Trim();
                    prof.WsHost = (_txtWsHost.Text ?? "").Trim();
                }
            }

            prof.Id = _editId ?? prof.Id;     // keep identity when editing
            prof.Group = _editGroup;          // keep group when editing (null → caller assigns Manual)
            p = prof;
            return null;
        }

        private void LoadFrom(ProxyProfile p)
        {
            _cboProtocol.SelectedItem = (p.Protocol ?? "vless").ToLowerInvariant();
            if (_cboProtocol.SelectedIndex < 0) _cboProtocol.SelectedIndex = 0;
            _cboNetwork.SelectedItem = string.IsNullOrEmpty(p.Network) ? "tcp" : p.Network.ToLowerInvariant();
            if (_cboNetwork.SelectedIndex < 0) _cboNetwork.SelectedIndex = 0;
            _cboSsMethod.SelectedItem = p.SsMethod;
            if (_cboSsMethod.SelectedIndex < 0) _cboSsMethod.SelectedIndex = 0;

            _txtName.Text = p.Name;
            _txtAddress.Text = p.Server;
            _txtPort.Text = p.Port.ToString();
            _txtUuid.Text = p.Uuid;
            _txtAlterId.Text = "0";
            _txtUser.Text = p.ProxyUser;
            // Password field is shared: proxy password for socks/http(s), else the SS password.
            _txtPassword.Text = !string.IsNullOrEmpty(p.ProxyPass) ? p.ProxyPass : p.Password;
            _txtWsPath.Text = string.IsNullOrEmpty(p.WsPath) ? "/" : p.WsPath;
            _txtWsHost.Text = p.WsHost;
            _txtSni.Text = p.Sni;
            _swTls.Checked = p.UseTls;
            _swInsecure.Checked = p.AllowInsecure;
        }

        private static MaterialTextBox2 NewText(string hint) => new MaterialTextBox2 { Hint = hint, Width = FieldW };
        private static MaterialComboBox NewCombo(string hint) => new MaterialComboBox { Hint = hint, Width = FieldW };
    }
}

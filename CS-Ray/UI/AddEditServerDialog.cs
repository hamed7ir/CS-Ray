using System;
using System.Drawing;
using System.Windows.Forms;
using CS_Ray.Core.Config;
using CS_Ray.Core.Protocol;

namespace CS_Ray.UI
{
    /// <summary>
    /// Protocol-adaptive Add/Edit server dialog. A <see cref="ThemedDialog"/> (same ThemeHelper dark/light + accent +
    /// Roboto as the main window) with a scrolling body of themed fields and a Save/Cancel footer. Shows ONLY the
    /// fields the chosen protocol+transport needs: VLESS/VMess (tcp/ws/xhttp + UUID/SNI/TLS), Shadowsocks
    /// (cipher+password), and the plain SOCKS5/HTTP(S) outbound proxies (address/port + optional user/pass). Produces
    /// a <see cref="ProxyProfile"/> on OK (the SAME model the rest of the app uses); null on Cancel.
    /// </summary>
    public sealed class AddEditServerDialog : ThemedDialog
    {
        private static int W => DrawHelper.Px(430);
        private static int FieldX => DrawHelper.Px(24);
        private static int FieldW => W - 2 * FieldX;
        private static int Gap => DrawHelper.Px(6);

        // SS ciphers the engine supports (AEAD only) — same set LinkParser accepts.
        private static readonly string[] SsMethods = { "chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm" };

        private readonly ThemedComboBox _cboProtocol = NewCombo("Protocol");
        private readonly ThemedComboBox _cboNetwork = NewCombo("Network (transport)");
        private readonly ThemedComboBox _cboHeader = NewCombo("Header (tcp camouflage)");
        private readonly ThemedComboBox _cboSsMethod = NewCombo("Encryption (SS method)");
        private readonly ThemedTextBox _txtName = NewText("Name (optional — defaults to address)");
        private readonly ThemedTextBox _txtAddress = NewText("Address (host or IP)");
        private readonly ThemedTextBox _txtPort = NewText("Port");
        private readonly ThemedTextBox _txtUuid = NewText("UUID");
        private readonly ThemedTextBox _txtAlterId = NewText("AlterId (0 only — AEAD)");
        private readonly ThemedTextBox _txtUser = NewText("Username (optional)");
        private readonly ThemedTextBox _txtPassword = NewText("Password");
        private readonly ThemedTextBox _txtWsHost = NewText("Host (ws / xhttp / http header; comma-separated for http)");
        private readonly ThemedTextBox _txtWsPath = NewText("Path (ws / xhttp / http header)");
        private readonly ThemedComboBox _cboSecurity = NewCombo("Security");
        private readonly ThemedTextBox _txtSni = NewText("SNI (TLS / REALITY server name)");
        private readonly ThemedTextBox _txtPbk = NewText("REALITY public key (pbk)");
        private readonly ThemedTextBox _txtSid = NewText("REALITY short ID (sid, hex — optional)");
        private readonly ThemedComboBox _cboFp = NewCombo("Fingerprint (fp)");
        private readonly ThemedComboBox _cboFlow = NewCombo("Flow");
        private readonly ToggleSwitch _swInsecure = new ToggleSwitch();
        private readonly Label _lblInsecure = NewToggleLabel("Allow insecure (skip cert check)");
        private readonly Label _lblError = new Label { AutoSize = false, TextAlign = ContentAlignment.MiddleLeft, Font = FontHelper.Ui(9f) };
        private readonly Label _lblNote = new Label { AutoSize = false, TextAlign = ContentAlignment.MiddleLeft, Font = FontHelper.Ui(9f) }; // unsupported-server note
        private readonly RoundedButton _btnOk;
        private readonly RoundedButton _btnCancel;

        private readonly string _editId;     // non-null when editing (keep Id/Group)
        private readonly string _editGroup;
        private readonly bool _unsupported;  // editing a recognized-but-unsupported server → show a read-only note
        private readonly string _noteText;
        private readonly string _keepSpiderX;   // not editable here — carried over so an edit doesn't drop it
        private readonly string _keepXhttpMode, _keepXhttpExtra;

        /// <summary>The profile produced on OK (null on Cancel).</summary>
        public ProxyProfile Result { get; private set; }

        public AddEditServerDialog(ProxyProfile existing) : base(existing == null ? "Add Server" : "Edit Server")
        {
            _editId = existing?.Id;
            _editGroup = existing?.Group;
            _unsupported = existing != null && existing.Unsupported;
            _noteText = existing?.UnsupportedReason;
            _keepSpiderX = existing?.SpiderX;
            _keepXhttpMode = existing?.XhttpMode;
            _keepXhttpExtra = existing?.XhttpExtra;

            KeyPreview = true;
            KeyDown += (s, e) => { if (e.KeyCode == Keys.Escape) { DialogResult = DialogResult.Cancel; Close(); } };

            _cboProtocol.Items.AddRange(new object[] { "vless", "vmess", "shadowsocks", "socks", "http", "https" });
            _cboNetwork.Items.AddRange(new object[] { "tcp", "ws", "xhttp" });
            _cboHeader.Items.AddRange(new object[] { "none", "http" });
            _cboSecurity.Items.AddRange(new object[] { "none", "tls", "reality" });
            _cboFp.Items.AddRange(new object[] { "chrome", "edge", "firefox", "safari", "ios", "android", "random" });
            _cboFlow.Items.AddRange(new object[] { "none", Core.Protocol.VlessProtocol.FlowVision });
            _cboSsMethod.Items.AddRange(SsMethods);

            foreach (var c in new Control[] { _cboProtocol, _cboNetwork, _cboHeader, _cboSsMethod, _txtName, _txtAddress,
                _txtPort, _txtUuid, _txtAlterId, _txtUser, _txtPassword, _txtWsPath, _txtWsHost, _cboSecurity, _txtSni,
                _txtPbk, _txtSid, _cboFp, _cboFlow, _lblInsecure, _swInsecure, _lblError, _lblNote })
            { if (!(c is ToggleSwitch)) c.Width = FieldW; Body.Host.Controls.Add(c); } // switches keep their DPI-scaled size
            _txtPort.Width = DrawHelper.Px(120);
            _swInsecure.TabStop = true;   // keyboard: Tab reaches it, Space flips it
            // The whole toggle row is the tap target (touch): its label flips the switch too.
            _lblInsecure.Click += (s, e) => _swInsecure.Checked = !_swInsecure.Checked;

            _lblNote.Visible = _unsupported;
            if (_unsupported) _lblNote.Text = "⚠ " + (_noteText ?? "Unsupported by the managed engine") + " — view only.";

            _btnOk = AddFooterButton("Save", RoundedButtonKind.Primary);                          // rightmost
            _btnCancel = AddFooterButton("Cancel", RoundedButtonKind.Secondary, DialogResult.Cancel);

            _cboProtocol.SelectedIndexChanged += (s, e) => Relayout();
            _cboNetwork.SelectedIndexChanged += (s, e) => Relayout();
            _cboHeader.SelectedIndexChanged += (s, e) => Relayout();
            _cboSecurity.SelectedIndexChanged += (s, e) => Relayout();
            _cboFlow.SelectedIndexChanged += (s, e) => Relayout();
            _btnOk.Click += OnOk;

            if (existing != null) LoadFrom(existing);
            else
            {
                _cboProtocol.SelectedIndex = 0; _cboNetwork.SelectedIndex = 0; _cboHeader.SelectedIndex = 0; _cboSsMethod.SelectedIndex = 0;
                _cboSecurity.SelectedItem = "tls"; _cboFp.SelectedIndex = 0; _cboFlow.SelectedIndex = 0; _txtWsPath.Text = "/";
            }

            ApplyDialogTheme();
            Relayout();
        }

        private string Proto => (_cboProtocol.SelectedItem as string) ?? "vless";
        private string Net => (_cboNetwork.SelectedItem as string) ?? "tcp";
        private string Hdr => (_cboHeader.SelectedItem as string) ?? "none";
        private string Sec => (_cboSecurity.SelectedItem as string) ?? "tls";
        private string FlowSel => (_cboFlow.SelectedItem as string) ?? "none";

        protected override void ApplyDialogTheme()
        {
            base.ApplyDialogTheme();
            if (_lblError == null) return; // base ctor runs this before the fields exist
            var p = ThemeHelper.Palette();
            foreach (var l in new[] { _lblInsecure, _lblError, _lblNote }) l.BackColor = p.Surface;
            _lblInsecure.ForeColor = p.Text;
            _lblError.ForeColor = _lblNote.ForeColor = p.Error;
        }

        private void Relayout()
        {
            bool vless = Proto == "vless", vmess = Proto == "vmess", ss = Proto == "shadowsocks";
            bool socks = Proto == "socks", http = Proto == "http", https = Proto == "https";
            bool vlessLike = vless || vmess;
            bool proxyLike = socks || http || https;
            bool xhttp = vlessLike && Net == "xhttp";
            bool ws = vlessLike && Net == "ws";
            bool wsOrXhttp = ws || xhttp;
            bool tcp = vlessLike && Net == "tcp";
            bool tcpHttp = tcp && Hdr == "http";          // tcp http-header camouflage uses Host / Path too
            bool reality = vless && ((tcp && !tcpHttp) || xhttp) && Sec == "reality";   // REALITY: VLESS over plain tcp or xhttp
            bool flowable = vless && tcp && !tcpHttp && Sec != "none";      // XTLS Vision: tcp + tls/reality
            bool vision = flowable && FlowSel != "none";

            _tabIndex = 0;
            int y = DrawHelper.Px(10);
            if (_unsupported)
            {
                int noteH = TextRenderer.MeasureText(_lblNote.Text, _lblNote.Font, new Size(FieldW, int.MaxValue), TextFormatFlags.WordBreak).Height + DrawHelper.Px(8);
                _lblNote.SetBounds(FieldX, y, FieldW, noteH); y += noteH + Gap;
            }
            Place(_cboProtocol, ref y, true);
            Place(_txtName, ref y, true);
            Place(_txtAddress, ref y, true);
            Place(_txtPort, ref y, true);
            Place(_txtUuid, ref y, vlessLike);
            Place(_txtAlterId, ref y, vmess);
            Place(_cboSsMethod, ref y, ss);
            Place(_txtUser, ref y, proxyLike);                 // socks/http(s): optional auth
            Place(_txtPassword, ref y, ss || proxyLike);       // SS password OR proxy password
            Place(_cboNetwork, ref y, vlessLike);
            Place(_cboHeader, ref y, tcp);
            Place(_txtWsHost, ref y, wsOrXhttp || tcpHttp);
            Place(_txtWsPath, ref y, wsOrXhttp || tcpHttp);
            Place(_cboSecurity, ref y, vlessLike);              // (xhttp: tls or reality — "none" counts as tls)
            Place(_txtSni, ref y, vlessLike || https);         // vless TLS/REALITY/xhttp + https-proxy TLS
            Place(_txtPbk, ref y, reality);
            Place(_txtSid, ref y, reality);
            Place(_cboFp, ref y, reality || vision);           // our TLS 1.3 hello shape (REALITY, or tls+Vision)
            Place(_cboFlow, ref y, flowable);
            PlaceToggle(_lblInsecure, _swInsecure, ref y, (vlessLike && !reality) || https);   // REALITY authenticates by key

            int errH = Math.Max(DrawHelper.Px(22), _lblError.Font.Height + DrawHelper.Px(6));
            _lblError.SetBounds(FieldX, y, FieldW, errH); _lblError.Visible = true; y += errH + Gap;

            FitToContent(W, y);
        }

        private int _tabIndex;   // Tab follows the on-screen order of the rows Relayout shows

        private void Place(Control c, ref int y, bool visible)
        {
            c.Visible = visible;
            if (!visible) return;
            c.TabIndex = _tabIndex++;
            c.Location = new Point(FieldX, y);
            y += c.Height + Gap;
        }

        // A toggle row: label on the left, switch right-aligned to the field column, row height font-derived.
        private void PlaceToggle(Label lbl, ToggleSwitch sw, ref int y, bool visible)
        {
            lbl.Visible = sw.Visible = visible;
            if (!visible) return;
            sw.TabIndex = _tabIndex++;
            int rowH = Math.Max(DrawHelper.Px(34), Math.Max(sw.Height, lbl.Font.Height) + DrawHelper.Px(10));
            lbl.SetBounds(FieldX, y, FieldW - sw.Width - DrawHelper.Px(8), rowH);
            sw.Location = new Point(FieldX + FieldW - sw.Width, y + (rowH - sw.Height) / 2);
            y += rowH + Gap;
        }

        private void OnOk(object sender, EventArgs e)
        {
            string err = Validate(out var p);
            if (err != null)
            {
                _lblError.Text = err;
                Body.EnsureVisible(_lblError.Top, _lblError.Height); // the row may be below the fold of a capped dialog
                return;
            }
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
                string sec = Net == "xhttp" && Sec == "none" ? "tls" : Sec;   // xhttp needs TLS or REALITY
                prof.UseTls = sec != "none";
                if (proto == "vmess" && (Net != "tcp" || sec != "none"))
                    return "VMess is supported over raw tcp only (security none, optional http header).";
                // Same visibility rule as Relayout: a Flow choice the user can't see doesn't count.
                bool flowable = proto == "vless" && Net == "tcp" && Hdr != "http" && sec != "none";
                string flow = flowable && FlowSel != "none" ? FlowSel : null;
                if (flow != null)
                {
                    prof.Flow = flow;
                    prof.Fingerprint = (_cboFp.SelectedItem as string) ?? "chrome";
                }
                if (sec == "reality")
                {
                    if (proto != "vless") return "REALITY is supported for VLESS only.";
                    if (!((Net == "tcp" && Hdr != "http") || Net == "xhttp")) return "REALITY works over plain tcp or xhttp only (no ws / http header).";
                    string pbk = (_txtPbk.Text ?? "").Trim(), sid = (_txtSid.Text ?? "").Trim();
                    if (Core.Transport.Tls13.RealityConfig.ParsePublicKey(pbk) == null)
                        return "Public key must be the server's X25519 key (43-character base64url, as in pbk=).";
                    if (Core.Transport.Tls13.RealityConfig.ParseShortId(sid) == null)
                        return "Short ID must be 0–16 hex characters (even length).";
                    if (prof.Sni.Length == 0) return "REALITY needs an SNI — one of the server's serverNames.";
                    prof.Reality = true;
                    prof.RealityPublicKey = pbk;
                    prof.RealityShortId = sid;
                    prof.Fingerprint = (_cboFp.SelectedItem as string) ?? "chrome";
                    prof.SpiderX = _keepSpiderX;
                }
                prof.HeaderType = Net == "tcp" && Hdr == "http" ? "http" : null;
                if (Net == "ws" || Net == "xhttp" || prof.HeaderType == "http")
                {
                    prof.WsPath = string.IsNullOrEmpty(_txtWsPath.Text) ? "/" : _txtWsPath.Text.Trim();
                    prof.WsHost = (_txtWsHost.Text ?? "").Trim();
                    if (Net == "xhttp") { prof.XhttpMode = _keepXhttpMode; prof.XhttpExtra = _keepXhttpExtra; }
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
            _cboHeader.SelectedItem = string.Equals(p.HeaderType, "http", StringComparison.OrdinalIgnoreCase) ? "http" : "none";
            if (_cboHeader.SelectedIndex < 0) _cboHeader.SelectedIndex = 0;
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
            _cboSecurity.SelectedItem = p.Reality ? "reality" : p.UseTls ? "tls" : "none";
            _txtPbk.Text = p.RealityPublicKey;
            _txtSid.Text = p.RealityShortId;
            string fp = string.IsNullOrEmpty(p.Fingerprint) ? "chrome" : p.Fingerprint.ToLowerInvariant();
            if (_cboFp.Items.IndexOf(fp) < 0) _cboFp.Items.Add(fp);   // keep an exotic fp (qq, 360, randomized…) as-is
            _cboFp.SelectedItem = fp;
            string fl = string.IsNullOrEmpty(p.Flow) ? "none" : p.Flow;
            if (_cboFlow.Items.IndexOf(fl) < 0) _cboFlow.Items.Add(fl);   // keep an unsupported flow visible as-is
            _cboFlow.SelectedItem = fl;
            _swInsecure.Checked = p.AllowInsecure;
        }

        private static ThemedTextBox NewText(string hint) => new ThemedTextBox { Hint = hint, Width = FieldW };
        private static ThemedComboBox NewCombo(string hint) => new ThemedComboBox { Hint = hint, Width = FieldW };
        private static Label NewToggleLabel(string text)
            => new Label { Text = text, AutoSize = false, TextAlign = ContentAlignment.MiddleLeft, Font = FontHelper.Ui(10f), Cursor = Cursors.Hand };
    }
}

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Drawing;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using MaterialSkin;
using MaterialSkin.Controls;
using CS_Ray.Core;
using CS_Ray.Core.Config;

namespace CS_Ray.UI
{
    /// <summary>
    /// Minimal spike UI: enter VLESS server fields, Start/Stop the engine on
    /// 127.0.0.1:10808, and watch the log. No link parsing / no theming yet.
    /// </summary>
    public class MainForm : MaterialForm
    {
        private MaterialSkinManager _skin;
        private bool _dark;
        private Color _accent;
        private Panel _content;            // all existing controls live here, below the Material title bar
        // Bottom-bar primary controls.
        private readonly ToggleSwitch _chkSystemProxy; // System-proxy on/off (field name kept; now an owner-drawn toggle)
        private readonly ToggleSwitch _chkRouteAll;    // Full-tunnel intent toggle (read by OnTunClick)
        private readonly Button _btnEngine;          // combined Start/Stop engine
        private readonly Button _btnTun;             // combined Start/Stop TUN
        private readonly Button _btnTest;
        private readonly Button _btnTestAll;
        private readonly Button _btnRemove;
        private readonly Button _btnClearLog;
        private readonly Label _lblSlow;
        private readonly TextBox _txtLog;

        // Group tabs: a hidden backing TabControl drives the visible flat strip + all existing group logic.
        private readonly TabControl _tabs;
        private readonly GroupTabStrip _strip;
        private readonly ListBox _listProfiles;
        private readonly Button _btnHamburger;       // ☰ → dropdown menu
        private SettingsPopup _settings;             // lazy; hosts the relocated controls

        // Tray + window/app icons (loaded/cached by IconHelper; the tray icon is resolved from the mode state).
        private NotifyIcon _notifyIcon;
        private ContextMenuStrip _trayMenu;
        private bool _reallyClosing;                 // true = real quit (Exit); ✕ otherwise hides to tray
        private ThemedScrollBar _logScroll, _listScroll;
        private Font _rowFont, _rowFontBold;         // server-list row fonts (kept private — MaterialSkin reassigns Control.Font)
        private string _runningProfileId;            // the profile whose engine is CURRENTLY running (active indicator)
        private bool _swapInProgress;                // hot-swap atomicity guard (drop overlapping requests)
        private string _switchingToId;               // swap target id (drives the transition indicator)
        private TouchScroller _listTouch, _logTouch, _stripTouch; // touch long-press + drag-to-scroll

        // Settings → General tab (created + wired here; re-homed into the popup page). Non-readonly because
        // they're built in BuildSettingsControls().
        private ToggleSwitch _chkVerbose;
        private ToggleSwitch _chkBlockQuic;
        private ToggleSwitch _chkStartup;
        private bool _syncingStartup;        // guards programmatic _chkStartup.Checked writes from the toggle handler

        /// <summary>Set by Program when launched with --startup (HKCU Run-key login) → start minimized to the tray.</summary>
        public bool StartInTray { get; set; }
        private ComboBox _cboDnsResolver;
        private TextBox _txtLink;
        private Button _btnAdd;
        private Button _btnAddServer;
        private TextBox _txtTestUrl;
        private TextBox _txtTunTestIp;
        private Button _btnUdpTest;

        // Settings → Subscriptions tab: add row + per-row management.
        private TextBox _txtSubUrl;
        private Button _btnAddSub;
        private ListBox _listSubs;
        private Button _btnSubUpdate, _btnSubDelete, _btnSubEdit;

        private bool _tunFullTunnel;
        private bool _tunRouting; // routes installed (distinct from adapter existence — adapter is kept alive)
        private readonly Dictionary<string, string> _delay = new Dictionary<string, string>(); // profileId → latency text
        private Core.Tun.TunDevice _tun;
        private Core.Tun.TunNetwork _tunNet;

        private ProxyEngine _engine;
        private int _activeListenPort = 10810; // engine SOCKS/HTTP inbound port the TUN TCP stack bridges to
        private VlessConfig _activeConfig;     // last-started outbound config (used to arm TUN UDP tunneling)
        private readonly Core.Config.ProfileStore _store = new Core.Config.ProfileStore(Core.Config.ProfileStore.DefaultPath);

        // Logging: producers ENQUEUE ONLY (any thread, non-blocking, drop-oldest on overflow); a UI
        // timer drains in batches and applies the policy. The packet/relay path never blocks on logging.
        private readonly ConcurrentQueue<string> _logQueue = new ConcurrentQueue<string>();   // priority (always shown)
        private readonly ConcurrentQueue<string> _floodQueue = new ConcurrentQueue<string>(); // high-frequency (rate-limited)
        private Timer _logTimer;
        public bool FileLogging; // set by Program for --autostart headless runs

        // --- tunable log-management policy ---
        private const int FlushIntervalMs = 300;
        private const int MaxLogChars = 120000;       // hard cap on the TextBox buffer (~120 KB, ARM32-friendly)
        private const int LogTrimToChars = 60000;     // ring-trim target when over cap
        private const int AutoClearTrimStreak = 5;    // consecutive over-cap flushes before one cheap clear-to-tail
        private const int AutoClearTailChars = 8000;
        private const int MaxQueueEntries = 50000;    // drop oldest beyond this (bounds memory under flood)
        private const int MaxDrainPerTick = 5000;
        private const int SlowOnLinesPerSec = 200;    // engage slow mode above this for SlowOnSeconds
        private const int SlowOffLinesPerSec = 60;    // leave slow mode below this for SlowOffSeconds
        private const int SlowOnSeconds = 2;
        private const int SlowOffSeconds = 3;
        private const int SlowSummaryMs = 2000;
        private const int StatsMs = 5000;

        private long _droppedLogs, _floodProduced, _floodWindowBase;
        private long _sumBaseV4, _sumBaseV6, _sumBaseTcp, _sumBaseUdp, _sumBaseIcmp;
        private int _rateWindowStartTick, _lastSlowSummaryTick, _lastStatsTick, _lastRate;
        private int _slowOnCount, _slowOffCount, _overCapStreak;
        private bool _slowMode;

        public MainForm()
        {
            // Load persisted settings (incl. theme) BEFORE any window paints — no flash. (TelegArm pattern.)
            _store.Load();
            ThemeMode tm; if (!Enum.TryParse(_store.ThemeMode ?? "System", true, out tm)) tm = ThemeMode.System;
            ThemeHelper.InitMode(tm);

            // MaterialSkin chrome + theme (TelegArm: AddFormToManage → ApplyTheme; system-DPI + AutoScaleMode.Font).
            _skin = MaterialSkinManager.Instance;
            _skin.AddFormToManage(this);
            ApplyTheme();

            // App/window icon = icon.ico (shared by every form via IconHelper). The tray icon reflects the current
            // mode (idle / system-proxy / full-tunnel) — see ResolveTrayIcon.
            if (IconHelper.App != null) Icon = IconHelper.App;

            AutoScaleMode = AutoScaleMode.Font;
            Font = FontHelper.Ui(9f);
            Text = "CS-Ray";
            ClientSize = new Size(620, 720);
            MinimumSize = new Size(560, 560);
            StartPosition = FormStartPosition.CenterScreen;

            // Hidden backing TabControl drives the visible group strip + ALL existing group logic.
            _tabs = new TabControl { Visible = false };
            _tabs.SelectedIndexChanged += OnTabChanged;
            Controls.Add(_tabs);

            // Build the controls that live in the settings popup (created + wired now; re-homed lazily on open).
            BuildSettingsControls();

            // Content panel under the Material title bar; whole body in Roboto.
            _content = new Panel { Dock = DockStyle.Fill, Font = FontHelper.Ui(9f) };
            Controls.Add(_content);

            // TOP — hamburger + flat group tab strip (HotCornersWin ScaledTabSelector approach).
            var topBar = new Panel { Dock = DockStyle.Top, Height = 48 }; // taller → finger-tappable tabs
            _strip = new GroupTabStrip(FontHelper.Ui(11f, FontStyle.Bold)) { Dock = DockStyle.Fill };
            _strip.BaseTabControl = _tabs;
            _strip.SelectedTabChanged += OnTabChanged; // reliable click signal (hidden _tabs may have no handle)
            _strip.TabRightClicked += OnTabRightClicked; // right-click a sub tab → Update/Remove/Rename menu
            _btnHamburger = new Button { Text = "☰", Dock = DockStyle.Right, Width = 46, FlatStyle = FlatStyle.Flat, Font = FontHelper.Ui(13f) };
            _btnHamburger.FlatAppearance.BorderSize = 0;
            _btnHamburger.Click += OnHamburgerClick;
            topBar.Controls.Add(_strip);         // Fill first
            topBar.Controls.Add(_btnHamburger);  // Right

            // BODY — server list fills.
            _listProfiles = new ListBox { Dock = DockStyle.Fill, IntegralHeight = false, BorderStyle = BorderStyle.None };
            _rowFont = FontHelper.Ui(10.5f);              // a step up from the 9f body font
            _rowFontBold = FontHelper.Ui(10.5f, FontStyle.Bold);
            _listProfiles.Font = _rowFont;
            _listProfiles.DrawMode = DrawMode.OwnerDrawFixed; // owner-draw: active indicator + themed row
            _listProfiles.ItemHeight = Math.Max(44, TextRenderer.MeasureText("Ag", _rowFont).Height + 18); // touch-tall, font-derived (DPI rule)
            _listProfiles.DrawItem += OnDrawProfileRow;
            _listProfiles.SelectedIndexChanged += OnProfileSelected;
            _listProfiles.DoubleClick += OnEditServerDoubleClick;
            _listProfiles.MouseUp += OnProfileRightClick;

            // BOTTOM — control bar (Engine/TUN + toggles + list/log actions) over the docked log.
            // Touch sizing: ~44px-high buttons, larger Roboto on the bar so checkboxes/labels are finger-tappable.
            var bottomRegion = new Panel { Dock = DockStyle.Bottom, Height = 320 };
            var bar = new Panel { Dock = DockStyle.Top, Height = 108, Font = FontHelper.Ui(10.5f) };
            _btnEngine = new RoundedButton { Kind = RoundedButtonKind.Primary, Text = "Start Engine", Left = 8, Top = 8, Width = 128, Height = 44 };
            _btnEngine.Click += OnEngineToggle;
            _btnTun = new RoundedButton { Kind = RoundedButtonKind.Primary, Text = "Start TUN", Left = 144, Top = 8, Width = 110, Height = 44 };
            _btnTun.Click += OnTunClick;
            // Full tunnel + System proxy: two toggle rows STACKED vertically on the right of the bar (label + slider,
            // one below the other — no longer side-by-side checkboxes). Same bound behavior as before.
            // AutoSize labels so the full text ("System proxy") never clips (a fixed width did — and it scales with
            // DPI); the toggles sit in an aligned column to their right.
            var lblFullTunnel = new Label { Text = "Full tunnel", Left = 392, Top = 16, AutoSize = true, Font = FontHelper.Ui(9.5f) };
            _chkRouteAll = new ToggleSwitch { Left = 492, Top = 13 };
            lblFullTunnel.Click += (s, e) => _chkRouteAll.Checked = !_chkRouteAll.Checked;
            var lblSysProxy = new Label { Text = "System proxy", Left = 392, Top = 52, AutoSize = true, Font = FontHelper.Ui(9.5f) };
            _chkSystemProxy = new ToggleSwitch { Left = 492, Top = 49 };
            _chkSystemProxy.CheckedChanged += OnSystemProxyToggle;
            lblSysProxy.Click += (s, e) => _chkSystemProxy.Checked = !_chkSystemProxy.Checked;
            _btnTest = new RoundedButton { Kind = RoundedButtonKind.Secondary, Text = "Test", Left = 8, Top = 58, Width = 84, Height = 42 };
            _btnTest.Click += OnTestClick;
            _btnTestAll = new RoundedButton { Kind = RoundedButtonKind.Secondary, Text = "Test All", Left = 98, Top = 58, Width = 92, Height = 42 };
            _btnTestAll.Click += OnTestAllClick;
            _btnRemove = new RoundedButton { Kind = RoundedButtonKind.Danger, Text = "Remove", Left = 196, Top = 58, Width = 92, Height = 42 };
            _btnRemove.Click += OnRemoveProfile;
            _btnClearLog = new RoundedButton { Kind = RoundedButtonKind.Neutral, Text = "Clear log", Left = 294, Top = 58, Width = 92, Height = 42 };
            _btnClearLog.Click += (s, e) => _txtLog.Clear();
            _lblSlow = new Label { Text = "[SLOW MODE]", ForeColor = Color.Firebrick, Left = 392, Top = 84, AutoSize = true, Visible = false };
            bar.Controls.Add(_btnEngine); bar.Controls.Add(_btnTun);
            bar.Controls.Add(lblFullTunnel); bar.Controls.Add(_chkRouteAll);
            bar.Controls.Add(lblSysProxy); bar.Controls.Add(_chkSystemProxy);
            bar.Controls.Add(_btnTest); bar.Controls.Add(_btnTestAll); bar.Controls.Add(_btnRemove); bar.Controls.Add(_btnClearLog); bar.Controls.Add(_lblSlow);

            _txtLog = new TextBox
            {
                Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.None,
                BackColor = Color.White, BorderStyle = BorderStyle.None, Font = new Font(FontFamily.GenericMonospace, 8.5f)
            };
            var logHost = WrapWithScrollbar(_txtLog, out _logScroll); // self-drawn themed bar (RT 8.1-safe)
            bottomRegion.Controls.Add(logHost);  // Fill first
            bottomRegion.Controls.Add(bar);      // Top → above the log

            // Assemble: Fill (list) first, then Top, then Bottom, so docking resolves predictably.
            var listHost = WrapWithScrollbar(_listProfiles, out _listScroll);
            _content.Controls.Add(listHost);
            _content.Controls.Add(topBar);
            _content.Controls.Add(bottomRegion);

            // Touch: finger drag-to-scroll on both; long-press the list → the per-server menu; tap → select a row.
            _logTouch = new TouchScroller(_txtLog, dy => _logScroll?.ScrollByPixels(dy), null, null);
            _listTouch = new TouchScroller(_listProfiles, dy => _listScroll?.ScrollByPixels(dy), TapSelectRow, LongPressRow);
            // Touch: horizontal swipe to scroll the tab strip; tap selects; long-press → per-sub menu.
            _stripTouch = new TouchScroller(_strip, dx => _strip.TouchPan(dx), p => _strip.TouchTap(p), p => _strip.TouchLongPress(p), horizontal: true);

            _logTimer = new Timer { Interval = FlushIntervalMs };
            _logTimer.Tick += FlushLog;
            _logTimer.Start();

            InitProfiles();
            // FIX 1: apply the persisted Block-QUIC preference (the CheckedChanged handler persists future edits).
            _chkBlockQuic.Checked = _store.BlockQuic;
            Core.Tun.PacketFilter.BlockQuic = _store.BlockQuic;
            UpdateEngineDeps();
            ApplyPanelColors();

            ThemeHelper.StartListening();                  // live OS light/dark follow (System mode)
            ThemeHelper.ThemeChanged += OnSystemThemeChanged;
            FormClosed += (s, e) => { ThemeHelper.ThemeChanged -= OnSystemThemeChanged; ThemeHelper.StopListening(); };

            Resize += (s, e) => { if (WindowState == FormWindowState.Minimized) Hide(); }; // minimize → hide to tray
            SetupTray();

            Shown += (s, e) => PreloadTun(); // create the adapter up front (if elevated) so Start-TUN is instant
            Shown += (s, e) => WarnIfConflicts(!StartInTray); // leak-safety warn; quiet (log-only) on a --startup tray launch
            Shown += (s, e) => { if (StartInTray) HideToTray(); }; // --startup (login): start minimized to the tray
        }

        // Create the controls that live in the settings popup (wired to their existing handlers). They have no
        // parent yet — LayoutSettings() re-homes them into the popup pages the first time it opens.
        private void BuildSettingsControls()
        {
            // ── General tab ──
            _btnAddServer = new RoundedButton { Kind = RoundedButtonKind.Primary, Text = "Add Server…", Width = 130, Height = 28 };
            _btnAddServer.Click += OnAddServerClick;

            _txtLink = new TextBox { Width = 380 };
            _btnAdd = new RoundedButton { Kind = RoundedButtonKind.Secondary, Text = "Add from link", Width = 120, Height = 26 };
            _btnAdd.Click += OnAddFromLink;

            _chkBlockQuic = new ToggleSwitch();
            _chkBlockQuic.CheckedChanged += (s, e) =>
            {
                Core.Tun.PacketFilter.BlockQuic = _chkBlockQuic.Checked;
                _store.BlockQuic = _chkBlockQuic.Checked; _store.Save();   // FIX 1: persist
                Log("QUIC block: " + (_chkBlockQuic.Checked ? "ON" : "OFF"));
            };
            _chkVerbose = new ToggleSwitch();

            // START-AT-LOGIN (Part 3): HKCU Run-key toggle; the REGISTRY is the source of truth (read back into Checked).
            _chkStartup = new ToggleSwitch();
            _syncingStartup = true; _chkStartup.Checked = StartupIsEnabled(); _syncingStartup = false;
            _chkStartup.CheckedChanged += OnStartupToggle;

            _cboDnsResolver = new ComboBox { Width = 130, DropDownStyle = ComboBoxStyle.DropDown };
            _cboDnsResolver.Items.AddRange(new object[] { "8.8.8.8", "1.1.1.1", "9.9.9.9" });
            _cboDnsResolver.Text = "8.8.8.8";
            _cboDnsResolver.TextChanged += (s, e) => ApplyDnsResolver();

            _txtTestUrl = new TextBox { Width = 360 };
            _txtTunTestIp = new TextBox { Width = 200 };
            _btnUdpTest = new RoundedButton { Kind = RoundedButtonKind.Neutral, Text = "UDP test (E1)", Width = 130, Height = 26 };
            _btnUdpTest.Click += OnUdpSelfTestClick;

            // ── Subscriptions tab ──
            _txtSubUrl = new TextBox { Width = 334 };
            _btnAddSub = new RoundedButton { Kind = RoundedButtonKind.Primary, Text = "Add", Width = 90, Height = 26 };
            _btnAddSub.Click += OnAddSub;
            _listSubs = new ListBox { Width = 552, Height = 300, IntegralHeight = false };
            _listSubs.DoubleClick += OnSubRowEdit;
            _btnSubUpdate = new RoundedButton { Kind = RoundedButtonKind.Secondary, Text = "Update", Width = 100, Height = 28 }; _btnSubUpdate.Click += OnSubRowUpdate;
            _btnSubEdit = new RoundedButton { Kind = RoundedButtonKind.Secondary, Text = "Edit…", Width = 100, Height = 28 }; _btnSubEdit.Click += OnSubRowEdit;
            _btnSubDelete = new RoundedButton { Kind = RoundedButtonKind.Danger, Text = "Delete", Width = 100, Height = 28 }; _btnSubDelete.Click += OnSubRowDelete;
        }

        // ── ☰ side DRAWER (TelegArm-style; replaces the old dropdown). A card-width owner-drawn overlay on the left
        // of the content, closed on an outside tap by a pre-dispatch message filter — no full-window snapshot/scrim. ──
        private DrawerMenu _drawer;
        private DrawerOutsideCloser _drawerCloser;

        private void OnHamburgerClick(object sender, EventArgs e) => ShowDrawer();

        private void ShowDrawer()
        {
            if (_drawer != null) { CloseDrawer(); return; } // ☰ again → close (toggle)

            string sub = _engine != null && _activeConfig != null && !string.IsNullOrEmpty(_activeConfig.ServerHost)
                ? "Connected · " + _activeConfig.ServerHost
                : "Not connected";
            string themeName = ThemeHelper.Mode == ThemeMode.System ? "System" : ThemeHelper.Mode == ThemeMode.Light ? "Light" : "Dark";

            var rows = new System.Collections.Generic.List<DrawerMenu.Row>
            {
                DrawerRow("➕", "Add Server…", () => OnAddServerClick(this, EventArgs.Empty)),
                DrawerRow("📋", "Add link from clipboard", OnAddFromClipboard),
                DrawerRow("⟳", "Update All Subscriptions", () => OnUpdateAll(this, EventArgs.Empty)),
                DrawerSep(),
                DrawerRow("⚙", "Settings", OpenSettings),
                DrawerVal("🎨", "Theme", themeName, CycleTheme),
                DrawerRow("ℹ", "About", ShowAbout),
                DrawerSep(),
                DrawerDanger("⏻", "Exit", ExitApp),
            };

            _drawer = new DrawerMenu(ThemeHelper.IsDark, ThemeHelper.GetWindowsAccentColor(), "CS-Ray", sub, rows)
            {
                Bounds = new Rectangle(0, 0, DrawerMenu.CardW, _content.ClientSize.Height)
            };
            _drawer.CloseRequested += () => BeginInvoke((Action)CloseDrawer);
            _content.Controls.Add(_drawer);
            _drawer.BringToFront();
            _drawer.Focus();

            // The narrow drawer can't catch outside taps itself — a pre-dispatch filter closes it on any down that
            // isn't on the drawer or the hamburger.
            if (_drawerCloser == null) { _drawerCloser = new DrawerOutsideCloser(this); Application.AddMessageFilter(_drawerCloser); }
        }

        private void CloseDrawer()
        {
            if (_drawerCloser != null) { try { Application.RemoveMessageFilter(_drawerCloser); } catch { } _drawerCloser = null; }
            var d = _drawer;
            if (d == null) return;
            _drawer = null;
            try { _content.Controls.Remove(d); d.Dispose(); } catch { }
        }

        // Each drawer action closes the drawer first (deferred a tick so the tap fully finishes), then runs.
        private Action WrapDrawer(Action action) => () => BeginInvoke((Action)(() => { CloseDrawer(); action?.Invoke(); }));
        private DrawerMenu.Row DrawerRow(string glyph, string label, Action action)
            => new DrawerMenu.Row { Glyph = glyph, Label = label, Action = WrapDrawer(action) };
        private DrawerMenu.Row DrawerVal(string glyph, string label, string value, Action action)
            => new DrawerMenu.Row { Glyph = glyph, Label = label, Value = value, Action = WrapDrawer(action) };
        private DrawerMenu.Row DrawerDanger(string glyph, string label, Action action)
            => new DrawerMenu.Row { Glyph = glyph, Label = label, IsDanger = true, Action = WrapDrawer(action) };
        private static DrawerMenu.Row DrawerSep() => new DrawerMenu.Row { Separator = true };

        // Theme row cycles System → Light → Dark (the drawer's right value shows the current mode; SetThemeMode
        // persists + re-applies the whole UI live).
        private void CycleTheme()
        {
            ThemeMode next = ThemeHelper.Mode == ThemeMode.System ? ThemeMode.Light
                           : ThemeHelper.Mode == ThemeMode.Light ? ThemeMode.Dark : ThemeMode.System;
            SetThemeMode(next);
        }

        // Pre-dispatch outside-tap detector for the card-width drawer: any mouse/touch DOWN not on the drawer (or the
        // hamburger) closes it. Observe-only (returns false → never consumes the tap → safe for touch gestures).
        private sealed class DrawerOutsideCloser : IMessageFilter
        {
            private const int WM_LBUTTONDOWN = 0x0201, WM_RBUTTONDOWN = 0x0204, WM_NCLBUTTONDOWN = 0x00A1,
                              WM_POINTERDOWN = 0x0246, WM_TOUCH = 0x0240;
            private readonly MainForm _f;
            public DrawerOutsideCloser(MainForm f) { _f = f; }
            public bool PreFilterMessage(ref Message m)
            {
                switch (m.Msg)
                {
                    case WM_LBUTTONDOWN:
                    case WM_RBUTTONDOWN:
                    case WM_NCLBUTTONDOWN:
                    case WM_POINTERDOWN:
                    case WM_TOUCH:
                        var d = _f._drawer;
                        if (d != null && !_f.IsDisposed && m.HWnd != d.Handle
                            && (_f._btnHamburger == null || m.HWnd != _f._btnHamburger.Handle))
                        {
                            try { _f.BeginInvoke((Action)_f.CloseDrawer); } catch { }
                        }
                        break;
                }
                return false; // observe only
            }
        }

        private void AddMenuItem(ContextMenuStrip menu, string text, Action action)
        {
            var item = new ToolStripMenuItem(text) { Font = FontHelper.Ui(9.5f) };
            item.Click += (s, e) => BeginInvoke(action);
            menu.Items.Add(item);
        }

        private void SetThemeMode(ThemeMode mode)
        {
            _store.ThemeMode = mode.ToString(); _store.Save();
            ThemeHelper.SetMode(mode); // raises ThemeChanged → OnSystemThemeChanged re-applies the whole UI
        }

        private void ShowAbout()
        {
            using (var dlg = new AboutDialog()) dlg.ShowDialog(this);
        }

        // Clipboard add, routed by content: share link → Manual server; http(s) → subscription (+fetch).
        private void OnAddFromClipboard()
        {
            string text = "";
            try { text = (Clipboard.GetText() ?? "").Trim(); } catch { }
            if (text.Length == 0) { Log("Clipboard: empty."); return; }
            string lower = text.ToLowerInvariant();
            if (lower.StartsWith("vless://") || lower.StartsWith("vmess://") || lower.StartsWith("ss://"))
            {
                Log("Clipboard: detected share link → adding server.");
                AddServerFromLink(text);
            }
            else if (lower.StartsWith("http://") || lower.StartsWith("https://"))
            {
                Log("Clipboard: detected subscription URL → adding + fetching.");
                var _ = AddSubFromUrl(text);
            }
            else Log("Clipboard: not a recognized link (expected vless:// / vmess:// / ss:// or http(s)://).");
        }

        // ── START-AT-LOGIN (Part 3) — HKCU Run key; the registry is the source of truth. Ported from TelegArm. ──
        private void OnStartupToggle(object sender, EventArgs e)
        {
            if (_syncingStartup) return;
            if (!StartupSetEnabled(_chkStartup.Checked))
            {
                MessageBox.Show(this, "Couldn't update the Windows startup setting — your account may not allow it.",
                    "CS-Ray — Startup", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                _syncingStartup = true; _chkStartup.Checked = StartupIsEnabled(); _syncingStartup = false; // revert to the TRUE state
                return;
            }
            Log("Start-at-login: " + (_chkStartup.Checked ? "ON" : "OFF") + " (HKCU Run key).");
        }

        // The HKCU Run key launches CS-Ray silently at login. This works because the app ships **asInvoker** (see
        // app.manifest): the login launch runs UN-elevated with no UAC — it just sits in the tray (via --startup)
        // until the user starts TUN, at which point on-demand elevation kicks in (ElevateForTun). (Under the old
        // requireAdministrator manifest this was broken — Windows won't silently auto-launch an elevated app from
        // Run.) The toggle writes/reads the key faithfully (registry = source of truth).
        private const string StartupRunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string StartupValueName = "CS-Ray";
        private static bool StartupIsEnabled()
        {
            try { using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(StartupRunKey)) return k != null && k.GetValue(StartupValueName) != null; }
            catch { return false; }
        }
        private static bool StartupSetEnabled(bool on)
        {
            try
            {
                using (var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(StartupRunKey, true) ?? Microsoft.Win32.Registry.CurrentUser.CreateSubKey(StartupRunKey))
                {
                    if (k == null) return false;
                    if (on) k.SetValue(StartupValueName, "\"" + Application.ExecutablePath + "\" --startup");  // overwrite = self-heal a stale path
                    else if (k.GetValue(StartupValueName) != null) k.DeleteValue(StartupValueName, false);      // idempotent
                }
                return true;
            }
            catch { return false; }
        }

        private void OpenSettings()
        {
            if (_settings == null || _settings.IsDisposed) { _settings = new SettingsPopup(); LayoutSettings(_settings); }
            _syncingStartup = true; _chkStartup.Checked = StartupIsEnabled(); _syncingStartup = false; // reflect the registry on (re)open
            RefreshSubsList();
            _settings.Open(this);
        }

        // Fill the popup's General + Subscriptions pages in TelegArm's sectioned style: accent section headers +
        // rounded bordered cards, each a stack of rows (label [+ subtitle] left, a control right). Absolute
        // positions inside the fixed-size scroll pages (no anchors → no reparent-size pitfalls).
        private void LayoutSettings(SettingsPopup pop)
        {
            const int cardW = 548;

            // ── General page ──
            var g = pop.GeneralPage; int y = 12;

            y = SetSection(g, "Servers", y, cardW);
            var serversCard = SetCard(g, y, 2, cardW); y += serversCard.Height + SetSecGap;
            SetRowTitle(serversCard, 0, "Add a server", "Open the add / edit dialog", 130);
            _btnAddServer.Size = new Size(104, 30); SetPlaceRight(serversCard, 0, _btnAddServer, 14);
            _btnAdd.Size = new Size(96, 28);
            _txtLink.SetBounds(16, SetCardPad + SetRowH + (SetRowH - 24) / 2, cardW - 16 - 96 - 14 - 8, 24); serversCard.Controls.Add(_txtLink);
            _btnAdd.Location = new Point(cardW - 96 - 14, SetCardPad + SetRowH + (SetRowH - 28) / 2); serversCard.Controls.Add(_btnAdd);

            y = SetSection(g, "Connection", y, cardW);
            var connCard = SetCard(g, y, 3, cardW); y += connCard.Height + SetSecGap;
            SetToggleRow(connCard, 0, "Block QUIC (UDP 443)", "Optional; QUIC tunnels by default", _chkBlockQuic);
            SetDivider(connCard, 0);
            SetRowTitle(connCard, 1, "DNS resolver", "Forced for tunneled DNS", 150);
            _cboDnsResolver.Width = 120; SetPlaceRight(connCard, 1, _cboDnsResolver, 14);
            SetDivider(connCard, 1);
            SetRowTitle(connCard, 2, "Delay-test URL", null, 270);
            _txtTestUrl.Width = 250; SetPlaceRight(connCard, 2, _txtTestUrl, 14);

            y = SetSection(g, "Startup", y, cardW);
            var startCard = SetCard(g, y, 1, cardW); y += startCard.Height + SetSecGap;
            SetToggleRow(startCard, 0, "Start at login", "Launch minimized to the tray", _chkStartup);

            y = SetSection(g, "Diagnostics", y, cardW);
            var diagCard = SetCard(g, y, 2, cardW); y += diagCard.Height + SetSecGap;
            SetToggleRow(diagCard, 0, "Verbose log", "Per-connection logging (test runs)", _chkVerbose);
            SetDivider(diagCard, 0);
            SetRowTitle(diagCard, 1, "TUN test IP", "Advanced; partial-capture", 220);
            int diY = SetCardPad + SetRowH;
            _btnUdpTest.Size = new Size(96, 28);
            _btnUdpTest.Location = new Point(cardW - 96 - 14, diY + (SetRowH - 28) / 2); diagCard.Controls.Add(_btnUdpTest);
            _txtTunTestIp.SetBounds(cardW - 96 - 14 - 118 - 8, diY + (SetRowH - 24) / 2, 118, 24); diagCard.Controls.Add(_txtTunTestIp);

            SetSpacer(g, y);

            // ── Subscriptions page ──
            var s = pop.SubsPage; int sy = 12;
            sy = SetSection(s, "Add subscription", sy, cardW);
            var addCard = SetCard(s, sy, 1, cardW); sy += addCard.Height + SetSecGap;
            _btnAddSub.Size = new Size(80, 28);
            _txtSubUrl.SetBounds(16, SetCardPad + (SetRowH - 24) / 2, cardW - 16 - 80 - 14 - 8, 24); addCard.Controls.Add(_txtSubUrl);
            _btnAddSub.Location = new Point(cardW - 80 - 14, SetCardPad + (SetRowH - 28) / 2); addCard.Controls.Add(_btnAddSub);

            sy = SetSection(s, "Your subscriptions", sy, cardW);
            _listSubs.SetBounds(16, sy, cardW, 232); _listSubs.BorderStyle = BorderStyle.FixedSingle; s.Controls.Add(_listSubs);
            sy += _listSubs.Height + 10;
            _btnSubUpdate.Size = new Size(100, 30); _btnSubUpdate.Location = new Point(16, sy); s.Controls.Add(_btnSubUpdate);
            _btnSubEdit.Size = new Size(100, 30); _btnSubEdit.Location = new Point(124, sy); s.Controls.Add(_btnSubEdit);
            _btnSubDelete.Size = new Size(100, 30); _btnSubDelete.Location = new Point(232, sy); s.Controls.Add(_btnSubDelete);
            SetSpacer(s, sy + 40);
        }

        // ── Settings sectioned-layout helpers (accent section header + rounded bordered card of rows) ──
        private const int SetCardX = 16, SetRowH = 46, SetCardPad = 6, SetSecGap = 14, SetSecLabelH = 22;

        private int SetSection(Control page, string text, int y, int cardW)
        {
            page.Controls.Add(new Label
            {
                Text = text.ToUpperInvariant(), Location = new Point(SetCardX + 2, y + 4), AutoSize = false,
                Size = new Size(cardW, SetSecLabelH), Tag = "accent", ForeColor = ThemeHelper.GetWindowsAccentColor(),
                BackColor = Color.Transparent, Font = FontHelper.Ui(8.25f, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft
            });
            return y + SetSecLabelH + 4;
        }

        private Panel SetCard(Control page, int y, int rows, int cardW)
        {
            int h = rows * SetRowH + 2 * SetCardPad;
            var card = new Panel { Location = new Point(SetCardX, y), Size = new Size(cardW, h), Tag = "card", BackColor = _dark ? Color.FromArgb(48, 48, 48) : Color.White };
            card.Paint += (s, e) =>
            {
                var gr = e.Graphics; gr.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                using (var pen = new Pen(ThemeHelper.IsDark ? Color.FromArgb(58, 58, 64) : Color.FromArgb(224, 224, 230)))
                using (var pth = DrawHelper.RoundedRect(new Rectangle(0, 0, card.Width - 1, card.Height - 1), 12))
                    gr.DrawPath(pen, pth);
            };
            page.Controls.Add(card);
            return card;
        }

        private void SetRowTitle(Panel card, int row, string title, string subtitle, int rightZone)
        {
            int iy = SetCardPad + row * SetRowH;
            int lw = card.Width - 16 - rightZone;
            card.Controls.Add(new Label { Text = title, Location = new Point(16, subtitle != null ? iy + 6 : iy + (SetRowH - 22) / 2), AutoSize = false, Size = new Size(lw, 22), BackColor = Color.Transparent, Font = FontHelper.Ui(10f), TextAlign = ContentAlignment.MiddleLeft });
            if (subtitle != null)
                card.Controls.Add(new Label { Text = subtitle, Tag = "dim", Location = new Point(16, iy + 27), AutoSize = false, Size = new Size(lw, 16), BackColor = Color.Transparent, Font = FontHelper.Ui(7.75f), TextAlign = ContentAlignment.MiddleLeft });
        }

        private void SetPlaceRight(Panel card, int row, Control ctrl, int margin)
        {
            int iy = SetCardPad + row * SetRowH;
            ctrl.Location = new Point(card.Width - ctrl.Width - margin, iy + (SetRowH - ctrl.Height) / 2);
            card.Controls.Add(ctrl); ctrl.BringToFront();
        }

        private void SetToggleRow(Panel card, int row, string title, string subtitle, ToggleSwitch sw)
        {
            SetRowTitle(card, row, title, subtitle, 64);
            SetPlaceRight(card, row, sw, 16);
            // Touch-friendly: tapping this row's label(s) flips the toggle too (the toggle handles its own click).
            int iy = SetCardPad + row * SetRowH;
            foreach (Control c in card.Controls)
                if (c is Label && c.Top >= iy && c.Top < iy + SetRowH)
                { c.Cursor = Cursors.Hand; c.Click += (s, e) => sw.Checked = !sw.Checked; }
        }

        private void SetDivider(Panel card, int row)
        {
            int dy = SetCardPad + (row + 1) * SetRowH;
            card.Controls.Add(new Panel { Location = new Point(14, dy), Size = new Size(card.Width - 28, 1), Tag = "div", BackColor = _dark ? Color.FromArgb(58, 58, 64) : Color.FromArgb(232, 232, 236) });
        }

        private void SetSpacer(Control page, int y)
        {
            page.Controls.Add(new Panel { Location = new Point(0, y), Size = new Size(4, SetSecGap), BackColor = Color.Transparent });
        }

        // Combined engine button: start when stopped, stop when running. (Inert mid-swap — the swap drives
        // OnStart/OnStop directly; this is only the user entry point.)
        private void OnEngineToggle(object sender, EventArgs e)
        {
            if (_swapInProgress) { Log("Switching, please wait…"); return; }
            if (_engine == null) OnStartClick(sender, e);
            else OnStopClick(sender, e);
        }

        // FIX 3: full-tunnel + system-proxy are intents (preferences) → ALWAYS enabled. Engine button always
        // live. ONLY the TUN button greys until the engine runs (start enables it; stop disables it).
        // This is the single sync point — the tray icon/tooltip update here too, so window + tray never disagree.
        private void UpdateEngineDeps()
        {
            bool on = _engine != null;
            _btnEngine.Text = on ? "Stop Engine" : "Start Engine";
            _btnEngine.Enabled = !_swapInProgress;        // disabled mid-swap (atomicity)
            _btnTun.Enabled = on && !_swapInProgress;
            _listProfiles?.Invalidate(); // repaint the active/switching indicator
            UpdateTray();
        }

        // ── Tray (v2rayN-style): state-driven icon, themed right-click menu, left-click restore ──
        private void SetupTray()
        {
            if (_notifyIcon != null) return;
            _trayMenu = new ThemedContextMenuStrip();
            _trayMenu.Opening += (s, e) => BuildTrayMenu(_trayMenu); // rebuild each open → always LIVE state
            _notifyIcon = new NotifyIcon
            {
                Icon = ResolveTrayIcon() ?? Icon,
                Text = "CS-Ray — stopped",
                Visible = true,
                ContextMenuStrip = _trayMenu
            };
            _notifyIcon.MouseClick += (s, e) => { if (e.Button == MouseButtons.Left) RestoreFromTray(); };
            UpdateTray();
        }

        // Single resolver for the tray icon from the CURRENT combined mode state — precedence: TUN/full-tunnel wins,
        // then system-proxy, else idle. Reads the ACTUAL current state each call (never set blindly per-toggle) so any
        // combination maps to exactly one icon (both on → full-tunnel; TUN off while system-proxy on → system-proxy).
        //   1. TUN / full-tunnel ON       → icon-fulltunnel.ico   (REGARDLESS of system-proxy)
        //   2. system-proxy ON, TUN OFF   → icon-systemproxy.ico
        //   3. otherwise (idle)           → icon.ico
        private Icon ResolveTrayIcon()
        {
            if (_tunRouting) return IconHelper.FullTunnel ?? IconHelper.App;
            if (SystemProxy.IsApplied) return IconHelper.SystemProxy ?? IconHelper.App;
            return IconHelper.App;
        }

        // Called on EVERY state change (engine start/stop via UpdateEngineDeps, system-proxy toggle, TUN start/stop):
        // the ICON comes from ResolveTrayIcon; the tooltip keeps the existing engine-running/stopped behavior.
        private void UpdateTray()
        {
            if (_notifyIcon == null) return;
            var ico = ResolveTrayIcon();
            if (ico != null) _notifyIcon.Icon = ico;
            bool on = _engine != null;
            string srv = _activeConfig != null ? (_activeConfig.ServerHost ?? "") : "";
            _notifyIcon.Text = Trunc(_swapInProgress ? "CS-Ray — switching…"
                : on ? "CS-Ray — engine running: " + srv
                : "CS-Ray — stopped");
        }

        private static string Trunc(string s) => s.Length <= 63 ? s : s.Substring(0, 60) + "…"; // NotifyIcon.Text cap

        // Rebuilt on every open so labels/checks/greying reflect LIVE state; each item calls the SAME handler as
        // the window control → single source of truth (toggling from the tray updates the window and vice-versa).
        private void BuildTrayMenu(ContextMenuStrip menu)
        {
            menu.Items.Clear();
            bool on = _engine != null;
            bool busy = _swapInProgress; // mid-swap → freeze the toggles (atomicity)

            var eng = new ToolStripMenuItem(on ? "Stop Engine" : "Start Engine") { Enabled = !busy, Font = FontHelper.Ui(9.5f) };
            eng.Click += (s, e) => BeginInvoke((Action)(() => OnEngineToggle(this, EventArgs.Empty)));
            menu.Items.Add(eng);

            var tun = new ToolStripMenuItem(_tunRouting ? "Stop TUN" : "Start TUN") { Enabled = on && !busy, Font = FontHelper.Ui(9.5f) };
            tun.Click += (s, e) => BeginInvoke((Action)(() => OnTunClick(this, EventArgs.Empty)));
            menu.Items.Add(tun);

            var proxy = new ToolStripMenuItem("System proxy") { Checked = _chkSystemProxy.Checked, CheckOnClick = false, Enabled = !busy, Font = FontHelper.Ui(9.5f) };
            proxy.Click += (s, e) => BeginInvoke((Action)(() => _chkSystemProxy.Checked = !_chkSystemProxy.Checked)); // → OnSystemProxyToggle
            menu.Items.Add(proxy);

            menu.Items.Add(new ToolStripSeparator());
            AddMenuItem(menu, Visible ? "Hide window" : "Show window", () => { if (Visible) HideToTray(); else RestoreFromTray(); });
            menu.Items.Add(new ToolStripSeparator());
            AddMenuItem(menu, "Exit", ExitApp);
        }

        private void RestoreFromTray()
        {
            Show();
            if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
            Activate();
            BringToFront();
        }

        private void HideToTray() => Hide(); // tray exists from startup

        // The real quit: routes through OnFormClosing's teardown (remove routes, restore DNS/IPv6/default-route).
        private void ExitApp() { _reallyClosing = true; Close(); }

        // First instance: allow the single-instance "surface" message through UIPI so a lower-IL (non-elevated)
        // second launch can reach this elevated window.
        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            SingleInstance.AllowSurfaceMessage(Handle);
        }

        private const int WM_DWMCOLORIZATIONCOLORCHANGED = 0x0320; // fires on 8.1 AND 10/11 when the accent changes

        // A second instance broadcasts SingleInstance.ShowMessage → surface this window (restore from tray, etc.).
        protected override void WndProc(ref Message m)
        {
            if (SingleInstance.ShowMessage != 0 && m.Msg == SingleInstance.ShowMessage)
            {
                try { RestoreFromTray(); } catch { }
                return;
            }
            base.WndProc(ref m);
            // Live accent follow (Part 1.2): WM_DWMCOLORIZATIONCOLORCHANGED is the reliable signal on BOTH 8.1 and
            // 10/11 (SystemEvents' Color category is flaky on 8.1). Don't trust wParam — it's the composed
            // colorization tint, not the picked swatch; NotifyAccentChanged RE-READS the registry, debounces ~300ms,
            // and fans out ThemeChanged → OnSystemThemeChanged repaints the whole UI.
            if (m.Msg == WM_DWMCOLORIZATIONCOLORCHANGED) ThemeHelper.NotifyAccentChanged();
        }

        // Leak-safety: warn (never kill) when another route/DNS-managing proxy app is running. Always logs; the
        // startup call also shows a one-time dialog offering an explicit, GRACEFUL close (skipped when headless).
        private void WarnIfConflicts(bool startup)
        {
            var apps = ConflictScanner.Detect();
            if (apps.Count == 0) return;
            string names = string.Join(", ", apps);
            Log("WARNING: another VPN/proxy app appears to be running (" + names + "). To avoid DNS/IP leaks, close it before connecting with CS-Ray.");
            if (!startup || FileLogging) return; // headless (--autostart) → log only, no modal

            var r = MessageBox.Show(this,
                "Another VPN/proxy app appears to be running:\n\n    " + names +
                "\n\nRunning two route/DNS managers at once can cause DNS/IP leaks.\nClose it before connecting with CS-Ray." +
                "\n\nAttempt to close it gracefully now? (CS-Ray never force-kills.)",
                "CS-Ray — conflicting proxy app", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (r == DialogResult.Yes)
            {
                int n = ConflictScanner.TryGracefulClose();
                Log("Requested graceful close of conflicting app(s) — signaled " + n + " (CloseMainWindow; never killed).");
            }
        }

        // Wrap a ListBox/TextBox with a self-drawn themed scrollbar (TelegArm attach pattern: target Fill, bar Right).
        private Panel WrapWithScrollbar(Control target, out ThemedScrollBar bar)
        {
            target.Dock = DockStyle.Fill;
            var host = new Panel { Dock = DockStyle.Fill, BackColor = target.BackColor };
            bar = new ThemedScrollBar(target, _dark, _accent) { Dock = DockStyle.Right };
            host.Controls.Add(target); // Fill — add first so it docks last, taking the leftover width
            host.Controls.Add(bar);    // Right strip
            return host;
        }

        // ── Theme (TelegArm pattern: resolve via ThemeHelper, push into MaterialSkin + re-color body controls) ──
        private void ApplyTheme()
        {
            _dark = ThemeHelper.IsDark;                       // System → OS, else the override
            _accent = ThemeHelper.GetWindowsAccentColor();
            _skin.Theme = _dark ? MaterialSkinManager.Themes.DARK : MaterialSkinManager.Themes.LIGHT;
            var primary = (Primary)(uint)_accent.ToArgb();   // map the Windows accent to MaterialSkin primary
            // Singleton-trap fix: the MaterialSkin Accent slot (MaterialTextBox underline / floating hint) must be
            // the SAME Windows accent — NOT the hardcoded Accent.LightBlue200 that any dialog re-poisoned it with.
            _skin.ColorScheme = new ColorScheme(primary, primary, primary, (Accent)(uint)_accent.ToArgb(), TextShade.WHITE);
        }

        // MaterialSkin themes its own chrome + Material* controls; our plain WinForms body controls don't
        // auto-theme, so re-color the body to match dark/light (shared with the hamburger popup).
        private void ApplyPanelColors()
        {
            if (_content == null) return;
            ThemeHelper.RecolorBody(_content);
            if (_lblSlow != null) _lblSlow.ForeColor = Color.Firebrick; // keep the warning color
            _strip?.Invalidate();                                       // owner-painted strip reads the new skin
            _listProfiles?.Invalidate();                                // owner-drawn rows read the new dark/accent
            foreach (var bar in new[] { _logScroll, _listScroll })      // self-drawn scrollbars follow the theme
                if (bar != null) { bar.IsDark = _dark; bar.AccentColor = _accent; bar.Invalidate(); }
        }

        // Theme is now chosen from the ☰ Theme▸ submenu (see SetThemeMode); ThemeChanged → OnSystemThemeChanged.

        // Re-apply on OS theme/accent change (System mode) or a manual switch. BeginInvoke → UI thread; full
        // repaint avoids the classic MaterialSkin half-repaint after a theme flip (TelegArm fix).
        private void OnSystemThemeChanged()
        {
            if (IsDisposed) return;
            try { BeginInvoke((Action)(() => { ApplyTheme(); ApplyPanelColors(); Invalidate(true); })); }
            catch { }
        }

        // Create the wintun adapter + read loop at startup so "Start TUN" only installs routes (fast, no freeze).
        private void PreloadTun()
        {
            if (_tun != null) return;
            if (!IsElevated()) { Log("TUN: running un-elevated — adapter pre-load skipped (elevation is requested on demand when you start TUN)."); return; }
            var tun = new Core.Tun.TunDevice(Log, LogFlood);
            if (tun.Start()) { tun.BeginReading(); _tun = tun; Log("TUN: adapter pre-loaded, ready."); }
        }

        // Parse the resolver box ("8.8.8.8") to a host-order uint and push it to PacketFilter. Bad input keeps
        // the last good value (default 8.8.8.8) so Leak-proof DNS always has a reachable public resolver.
        private void ApplyDnsResolver()
        {
            var t = (_cboDnsResolver?.Text ?? "").Trim();
            if (System.Net.IPAddress.TryParse(t, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var b = ip.GetAddressBytes();
                uint v = (uint)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
                if (v != Core.Tun.PacketFilter.DnsResolver) { Core.Tun.PacketFilter.DnsResolver = v; Log("DNS resolver set to " + t + " (used when Leak-proof DNS is ON)."); }
            }
        }

        // Arm TUN UDP tunneling: every captured UDP datagram opens a per-destination VLESS UDP session
        // through the server (E2). Only VLESS carries UDP today (VMess UDP arrives in E4); for any other
        // protocol the factory is cleared so UDP is dropped (never relayed direct = no leak).
        private void ArmUdpOutbound()
        {
            var cfg = _activeConfig;
            string proto = cfg != null ? (cfg.Protocol ?? "").Trim().ToLowerInvariant() : "";
            string net = cfg != null ? (cfg.Network ?? "").Trim().ToLowerInvariant() : "";
            bool xhttp = net == "xhttp" || net == "splithttp";
            try
            {
                if (proto == "vless" && xhttp)
                {
                    // VlessUdpSession is tcp/ws-only; over xhttp, leave UDP unarmed → DNS rides DNS-over-TCP
                    // through the engine (xhttp-aware), non-DNS UDP drops (apps fall back to TCP).
                    _tun.SetUdpOutboundFactory(null);
                    Log("TUN UDP: VLESS-over-XHTTP — DNS tunnels via engine (TCP); non-DNS UDP dropped.");
                }
                else if (proto == "vless")
                {
                    var uuid = Core.Protocol.VlessProtocol.ParseUuid(cfg.Uuid);
                    _tun.SetUdpOutboundFactory(() => new Core.Protocol.VlessUdpSession(cfg, uuid));
                    Log("TUN UDP: VLESS UDP tunneling armed (per-destination sessions).");
                }
                else if (proto == "vmess")
                {
                    var uuid = Core.Protocol.VlessProtocol.ParseUuid(cfg.VmessId);
                    _tun.SetUdpOutboundFactory(() => new Core.Protocol.Vmess.VMessUdpSession(cfg, uuid));
                    Log("TUN UDP: VMess UDP tunneling armed (per-destination sessions).");
                }
                else
                {
                    _tun.SetUdpOutboundFactory(null);
                    Log("TUN UDP: " + (proto == "" ? "no profile" : proto) + " has no native UDP — non-DNS UDP dropped (DNS still tunnels via engine).");
                }
            }
            catch (Exception ex)
            {
                _tun.SetUdpOutboundFactory(null);
                Log("TUN UDP: could not arm " + proto + " UDP (" + ex.Message + ") — UDP will be dropped.");
            }
        }

        private bool EnsureTunAdapter()
        {
            if (_tun != null) return true;
            var tun = new Core.Tun.TunDevice(Log, LogFlood);
            if (!tun.Start()) return false; // TunDevice logged why (e.g. needs administrator)
            tun.BeginReading();
            _tun = tun;
            Log("TUN: adapter created.");
            return true;
        }

        private static bool IsElevated()
        {
            try
            {
                using (var id = System.Security.Principal.WindowsIdentity.GetCurrent())
                    return new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        private sealed class Row
        {
            public ProxyProfile Profile;
            public string Latency; // last delay-test result (e.g. "182ms" / "timeout"), shown inline
            public override string ToString()
                => (string.IsNullOrEmpty(Profile.Name) ? Profile.Server : Profile.Name)
                   + "  (" + Profile.Protocol + ", " + Profile.Network + ")"
                   + (string.IsNullOrEmpty(Latency) ? "" : "  — " + Latency);
        }

        // Owner-draw a server row: themed background, accent selection highlight, and a DISTINCT active marker
        // (left accent bar + dot, bold text) for the server whose engine is currently running. Selection and
        // active are independent — _runningProfileId is the single source (set in OnStart/OnStop).
        private void OnDrawProfileRow(object sender, DrawItemEventArgs e)
        {
            if (e.Index < 0 || e.Index >= _listProfiles.Items.Count) return;
            var row = (Row)_listProfiles.Items[e.Index];
            var g = e.Graphics;
            bool selected = (e.State & DrawItemState.Selected) != 0;
            bool unsupported = row.Profile.Unsupported;
            bool active = !unsupported && _runningProfileId != null && row.Profile.Id == _runningProfileId;
            bool switching = !unsupported && _swapInProgress && _switchingToId != null && row.Profile.Id == _switchingToId;

            Color listBg = _dark ? Color.FromArgb(60, 60, 60) : Color.White;
            Color fg = _dark ? Color.Gainsboro : Color.Black;
            Color dimFg = _dark ? Color.FromArgb(125, 125, 125) : Color.FromArgb(155, 155, 155); // unsupported (greyed)
            Color selBg = Blend(_accent, listBg, 0.32f);          // muted accent → distinct from the solid active bar
            Color selFg = _dark ? Color.White : Color.Black;
            Color amber = Color.FromArgb(230, 160, 30);           // transition (switching) marker

            using (var b = new SolidBrush(selected ? selBg : listBg)) g.FillRectangle(b, e.Bounds);

            int textX = e.Bounds.X + 10;
            Color marker = active ? _accent : (switching ? amber : Color.Empty);
            if (marker != Color.Empty)
            {
                using (var ab = new SolidBrush(marker)) g.FillRectangle(ab, e.Bounds.X, e.Bounds.Y, 4, e.Bounds.Height);
                int d = 9, cy = e.Bounds.Y + (e.Bounds.Height - d) / 2;
                var sm = g.SmoothingMode; g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                using (var ab = new SolidBrush(marker)) g.FillEllipse(ab, e.Bounds.X + 9, cy, d, d);
                g.SmoothingMode = sm;
                textX = e.Bounds.X + 26;
            }

            string text = row.ToString();
            if (unsupported) text += "   ⚠ " + (row.Profile.UnsupportedReason ?? "unsupported");
            else if (switching) text += "   — switching…";
            Color textColor = selected ? selFg : (unsupported ? dimFg : fg);
            var textRect = new Rectangle(textX, e.Bounds.Y, e.Bounds.Right - textX - 6, e.Bounds.Height);
            TextRenderer.DrawText(g, text, (active || switching) ? _rowFontBold : _rowFont, textRect,
                textColor,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        }

        private static Color Blend(Color a, Color b, float t)
            => Color.FromArgb((int)(a.R * t + b.R * (1 - t)), (int)(a.G * t + b.G * (1 - t)), (int)(a.B * t + b.B * (1 - t)));

        // Per-server right-click (mouse): open the themed menu at the click point.
        private void OnProfileRightClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right) ShowProfileMenuAt(e.Location);
        }

        // Touch tap → select the row under the finger (mouse selection path is suppressed for touch).
        private void TapSelectRow(Point pt)
        {
            int idx = _listProfiles.IndexFromPoint(pt);
            if (idx >= 0) { _listProfiles.SelectedIndex = idx; try { _listProfiles.Focus(); } catch { } }
        }

        // Touch long-press → the same per-server menu as mouse right-click.
        private void LongPressRow(Point pt) => ShowProfileMenuAt(pt);

        // Select the row at the point (so Set-active/Test/Edit/Remove target it), then show the themed menu there.
        private void ShowProfileMenuAt(Point pt)
        {
            int idx = _listProfiles.IndexFromPoint(pt);
            if (idx < 0) return;
            _listProfiles.SelectedIndex = idx;
            var p = SelectedProfile();
            if (p == null) return;

            var menu = new ThemedContextMenuStrip();
            AddMenuItem(menu, "Set as active", () => SetActiveServer(p));
            AddMenuItem(menu, "Test", () => OnTestClick(this, EventArgs.Empty));
            AddMenuItem(menu, "Edit…", () => OnEditServerDoubleClick(this, EventArgs.Empty));
            menu.Items.Add(new ToolStripSeparator());
            AddMenuItem(menu, "Remove", () => OnRemoveProfile(this, EventArgs.Empty));
            menu.Closed += (s, ev) => BeginInvoke((Action)menu.Dispose);
            menu.Show(_listProfiles, pt);
        }

        // "Set as active" — swap-aware. Nothing running → select + persist the start target. Running → hot-swap.
        private void SetActiveServer(ProxyProfile p)
        {
            if (p == null) return;
            if (p.Unsupported) { Log("Can't activate " + LabelOf(p) + " — " + p.UnsupportedReason); return; }
            if (_swapInProgress) { Log("Switching, please wait…"); return; }

            if (_engine == null)
            {
                SelectProfile(p);
                _store.ActiveProfileId = p.Id; _store.Save();
                Log("Set as active: " + LabelOf(p) + " — will start when you click Start Engine.");
                return;
            }
            if (_runningProfileId == p.Id)
            {
                SelectProfile(p);
                Log("Already connected to " + LabelOf(p) + ".");
                return;
            }
            var _ = SwapToAsync(p); // engine is up → hot-swap (Branch A or B)
        }

        // Hot-swap to a different server while connected. Validates the NEW server first (current tunnel stays
        // intact on failure), then ORCHESTRATES the existing stop/start handlers sequentially — TUN teardown is
        // synchronous inside OnStopClick, so it FULLY completes (loop-guard /32 + capture routes removed, DNS/
        // IPv6/default-route restored) before the new server's bring-up begins. Atomic via _swapInProgress.
        private async Task SwapToAsync(ProxyProfile target)
        {
            _swapInProgress = true;
            _switchingToId = target.Id;
            bool wasFullTunnel = _tunRouting;       // Branch B if TUN was up; else Branch A
            bool wasRouteAll = _chkRouteAll.Checked;
            bool wasProxy = _chkSystemProxy.Checked;
            string fromLabel = CurrentRunningLabel();
            UpdateEngineDeps();                     // disable buttons + tray "switching…" + transition indicator
            Log("Switching to " + LabelOf(target) + " — validating…");
            try
            {
                // 1) VALIDATE the new server with a throwaway probe (read-only; never tears the running tunnel).
                DelayResult res;
                try { res = await Core.DelayTester.TestAsync(target.ToEngineConfig(), EffectiveTestUrl(), System.Threading.CancellationToken.None); }
                catch (Exception ex) { res = new DelayResult { Ok = false, Error = ex.Message }; }
                if (!res.Ok)
                {
                    Log(LabelOf(target) + " unreachable (" + res.Error + ") — staying on " + fromLabel + ". (Nothing was torn down.)");
                    return; // current tunnel fully intact
                }

                // 2) TEAR DOWN current — OnStopClick stops TUN (full, synchronous netsh) THEN the engine.
                Log("Validated (" + res.TotalMs + "ms). Tearing down " + fromLabel + "…");
                await Task.Delay(40); // let the UI paint the switching state + flush the log between phases
                OnStopClick(this, EventArgs.Empty); // returns only AFTER routes/DNS/adapter are restored
                await Task.Delay(40);

                // 3) SWITCH the active selection + persist as the start target.
                SelectProfile(target);
                _store.ActiveProfileId = target.Id; _store.Save();

                // 4) START the engine on the new server.
                OnStartClick(this, EventArgs.Empty);
                if (_engine == null)
                {
                    Log("Switch failed: engine did not start on " + LabelOf(target) + ". Stopped cleanly (no routes installed).");
                    return;
                }
                await Task.Delay(40);

                // 5) Re-apply intents on the new server: system proxy (same local port), then full tunnel if it was up.
                if (wasProxy && !_chkSystemProxy.Checked) _chkSystemProxy.Checked = true; // → OnSystemProxyToggle

                if (wasFullTunnel)
                {
                    _chkRouteAll.Checked = wasRouteAll;
                    Log("Bringing up TUN on " + LabelOf(target) + "…");
                    await Task.Delay(40);
                    OnTunClick(this, EventArgs.Empty); // full bring-up on the NEW server (old /32 already removed)
                    await Task.Delay(40);
                    if (!_tunRouting)
                    {
                        // Bring-up failed/aborted → end in a CLEAN, defined state (fully stopped, routes restored).
                        OnStopClick(this, EventArgs.Empty);
                        Log("Switch failed during TUN bring-up — stopped cleanly (routes/DNS/adapter restored; no stale routes).");
                        return;
                    }
                }
                Log("Switched to " + LabelOf(target) + ".");
            }
            catch (Exception ex)
            {
                Log("Swap error: " + ex.Message + " — stopping cleanly.");
                try { OnStopClick(this, EventArgs.Empty); } catch { }
            }
            finally
            {
                _swapInProgress = false;
                _switchingToId = null;
                UpdateEngineDeps(); // re-enable buttons, move the indicator to the new running server, refresh tray
            }
        }

        // Show the profile's group tab and select its row (so OnStartClick's SelectedProfile() returns it).
        private void SelectProfile(ProxyProfile p)
        {
            if (p == null) return;
            SelectTabByTag(ProfileStore.GroupOf(p));
            for (int i = 0; i < _listProfiles.Items.Count; i++)
                if (((Row)_listProfiles.Items[i]).Profile.Id == p.Id) { _listProfiles.SelectedIndex = i; return; }
        }

        private string CurrentRunningLabel()
        {
            var p = _runningProfileId != null ? _store.GetById(_runningProfileId) : null;
            return p != null ? LabelOf(p) : "current server";
        }

        private const string AllTag = "__all__";

        private void InitProfiles()
        {
            if (!string.IsNullOrEmpty(Core.Config.ProfileStore.ResolutionInfo)) Log(Core.Config.ProfileStore.ResolutionInfo);
            _store.Load();
            _txtTestUrl.Text = string.IsNullOrEmpty(_store.DelayTestUrl) ? Core.DelayTester.DefaultUrl : _store.DelayTestUrl;
            RefreshGroups();
            if (!string.IsNullOrEmpty(_store.ActiveProfileId))
            {
                for (int i = 0; i < _listProfiles.Items.Count; i++)
                {
                    if (((Row)_listProfiles.Items[i]).Profile.Id == _store.ActiveProfileId)
                    {
                        _listProfiles.SelectedIndex = i; // loads it into the fields
                        break;
                    }
                }
            }
        }

        // Rebuild the (hidden) group model — All / Manual / one per subscription — preserving the active tab.
        // The visible GroupTabStrip is bound to _tabs and repaints itself; the standalone list is then refreshed.
        private void RefreshGroups()
        {
            string activeTag = _tabs.SelectedTab?.Tag as string;
            _tabs.SelectedIndexChanged -= OnTabChanged;  // suppress events during rebuild
            _tabs.TabPages.Clear();
            // Tab title carries per-group state: server count now; C4 will append an active-server / health
            // indicator here (e.g. a "● <exit>" or colored dot) once live connection state is tracked.
            _tabs.TabPages.Add(new TabPage("All (" + _store.Profiles.Count + ")") { Tag = AllTag });
            _tabs.TabPages.Add(new TabPage("Manual (" + GroupCount(ProfileStore.ManualGroup) + ")") { Tag = ProfileStore.ManualGroup });
            foreach (var s in _store.Subscriptions)
            {
                string title = (string.IsNullOrEmpty(s.Name) ? s.Url : s.Name) + " (" + GroupCount(s.Id) + ")";
                _tabs.TabPages.Add(new TabPage(title) { Tag = s.Id });
            }

            int idx = 0;
            if (activeTag != null)
                for (int i = 0; i < _tabs.TabPages.Count; i++)
                    if ((_tabs.TabPages[i].Tag as string) == activeTag) { idx = i; break; }
            _tabs.SelectedIndex = idx;
            _tabs.SelectedIndexChanged += OnTabChanged;

            _strip?.Invalidate(); // strip reads _tabs.TabPages — redraw the new titles/counts
            RefreshProfileList();
        }

        private int GroupCount(string groupId)
        {
            int n = 0;
            foreach (var p in _store.Profiles)
                if (string.Equals(ProfileStore.GroupOf(p), groupId, StringComparison.OrdinalIgnoreCase)) n++;
            return n;
        }

        private void OnTabChanged(object sender, EventArgs e)
        {
            _strip?.Invalidate(); // reflect the selection in the strip
            RefreshProfileList();
        }

        private void SelectTabByTag(string tag)
        {
            for (int i = 0; i < _tabs.TabPages.Count; i++)
                if ((_tabs.TabPages[i].Tag as string) == tag)
                {
                    _tabs.SelectedIndex = i;
                    _strip?.EnsureSelectedVisible(); // scroll the chosen tab into view
                    _strip?.Invalidate();
                    RefreshProfileList(); // hidden _tabs may not fire SelectedIndexChanged — refresh explicitly
                    break;
                }
        }

        // Servers visible in the current tab (All = everything; otherwise the tab's group).
        private List<ProxyProfile> ProfilesInCurrentTab()
        {
            string tag = _tabs.SelectedTab?.Tag as string ?? AllTag;
            var list = new List<ProxyProfile>();
            foreach (var p in _store.Profiles)
                if (tag == AllTag || string.Equals(ProfileStore.GroupOf(p), tag, StringComparison.OrdinalIgnoreCase))
                    list.Add(p);
            return list;
        }

        private void RefreshProfileList()
        {
            var selectedId = SelectedProfile()?.Id;
            _listProfiles.BeginUpdate();
            _listProfiles.Items.Clear();
            foreach (var p in ProfilesInCurrentTab())
                _listProfiles.Items.Add(new Row { Profile = p, Latency = _delay.TryGetValue(p.Id, out var d) ? d : null });
            _listProfiles.EndUpdate();
            if (selectedId != null)
            {
                for (int i = 0; i < _listProfiles.Items.Count; i++)
                    if (((Row)_listProfiles.Items[i]).Profile.Id == selectedId) { _listProfiles.SelectedIndex = i; break; }
            }
            _listScroll?.NotifyTargetChanged(); // refresh themed bar + re-hide native after refill
        }

        private ProxyProfile SelectedProfile()
            => _listProfiles.SelectedItem is Row r ? r.Profile : null;

        // Selection no longer mirrors into inline fields (removed in C2b) — the engine reads the selected
        // profile at Start time, and double-click opens it in the Add/Edit dialog.
        private void OnProfileSelected(object sender, EventArgs e) { }

        private void OnAddFromLink(object sender, EventArgs e) => AddServerFromLink(_txtLink.Text);

        // Parse a vless/vmess/ss share link → save into Manual → select it. Shared by the "Add from link" box
        // and the ☰ "Add link from clipboard" action.
        private void AddServerFromLink(string link)
        {
            var result = Core.Config.LinkParser.Parse(link);
            if (!result.Ok) { Log("Parse error: " + result.Error); return; }
            result.Profile.Group = ProfileStore.ManualGroup; // hand-added → Manual group
            var saved = _store.AddOrUpdate(result.Profile);
            RefreshGroups();
            SelectTabByTag(ProfileStore.ManualGroup); // show it where it lives
            for (int i = 0; i < _listProfiles.Items.Count; i++)
                if (((Row)_listProfiles.Items[i]).Profile.Id == saved.Id) { _listProfiles.SelectedIndex = i; break; }
            Log("Saved profile: " + (string.IsNullOrEmpty(saved.Name) ? saved.Server : saved.Name) +
                " (" + saved.Protocol + ", " + saved.Network + ") → Manual. " + _store.Profiles.Count + " profile(s).");
        }

        // ── Add/Edit server via the adaptive dialog (parallel to the inline fields; goes to Manual) ──
        private void OnAddServerClick(object sender, EventArgs e)
        {
            using (var dlg = new AddEditServerDialog(null))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK || dlg.Result == null) return;
                dlg.Result.Group = ProfileStore.ManualGroup;
                var saved = _store.AddOrUpdate(dlg.Result);
                RefreshGroups();
                SelectTabByTag(ProfileStore.ManualGroup);
                for (int i = 0; i < _listProfiles.Items.Count; i++)
                    if (((Row)_listProfiles.Items[i]).Profile.Id == saved.Id) { _listProfiles.SelectedIndex = i; break; }
                Log("Added server: " + LabelOf(saved) + " (" + saved.Protocol + ") → Manual.");
            }
        }

        private void OnEditServerDoubleClick(object sender, EventArgs e)
        {
            var p = SelectedProfile();
            if (p == null) return;
            using (var dlg = new AddEditServerDialog(p))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK || dlg.Result == null) return;
                dlg.Result.Id = p.Id;        // edit in place
                dlg.Result.Group = p.Group;  // keep its group (Manual or a sub)
                dlg.Result.Unsupported = p.Unsupported;             // editing host/port can't make it runnable
                dlg.Result.UnsupportedReason = p.UnsupportedReason;
                _store.Update(dlg.Result);
                RefreshGroups();
                for (int i = 0; i < _listProfiles.Items.Count; i++)
                    if (((Row)_listProfiles.Items[i]).Profile.Id == p.Id) { _listProfiles.SelectedIndex = i; break; }
                Log("Updated server: " + LabelOf(dlg.Result) + ".");
            }
        }

        // ── Subscriptions ──────────────────────────────────────────────────────────────────────────────────
        // One row in the Settings → Subscriptions list (name + URL + server count).
        private sealed class SubRow
        {
            public Subscription Sub;
            public int Count;
            public override string ToString()
                => (string.IsNullOrEmpty(Sub.Name) ? Sub.Url : Sub.Name) + "  —  " + Sub.Url + "  (" + Count + " server" + (Count == 1 ? "" : "s") + ")";
        }

        // Add-row in the Subscriptions tab → fetch + install.
        private async void OnAddSub(object sender, EventArgs e)
        {
            var url = (_txtSubUrl.Text ?? "").Trim();
            if (url.Length == 0) { Log("Enter a subscription URL."); return; }
            _btnAddSub.Enabled = false;
            await AddSubFromUrl(url);
            _txtSubUrl.Clear();
            _btnAddSub.Enabled = true;
        }

        // Shared by the add-row and the ☰ "Add link from clipboard". Failure-safe: only commits after a good fetch.
        private async Task AddSubFromUrl(string url)
        {
            url = (url ?? "").Trim();
            if (url.Length == 0) { Log("Enter a subscription URL."); return; }
            Log("Sub: fetching " + url + " …");
            var res = await Core.Config.SubscriptionFetcher.FetchAsync(url, _activeListenPort, _engine != null, Log);
            if (!res.Ok) { Log("Sub: add FAILED — " + res.Error); return; }
            var sub = _store.AddSubscription(DeriveSubName(url), url);
            _store.ReplaceGroup(sub.Id, res.Profiles);
            Log("Sub: added '" + sub.Name + "' — " + res.Profiles.Count + " server(s) via " + res.Path + ".");
            RefreshGroups();
            RefreshSubsList();
            SelectTabByTag(sub.Id);
        }

        // ☰ menu "Update All Subscriptions" (global action — no single target).
        private async void OnUpdateAll(object sender, EventArgs e)
        {
            var subs = new List<Subscription>(_store.Subscriptions);
            if (subs.Count == 0) { Log("No subscriptions to update."); return; }
            foreach (var s in subs) await UpdateOneSub(s);
            RefreshSubsList();
        }

        // Failure-safe: only replace the group's servers AFTER a successful fetch+decode; on failure keep them.
        private async Task UpdateOneSub(Subscription sub)
        {
            if (sub == null) return;
            Log("Sub: updating '" + sub.Name + "' …");
            var res = await Core.Config.SubscriptionFetcher.FetchAsync(sub.Url, _activeListenPort, _engine != null, Log);
            if (!res.Ok) { Log("Sub: update '" + sub.Name + "' FAILED — " + res.Error + " (existing servers kept)."); return; }
            _store.ReplaceGroup(sub.Id, res.Profiles);
            Log("Sub: '" + sub.Name + "' updated — " + res.Profiles.Count + " server(s) via " + res.Path + ".");
            RefreshProfileList();
            RefreshSubsList();
        }

        // Remove a subscription + its servers (shared by the row Delete and the tab right-click).
        private void RemoveSub(Subscription sub)
        {
            if (sub == null) return;
            _store.RemoveSubscription(sub.Id);
            Log("Sub: removed '" + sub.Name + "' and its servers.");
            RefreshGroups();
            RefreshSubsList();
        }

        // Rename + re-point a subscription via the small themed dialog (shared by row Edit and tab Rename…).
        private void RenameSub(Subscription sub)
        {
            if (sub == null) return;
            using (var dlg = new SubEditDialog("Edit subscription", sub.Name, sub.Url))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                string name = string.IsNullOrEmpty(dlg.ResultName) ? DeriveSubName(dlg.ResultUrl) : dlg.ResultName;
                _store.UpdateSubscription(sub.Id, name, dlg.ResultUrl);
                Log("Sub: '" + name + "' saved (URL: " + dlg.ResultUrl + ").");
                RefreshGroups();
                RefreshSubsList();
            }
        }

        // ── Settings → Subscriptions tab: per-row actions (target = the selected row) ──
        private SubRow SelectedSubRow() => _listSubs?.SelectedItem as SubRow;

        private async void OnSubRowUpdate(object sender, EventArgs e)
        {
            var row = SelectedSubRow();
            if (row == null) { Log("Select a subscription row to update."); return; }
            _btnSubUpdate.Enabled = false;
            await UpdateOneSub(row.Sub);
            _btnSubUpdate.Enabled = true;
        }

        private void OnSubRowDelete(object sender, EventArgs e)
        {
            var row = SelectedSubRow();
            if (row == null) { Log("Select a subscription row to delete."); return; }
            RemoveSub(row.Sub);
        }

        private void OnSubRowEdit(object sender, EventArgs e)
        {
            var row = SelectedSubRow();
            if (row == null) { Log("Select a subscription row to edit."); return; }
            RenameSub(row.Sub);
        }

        // Repopulate the Subscriptions-tab list (name + URL + live server count).
        private void RefreshSubsList()
        {
            if (_listSubs == null) return;
            var keepId = SelectedSubRow()?.Sub.Id;
            _listSubs.BeginUpdate();
            _listSubs.Items.Clear();
            foreach (var s in _store.Subscriptions)
                _listSubs.Items.Add(new SubRow { Sub = s, Count = GroupCount(s.Id) });
            _listSubs.EndUpdate();
            if (keepId != null)
                for (int i = 0; i < _listSubs.Items.Count; i++)
                    if (((SubRow)_listSubs.Items[i]).Sub.Id == keepId) { _listSubs.SelectedIndex = i; break; }
        }

        // ── Right-click a group tab → in-context subscription actions (subs only; Manual/All get nothing) ──
        private void OnTabRightClicked(object sender, int tabIndex)
        {
            if (tabIndex < 0 || tabIndex >= _tabs.TabPages.Count) return;
            var tag = _tabs.TabPages[tabIndex].Tag as string;
            var sub = tag == null ? null : _store.GetSubscription(tag);
            if (sub == null) return; // not a subscription tab (All / Manual)

            _tabs.SelectedIndex = tabIndex; _strip?.Invalidate(); RefreshProfileList(); // focus the tab we act on

            var menu = new ThemedContextMenuStrip();
            AddMenuItem(menu, "⟳   Update this subscription", () => { var _ = UpdateOneSub(sub); });
            AddMenuItem(menu, "✎   Rename…", () => RenameSub(sub));
            menu.Items.Add(new ToolStripSeparator());
            AddMenuItem(menu, "🗑   Remove subscription", () => RemoveSub(sub));
            menu.Closed += (s, e) => BeginInvoke((Action)menu.Dispose);
            menu.Show(_strip, _strip.PointToClient(Cursor.Position));
        }

        private static string DeriveSubName(string url)
        {
            try { return new Uri(url).Host; } catch { return url; }
        }

        private void OnTunClick(object sender, EventArgs e)
        {
            if (!_tunRouting)
            {
                WarnIfConflicts(false); // leak-safety: another route-manager up = leak risk
                bool routeAll = _chkRouteAll.Checked;
                if (routeAll && _engine == null)
                {
                    Log("Start an engine profile first — Full tunnel needs a running engine.");
                    return;
                }
                // ON-DEMAND ELEVATION: TUN needs admin. If we're un-elevated, relaunch ourselves elevated to start
                // TUN (hands off via the single-instance mutex). This instance stays put if the user declines UAC.
                if (!IsElevated()) { ElevateForTun(routeAll); return; }
                if (!EnsureTunAdapter()) return; // logged (e.g. needs administrator)

                var testIp = _txtTunTestIp.Text.Trim();
                _tun.TestIp = testIp;
                _tun.EnginePort = _activeListenPort; // TCP stack bridges here via SOCKS5
                Core.Tun.PacketFilter.BlockQuic = _chkBlockQuic.Checked;
                ApplyDnsResolver();
                ArmUdpOutbound();

                // Clear any prior pinned server IP so a network/server change re-pins this bring-up.
                if (_activeConfig != null) _activeConfig.ServerIp = null;

                // Apply verifies preconditions (engine reachable, loop-guard) and installs routes on the
                // already-live adapter; the callbacks set PhysicalIfIndex and the pinned server IP before capture.
                _tunNet = new Core.Tun.TunNetwork(Log);
                string srvHost = _activeConfig != null ? (_activeConfig.ServerHost ?? "") : "";
                string srvProto = _activeConfig != null ? (_activeConfig.Protocol ?? "") : "";
                int srvPort = _activeConfig != null ? _activeConfig.ServerPort : 0;
                bool applied = _tunNet.Apply(_tun.Adapter, srvHost, srvPort, testIp, routeAll,
                    _activeListenPort, idx => _tun.PhysicalIfIndex = idx,
                    ip => { if (_activeConfig != null) { _activeConfig.ServerIp = ip; Log("Server pinned to " + ip + " (SNI stays " + srvHost + ")."); } });

                if (routeAll && !applied) { _tunNet = null; return; } // Apply already reverted + logged

                _tunRouting = true;
                _tun.RoutingActive = true; // begin processing/relaying captured packets
                _tunFullTunnel = routeAll;
                if (routeAll)
                    Log("FULL TUNNEL ACTIVE — all traffic via " +
                        (string.IsNullOrEmpty(srvHost) ? "engine" : srvHost) +
                        " (" + srvProto + "). Private/LAN stays direct.");
                else
                    Log("TUN: routing active.");
                _btnTun.Text = "Stop TUN";
            }
            else
            {
                // Remove routes only — KEEP the adapter alive for instant restart (closed on app exit).
                if (_tun != null) _tun.RoutingActive = false; // back to drain+drop silently
                try { _tunNet?.Restore(); } catch { }
                _tunNet = null;
                if (_activeConfig != null) _activeConfig.ServerIp = null; // unpin → non-tunnel dials by hostname (today's path)
                _tunRouting = false;
                _btnTun.Text = "Start TUN";
                if (_tunFullTunnel) { Log("full tunnel off — direct restored."); _tunFullTunnel = false; }
                else Log("TUN: routing stopped (adapter kept alive).");
            }

            UpdateTray(); // tray icon reflects the new TUN state (full-tunnel wins over system-proxy)
        }

        // ── ON-DEMAND ELEVATION (TUN needs admin; everything else runs un-elevated) ──────────────────────────────
        // We can't gain admin in place, so "elevate" = relaunch our own exe elevated (ShellExecute "runas") with
        // --elevated-start-tun and the intended --profile. On success we hand off (a graceful exit stops the engine →
        // frees 127.0.0.1:10810, then Program releases the single-instance mutex, which is the elevated instance's
        // cue to take over). If the user DECLINES UAC we stay exactly as we are (engine/system-proxy untouched, no
        // TUN) — never a vanished app.
        private void ElevateForTun(bool routeAll)
        {
            var p = _runningProfileId != null ? _store.GetById(_runningProfileId) : SelectedProfile();
            if (p == null) { Log("Select a server first before starting TUN."); return; }
            _store.ActiveProfileId = p.Id; _store.Save();   // fallback source of truth for the elevated instance

            string args = "--elevated-start-tun --profile \"" + p.Id + "\"";
            if (routeAll) args += " --full-tunnel";
            if (_chkSystemProxy.Checked) args += " --system-proxy";

            var psi = new System.Diagnostics.ProcessStartInfo(Application.ExecutablePath, args)
            {
                UseShellExecute = true,
                Verb = "runas"                       // → the UAC prompt
            };
            try { System.Diagnostics.Process.Start(psi); }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223) // ERROR_CANCELLED
            {
                Log("Elevation declined — TUN/full-tunnel needs administrator. System-proxy mode still works un-elevated.");
                MessageBox.Show(this,
                    "Full-tunnel (TUN) mode requires administrator access.\n\nSystem-proxy mode works without it.",
                    "CS-Ray — Administrator required", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;   // STAY: mutex still held, engine + system-proxy untouched, TUN not started
            }
            catch (Exception ex)
            {
                Log("Elevation relaunch failed: " + ex.Message);
                MessageBox.Show(this, "Couldn't relaunch with administrator access:\n\n" + ex.Message,
                    "CS-Ray", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;   // STAY
            }

            // UAC accepted → the elevated instance is launching and waiting on the mutex. Exit gracefully: our
            // OnFormClosing stops the engine (frees :10810) + clears system proxy BEFORE Program's finally releases
            // the mutex — so the port is free the instant the elevated instance takes over. We never started TUN
            // here (un-elevated → PreloadTun skipped, _tun == null), so there are no routes/adapter to tear down.
            Log("Relaunching with administrator access to start TUN…");
            ExitApp();
        }

        // Elevated take-over entry (Program wires this to Shown when launched with --elevated-start-tun). Selects the
        // server from the EXPLICIT --profile id (source of truth; ActiveProfileId is the fallback), brings the engine
        // up, re-applies the system-proxy intent, and starts TUN. Runs elevated, so OnTunClick's IsElevated guard
        // passes and TUN actually comes up.
        public void ElevatedStartTun(string profileId, bool fullTunnel, bool systemProxy)
        {
            string id = !string.IsNullOrEmpty(profileId) ? profileId : _store.ActiveProfileId;
            if (!string.IsNullOrEmpty(id)) SelectProfileById(id);

            if (_engine == null) OnStartClick(this, EventArgs.Empty);   // bring the engine up on that server
            if (_engine == null) { Log("Elevated start: engine didn't start — cannot start TUN."); return; }

            if (systemProxy && !_chkSystemProxy.Checked) _chkSystemProxy.Checked = true; // re-apply (triggers Set)
            _chkRouteAll.Checked = fullTunnel;
            OnTunClick(this, EventArgs.Empty);   // elevated now → EnsureTunAdapter succeeds → TUN starts
        }

        // Rare fault path: the outgoing instance didn't release the mutex within the wait window. Come up (so the user
        // has a working elevated app) but do NOT auto-start TUN — binding :10810 would likely fail while the old
        // instance lingers. Tell them to exit fully and retry (they can then just click Start TUN here — already
        // elevated, so it starts directly with no relaunch).
        public void ShowTakeoverFailed()
        {
            Log("Elevation take-over: the previous instance didn't release in time — not auto-starting TUN.");
            MessageBox.Show(this,
                "Couldn't take over from the previous CS-Ray instance.\n\nPlease exit CS-Ray fully (tray → Exit) and retry starting TUN.",
                "CS-Ray — Administrator", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        private void SelectProfileById(string id)
        {
            for (int i = 0; i < _listProfiles.Items.Count; i++)
                if (_listProfiles.Items[i] is Row r && r.Profile.Id == id) { _listProfiles.SelectedIndex = i; return; }
        }

        private void OnRemoveProfile(object sender, EventArgs e)
        {
            var p = SelectedProfile();
            if (p == null) { Log("No profile selected to remove."); return; }
            _store.Remove(p.Id);
            RefreshProfileList();
            Log("Removed profile: " + (string.IsNullOrEmpty(p.Name) ? p.Server : p.Name) + ".");
        }

        // ── Phase D: real-delay testing (standalone; idle / system-proxy mode only) ──
        private async void OnTestClick(object sender, EventArgs e)
        {
            if (_tunFullTunnel) { Log("Stop full tunnel to delay-test servers (its traffic would be captured)."); return; }
            var p = SelectedProfile();
            if (p == null) { Log("Select a server to test."); return; }
            if (p.Unsupported) { Log("Can't test " + LabelOf(p) + " — " + p.UnsupportedReason + "."); return; }

            string url = EffectiveTestUrl();
            _btnTest.Enabled = false; _btnTestAll.Enabled = false;
            SetRowLatency(p.Id, "…");
            DelayResult res;
            try { res = await Core.DelayTester.TestAsync(p.ToEngineConfig(), url, System.Threading.CancellationToken.None); }
            catch (Exception ex) { res = new DelayResult { Ok = false, Error = ex.Message }; }
            SetRowLatency(p.Id, ResultText(res));
            Log("Delay " + LabelOf(p) + ": " + (res.Ok ? ("connect=" + res.ConnectMs + "ms total=" + res.TotalMs + "ms") : ("FAILED — " + res.Error)));
            _btnTest.Enabled = true; _btnTestAll.Enabled = true;
        }

        private async void OnTestAllClick(object sender, EventArgs e)
        {
            if (_tunFullTunnel) { Log("Stop full tunnel to delay-test servers (its traffic would be captured)."); return; }
            var profiles = ProfilesInCurrentTab();
            profiles.RemoveAll(x => x.Unsupported); // unsupported servers can't be delay-tested
            if (profiles.Count == 0) { Log("No testable servers in this tab."); return; }

            string url = EffectiveTestUrl();
            _btnTest.Enabled = false; _btnTestAll.Enabled = false;
            Log("Delay test: " + profiles.Count + " server(s) → " + url + ", up to 8 in parallel…");
            foreach (var p in profiles) SetRowLatency(p.Id, "…");

            using (var sem = new System.Threading.SemaphoreSlim(8))
            {
                var tasks = new List<Task>();
                foreach (var p in profiles)
                {
                    var prof = p; // capture
                    tasks.Add(Task.Run(async () =>
                    {
                        await sem.WaitAsync().ConfigureAwait(false);
                        DelayResult res;
                        try { res = await Core.DelayTester.TestAsync(prof.ToEngineConfig(), url, System.Threading.CancellationToken.None).ConfigureAwait(false); }
                        catch (Exception ex) { res = new DelayResult { Ok = false, Error = ex.Message }; }
                        finally { sem.Release(); }
                        string text = ResultText(res);
                        try { BeginInvoke((Action)(() => SetRowLatency(prof.Id, text))); } catch { }
                    }));
                }
                await Task.WhenAll(tasks);
            }
            _btnTest.Enabled = true; _btnTestAll.Enabled = true;
            Log("Delay test complete.");
        }

        private static string ResultText(DelayResult r) => r.Ok ? r.TotalMs + "ms" : (r.Error == "timeout" ? "timeout" : "dead");
        private static string LabelOf(ProxyProfile p) => string.IsNullOrEmpty(p.Name) ? p.Server : p.Name;

        // The delay-test target from the box (empty → default); persists it when changed so it survives restart.
        private string EffectiveTestUrl()
        {
            var url = (_txtTestUrl.Text ?? "").Trim();
            if (url.Length == 0) { url = Core.DelayTester.DefaultUrl; _txtTestUrl.Text = url; }
            string toStore = (url == Core.DelayTester.DefaultUrl) ? null : url; // null = track the built-in default
            if ((_store.DelayTestUrl ?? "") != (toStore ?? "")) { _store.DelayTestUrl = toStore; _store.Save(); }
            return url;
        }

        // Update one server row's inline latency on the UI thread; persisted in _delay so list rebuilds keep it.
        private void SetRowLatency(string profileId, string text)
        {
            _delay[profileId] = text;
            for (int i = 0; i < _listProfiles.Items.Count; i++)
            {
                var row = (Row)_listProfiles.Items[i];
                if (row.Profile.Id == profileId)
                {
                    row.Latency = text;
                    int sel = _listProfiles.SelectedIndex;
                    _listProfiles.Items[i] = row;                 // force this line to re-render
                    if (sel >= 0 && _listProfiles.SelectedIndex != sel) _listProfiles.SelectedIndex = sel;
                    break;
                }
            }
        }

        /// <summary>Selects a server (if none) and starts the engine — used by the --autostart switch.</summary>
        public void AutoStart()
        {
            _chkVerbose.Checked = true; // headless test runs want the full per-connection log
            if (_listProfiles.Items.Count > 0 && _listProfiles.SelectedIndex < 0) _listProfiles.SelectedIndex = 0;
            if (_engine == null) OnStartClick(this, EventArgs.Empty);
        }

        // System proxy is an INDEPENDENT switch: toggling takes effect immediately, regardless of engine state.
        private void OnSystemProxyToggle(object sender, EventArgs e)
        {
            try
            {
                if (_chkSystemProxy.Checked)
                {
                    SystemProxy.Set(_activeListenPort);
                    Log("System proxy set: http/https/socks=127.0.0.1:" + _activeListenPort + " (prior settings saved).");
                }
                else if (SystemProxy.IsApplied)
                {
                    SystemProxy.Clear();
                    Log("System proxy cleared — prior settings restored.");
                }
            }
            catch (Exception ex) { Log("System proxy toggle error: " + ex.Message); }
            UpdateTray(); // tray icon reflects system-proxy state (unless TUN is on, which wins)
        }

        // E1: prove VLESS UDP round-trips (DNS to 8.8.8.8 via the server), no TUN involved. Uses the SELECTED
        // profile's config, so it works whether or not an engine is running.
        private async void OnUdpSelfTestClick(object sender, EventArgs e)
        {
            var p = SelectedProfile();
            if (p == null) { Log("Select a server first for the UDP test."); return; }
            var cfg = p.ToEngineConfig();
            _btnUdpTest.Enabled = false;
            try { await Core.Protocol.VlessUdpSession.RunDnsSelfTestAsync(cfg, Log); }
            catch (Exception ex) { Log("E1 UDP test: error — " + ex.Message); }
            finally { _btnUdpTest.Enabled = true; }
        }

        // Combined-button START: build the engine from the SELECTED profile (inline fields removed in C2b).
        private void OnStartClick(object sender, EventArgs e)
        {
            var p = SelectedProfile();
            if (p == null) { Log("Select a server first (add one via the hamburger ☰ menu)."); return; }
            if (p.Unsupported) { Log("Can't start " + LabelOf(p) + " — " + p.UnsupportedReason + "."); return; }
            WarnIfConflicts(false); // leak-safety: warn (don't block) if another proxy/VPN app is up
            try
            {
                var config = p.ToEngineConfig();
                if (string.IsNullOrWhiteSpace(config.ServerHost) || config.ServerPort <= 0)
                { Log("Selected server is missing an address/port."); return; }

                _engine = new ProxyEngine(config) { Verbose = _chkVerbose.Checked };
                _engine.Log += Log;
                _engine.Start();
                _activeListenPort = config.ListenPort;
                _activeConfig = config; // remember for TUN UDP tunneling

                if (_store.ActiveProfileId != p.Id) { _store.ActiveProfileId = p.Id; _store.Save(); }
                _runningProfileId = p.Id; // the truly-active server (drives the list indicator + tray icon)
                Log("Engine started: " + LabelOf(p) + " (" + config.Protocol + ") on 127.0.0.1:" + _activeListenPort + ".");
                UpdateEngineDeps();
            }
            catch (Exception ex)
            {
                Log("Failed to start: " + ex.Message);
                _engine = null;
                UpdateEngineDeps();
            }
        }

        // Combined-button STOP: tears down everything that depends on the engine (TUN routes + system proxy).
        private void OnStopClick(object sender, EventArgs e)
        {
            if (_tunRouting) { try { OnTunClick(this, EventArgs.Empty); } catch (Exception ex) { Log("TUN stop error: " + ex.Message); } }
            if (SystemProxy.IsApplied) { try { _chkSystemProxy.Checked = false; } catch { } } // routes via OnSystemProxyToggle → Clear

            try { _engine?.Stop(); } // ProxyEngine.Stop() logs "Engine stopped." itself — don't log it twice here
            catch (Exception ex) { Log("Stop error: " + ex.Message); }
            _engine = null;
            _activeConfig = null;
            _runningProfileId = null; // no server is active once the engine stops
            UpdateEngineDeps();
        }

        private static string Stamp(string m) => "[" + DateTime.Now.ToString("HH:mm:ss") + "] " + m;

        // Priority sink — thread-safe, non-blocking, drop-oldest on overflow. Always rendered.
        private void Log(string message)
        {
            if (_logQueue.Count >= MaxQueueEntries && _logQueue.TryDequeue(out _))
                System.Threading.Interlocked.Increment(ref _droppedLogs);
            _logQueue.Enqueue(Stamp(message));
        }

        // High-frequency packet sink — rate-limited by slow mode; same enqueue-only/drop-oldest rules.
        private void LogFlood(string message)
        {
            System.Threading.Interlocked.Increment(ref _floodProduced);
            if (_floodQueue.Count >= MaxQueueEntries && _floodQueue.TryDequeue(out _))
                System.Threading.Interlocked.Increment(ref _droppedLogs);
            _floodQueue.Enqueue(Stamp(message));
        }

        private void FlushLog(object sender, EventArgs e)
        {
            if (IsDisposed) return;
            int now = Environment.TickCount;

            // --- ~1s rate window → slow-mode transitions (based on flood lines produced/sec) ---
            if (unchecked(now - _rateWindowStartTick) >= 1000)
            {
                long produced = System.Threading.Interlocked.Read(ref _floodProduced);
                int elapsed = unchecked(now - _rateWindowStartTick);
                _lastRate = elapsed > 0 ? (int)((produced - _floodWindowBase) * 1000 / elapsed) : 0;
                _floodWindowBase = produced;
                _rateWindowStartTick = now;

                if (!_slowMode)
                {
                    _slowOnCount = _lastRate > SlowOnLinesPerSec ? _slowOnCount + 1 : 0;
                    if (_slowOnCount >= SlowOnSeconds)
                    { _slowMode = true; _slowOffCount = 0; _logQueue.Enqueue(Stamp("[SLOW MODE] ON — packet logs summarized (" + _lastRate + "/s)")); }
                }
                else
                {
                    _slowOffCount = _lastRate < SlowOffLinesPerSec ? _slowOffCount + 1 : 0;
                    if (_slowOffCount >= SlowOffSeconds)
                    { _slowMode = false; _slowOnCount = 0; _logQueue.Enqueue(Stamp("SLOW MODE OFF — normal logging")); }
                }
            }

            var render = new StringBuilder();

            int n = 0;
            while (n < MaxDrainPerTick && _logQueue.TryDequeue(out var pl)) { render.Append(pl).Append(Environment.NewLine); n++; }

            int floodDrained = 0;
            if (_slowMode)
                while (floodDrained < MaxDrainPerTick && _floodQueue.TryDequeue(out _)) floodDrained++; // discard, counted via rate
            else
                while (floodDrained < MaxDrainPerTick && _floodQueue.TryDequeue(out var fl)) { render.Append(fl).Append(Environment.NewLine); floodDrained++; }

            if (_slowMode && unchecked(now - _lastSlowSummaryTick) >= SlowSummaryMs)
            { _lastSlowSummaryTick = now; render.Append(Stamp(SlowSummary())).Append(Environment.NewLine); }

            if (unchecked(now - _lastStatsTick) >= StatsMs && _tun != null && _tunRouting)
            { _lastStatsTick = now; render.Append(Stamp(StatsLine())).Append(Environment.NewLine); }

            if (_lblSlow.Visible != _slowMode) _lblSlow.Visible = _slowMode;

            if (render.Length == 0) return;
            var batch = render.ToString();
            _txtLog.AppendText(batch);

            // Hard cap: ring-trim; escalate to a single cheap clear-to-tail under sustained flood.
            if (_txtLog.TextLength > MaxLogChars)
            {
                if (++_overCapStreak >= AutoClearTrimStreak)
                {
                    _overCapStreak = 0;
                    var t = _txtLog.Text;
                    _txtLog.Text = t.Substring(Math.Max(0, t.Length - AutoClearTailChars));
                    _txtLog.AppendText(Stamp("log auto-cleared (flood)") + Environment.NewLine);
                }
                else
                {
                    var t = _txtLog.Text;
                    _txtLog.Text = t.Substring(t.Length - LogTrimToChars);
                }
                _txtLog.SelectionStart = _txtLog.TextLength;
                _txtLog.ScrollToCaret();
            }
            else _overCapStreak = 0;

            if (FileLogging)
            {
                try { System.IO.File.AppendAllText(System.IO.Path.Combine(System.IO.Path.GetTempPath(), "csray.log"), batch); }
                catch { }
            }
        }

        private string StatsLine()
        {
            if (_tun == null) return "TUN stats: (stopped)";
            _tun.GetCounters(out var t, out var v4, out var v6, out var tcp, out var udp, out var icmp);
            _tun.GetRelayCounters(out var drop, out var udpRelay, out var icmpRep, out var quicDrop, out var udpViaEng, out var leakDrop);
            _tun.GetTcpCounters(out var tcpOpen, out var tcpAct, out var tcpClosed, out var tcpPeak);
            long droppedLogs = System.Threading.Interlocked.Read(ref _droppedLogs);
            return "TUN stats: total=" + t + " v4=" + v4 + " v6=" + v6 + " TCP=" + tcp + " UDP=" + udp + " ICMP=" + icmp +
                   " | dropped=" + drop + " udpDirect=" + udpRelay + " udpViaEngine=" + udpViaEng + " udpSessions=" + _tun.UdpSessions + " udpLeakDropped=" + leakDrop + " quicDropped=" + quicDrop + " icmpReplies=" + icmpRep +
                   " | tcpConns=" + tcpOpen + " tcpActive=" + tcpAct + " tcpPeak=" + tcpPeak + " tcpClosed=" + tcpClosed +
                   (droppedLogs > 0 ? " droppedLogs=" + droppedLogs : "");
        }

        private string SlowSummary()
        {
            long t = 0, v4 = 0, v6 = 0, tcp = 0, udp = 0, icmp = 0;
            _tun?.GetCounters(out t, out v4, out v6, out tcp, out udp, out icmp);
            long d4 = v4 - _sumBaseV4, d6 = v6 - _sumBaseV6, dtcp = tcp - _sumBaseTcp, dudp = udp - _sumBaseUdp, dicmp = icmp - _sumBaseIcmp;
            _sumBaseV4 = v4; _sumBaseV6 = v6; _sumBaseTcp = tcp; _sumBaseUdp = udp; _sumBaseIcmp = icmp;
            return "SLOW MODE: ~" + _lastRate + " lines/s suppressed; v4=" + d4 + " v6=" + d6 + " TCP=" + dtcp + " UDP=" + dudp + " ICMP=" + dicmp;
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // ✕ / Alt+F4 minimize to tray; only Exit (tray or ☰) sets _reallyClosing → real graceful teardown.
            if (!_reallyClosing && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                HideToTray();
                return;
            }
            try { CloseDrawer(); } catch { } // drop the drawer's message filter if it was open at quit
            try { _logTimer?.Stop(); } catch { }
            try { _listTouch?.Dispose(); } catch { }
            try { _logTouch?.Dispose(); } catch { }
            try { _stripTouch?.Dispose(); } catch { }
            try { _settings?.Dispose(); } catch { } // bypasses its hide-on-close so it actually closes
            try { _tunNet?.Restore(); } catch { } // routing first, then close the adapter
            try { _tun?.Stop(); } catch { }
            try { SystemProxy.Clear(); } catch { }
            try { _engine?.Stop(); } catch { }
            try { if (_notifyIcon != null) { _notifyIcon.Visible = false; _notifyIcon.Dispose(); _notifyIcon = null; } } catch { }
            base.OnFormClosing(e);
        }
    }
}

# TelegArm — Creative & Design Decisions

## UI framework: MaterialSkin.2 (WinForms)
WinForms is the only practical UI for **Windows RT 8.1 / Windows 10 ARM32 on .NET 4.7** (no WPF requirement, broad compatibility, lightweight). MaterialSkin.2 gives a modern Material look on top of WinForms with theme + accent support. **No WPF anywhere.**

## Target framework: .NET 4.7
Windows 10 ARM32 build 15035 ships .NET **4.7** built-in; **4.7.2 is not present** without a manual install. 4.7 is binary-compatible for our code, so we target 4.7 to run out-of-the-box on the device. (Requires the 4.7 targeting pack on the build machine.)

## Bitness: AnyCPU + Prefer32Bit = true
A single AnyCPU build runs as **x86 on x64** (Prefer32Bit) and **ARM32 on ARM32 Windows** (Prefer32Bit is ignored on ARM — no x86 subsystem). One binary for all targets, no per-arch projects. Consequence: native deps (VLC) must match the **process** arch — x86 on PCs, ARM32 on the device.

## Telegram library: WTelegramClient (not TLSharp)
WTelegramClient is actively maintained, full MTProto, supports netstandard2.0/net40-compatible usage on .NET 4.7, has a clean `Config` callback and helpers (`UserOrChat`, `ToInputPeer`, `DownloadFileAsync`, `SendMessageAsync`, `OnUpdates`). TLSharp is largely abandoned and less complete.

## VLC detection: folder-based, arch-agnostic, runtime
No hardcoded VLC path, no post-build copy, no bundled native package (we explicitly do NOT add `VideoLAN.LibVLC.Windows`). At runtime we look for `<exe>\libvlc\libvlc.dll`+`libvlccore.dll`. `Core.Initialize` is wrapped in try/catch so a wrong-arch/partial drop falls back gracefully instead of crashing. This lets the same build: use embedded VLC where matching libs are provided (ARM32 device, or x86 VLC on a PC) and fall back to the system player elsewhere.

## LibVLCSharp 3.x (NOT 4.x)
3.9.7 ships **net40** assemblies, which are consumable from .NET 4.7 (4.x raises the floor). NuGet auto-picks net40 for our net47 target (net471 is correctly excluded as > 4.7).

## Video/doc storage: stream to a persistent cache file (not byte[])
Videos can be tens–hundreds of MB; ARM32 RT devices have ~1 GB RAM. Loading a video fully into a `byte[]` risks OOM. Instead we **stream to disk** (`MediaCacheFolder`). Inspired by Telegram Desktop: keep downloads in a cache folder and prune old files (retention setting) so storage doesn't fill. Photos stay in-memory (small) plus a disk copy for reuse.

## Disk cache with startup index restore
Downloaded photos are written to `photo_{id}.jpg`; on startup `RestorePhotoCacheIndex()` scans the cache folder and rebuilds the id→path map, so restarts reuse downloads (instant, no re-download). Cache naming is centralized (`MediaCache.CacheFileName`).

## Media cache folder strategy
Default `%LocalAppData%\TelegArm\Cache` (user-writable on RT, survives app-folder restrictions). Configurable in Settings. Daily background cleanup deletes files older than `MediaCacheRetentionDays` (default 7); "Clear Cache Now" deletes all.

## Single-instance: machine-wide Global mutex
`Global\TelegArm_SingleInstance` with a permissive (WorldSid) ACL so it works across user sessions/RDP. Two clients on the **same session file** trigger Telegram's `AUTH_KEY_DUPLICATED`, which revokes the session — the mutex prevents that. Permissive ACL avoids `UnauthorizedAccessException` across accounts.

## GDI+ drawn buttons instead of font glyphs
WinForms `Button.Text` renders via GDI, which can't draw color emoji, and geometric glyphs vary by font/OS. `MediaControlButton` draws each icon (Play/Pause/Prev/Next/Volume/Mute) with GDI+ shapes — pixel-identical on 8.1/10/ARM32. (See LESSONS_LEARNED.)

## Owner-painted custom controls everywhere it matters
Chat rows, message bubbles, the seek bar, and media buttons are all owner-painted (`OnPaint`) for full control over look + DPI behavior + cross-OS consistency, and to avoid MaterialSkin's font override (fonts stored in private fields).

## Audio: one static, audio-only player + per-chat playlist
Voice notes and music share a single process-wide `AudioPlayer` (audio-only LibVLC, no `VideoView`) so only one clip ever plays at once and state is trivial to reflect everywhere. It keeps a per-chat playlist and a `resolve(id)→path` callback, so next/previous can stream the next file on demand instead of pre-downloading the whole chat. A single `StateChanged` event drives every view (bubbles + mini bar), so they never get out of sync.

## Telegram-style audio/voice bubble
Audio messages were redesigned to match Telegram: a circular accent button (download arrow → spinner while downloading → play/pause) plus two text lines (voice = "Voice message" + duration; music = filename + "duration, size"; while playing = live "elapsed / total"). The per-bubble waveform/seek/speed were intentionally **removed** from the bubble — transport now lives in the mini player bar, keeping bubbles compact.

## Persistent mini player bar — owner-painted as a single control
The mini player docks at the top of the conversation pane while audio plays (prev/play-pause/next, title, draggable seek, elapsed/total, speed cycle, mute, close). It is drawn as **one owner-painted control** rather than a panel of child widgets: owner-painted *child* controls (and even native `Button` text) refuse to render inside a toolbar row, while a control that paints itself works — the same approach that makes the message bubbles reliable. Accent circles match the bubble button style for visual consistency. The row collapses to 0 height when idle (preserving the message scroll position) and reserves the scrollbar width so controls never overlap it.

## Sending media: stream-upload, no re-encode, one dialog for both entry points
Phase 4 sends photos/videos/documents. Design choices:
- **One send path, two triggers.** The paperclip (`AttachButton` + `OpenFileDialog`) and drag-and-drop both route through `OnFilesDropped` → `SendMediaDialog`, so there's a single upload/confirm flow to reason about and theme.
- **Upload by streaming from the path** (`UploadFileAsync(path)`), never reading whole files into a `byte[]` — same ARM32 memory discipline as the download side. Only images are first compressed to a small temp JPEG (≤1280, q82), which is then deleted.
- **Video "compress" does NOT re-encode.** We add no codec/FFmpeg/NuGet dependency; "compress" sends the user's file as a *streamable* video document (`supports_streaming`). Duration/width/height are left 0 because probing them needs decoding the file (avoided on ARM32). A **Compress ⇄ Send as file** per-row toggle lets the user force a raw document instead.
- **Optimistic bubbles, like text.** Each file shows a pending bubble immediately (clock glyph), then resolves to sent (or a red failed mark). Caption applies to the first file (album-style). This keeps the UI responsive during slow ARM32 uploads.
- **The dialog owns the upload** (sequential, cancellable, per-file progress) and only raises UI-thread lifecycle events; MainForm stays the view layer.
- **Pending→sent reconciliation is race-proof by being idempotent.** The outgoing echo and the dialog's success callback can fire in either order (the modal dialog pumps updates during the upload), so both do the *same* in-place swap and the loser no-ops. Sequential uploads keep the match unambiguous without needing a per-send `random_id` (which is the escalation if uploads ever become concurrent). See BUGS_AND_FIXES / LESSONS_LEARNED.

## Message actions: one touch-friendly context menu, reuse the themed-menu plumbing
Per-message actions (Copy / Reply / Delete) hang off a single context menu rather than per-bubble buttons (which would clutter the owner-painted bubbles and fight the VLC/owner-paint rules). The menu is triggered from `WM_CONTEXTMENU`, not a right-click handler, specifically so **touch-and-hold works on the ARM32 tablet** with no extra gesture code. The menu itself reuses the existing `ApplyThemeToMenu` used by the hamburger, so it's themed for free and stays consistent. Actions only appear for real (server) messages — optimistic/pending bubbles have nothing to act on yet.

## Themed dialogs instead of native MessageBox
Confirmations and alerts use `ThemedDialog` (a MaterialForm styled from `ThemeHelper`) rather than `MessageBox`, so they match the app's dark/light + accent instead of looking like a stock Windows popup — important on the tablet where a native dialog feels out of place. It returns the clicked button index, which also lets one dialog express a *choice* (e.g. Delete → **Just for me / For everyone**) rather than only Yes/No. This is the standard for all new dialogs.

## Reply quote rendered inside the bubble
A reply shows the quoted message *inside* the replying bubble (accent bar + one-line preview), resolved from already-loaded history — matching Telegram and making threads readable at a glance. The quote height is folded into every paint path (text / photo / file) so layout stays correct. Sender attribution in the quote is a later refinement; v1 shows the quoted text.

## Forward picker reuses the chat-row control
The "forward to…" dialog is a themed `MaterialForm` that fills a `FlowLayoutPanel` with the same `ChatListItemControl` used in the main list (plus a search filter), so forwarding looks and behaves like picking a chat anywhere else — no second list style to maintain.

## Reply composer as a toggled layout row (not a popup)
The "replying to…" affordance is a thin strip that appears as a **5th row** in the right-panel `TableLayoutPanel` (header / mini player / messages / reply strip / input), collapsing to 0 height when inactive — the same toggled-row pattern (and scroll-offset preservation) as the mini player bar. This keeps the reply context anchored to the input where the user is typing, and avoids a floating popup that would be awkward with touch.

## Voice recording: pure-managed Opus, no native codecs
Voice notes are recorded with **NAudio** (mic capture) and encoded to **OGG/Opus with Concentus** (a pure-C# Opus port) — deliberately chosen because they're managed AnyCPU IL, so they run on ARM32 with **no native binary to source** (the exact pain VLC had). The UX is **Record → Stop → Ready → Send** (Stop never auto-sends; the Send button sends, the mic's red ✕ discards) so the Send button stays meaningful. Real voice-note semantics (`DocumentAttributeAudio{ voice }`, OGG) rather than a plain audio attachment.

## Owner-painted bars over child-control panels
Every in-chat bar (video controls, mini player, **selection toolbar**, **recording strip**) is a *single owner-painted control*, not a panel of child widgets. Child controls with transparent backgrounds paint black, owner-painted children don't render in toolbar rows, and `MediaControlButton` is hard-coded dark — all avoided by painting the whole bar in its own `OnPaint` with `ThemeHelper` colors and region hit-testing. This is now the standing pattern for any bar.

## One themed menu renderer for the whole app
Rather than recoloring each menu, a single `ToolStripManager.Renderer` (`ThemedMenuRenderer` + `ThemedColorTable`, both reading `ThemeHelper`) themes every context menu **and its sub-menus** automatically (bg/text from IsDark, hover from accent). `ThemedContextMenuStrip` is the type the app instantiates.

## RTL detection for Persian/Arabic
Detect RTL by scanning for Unicode ranges (Hebrew 0590–05FF, Arabic 0600–06FF/0750–077F/08A0–08FF, Arabic Presentation FB50–FDFF/FE70–FEFF). When RTL: `StringFormatFlags.DirectionRightToLeft` + `Alignment.Far` + `RightToLeft=Yes`, and measure/draw with ONE shared StringFormat at the same width so text never overflows the bubble.

## Theme: three-state mode (System / Light / Dark), one helper
Rather than a binary dark toggle, the app has a persisted `ThemeMode` (default **System**). We **extended the existing `ThemeHelper`** (added `Mode`/`SetMode`/`InitMode`/`IsDark`) instead of introducing a second theming system, since every form and `MediaControlButton` already consume it. `IsDark` resolves the decision in one place (override wins; System reads the OS). The accent color always tracks the OS; the OS light/dark switch only moves the app when following the system, so a manual override is never overridden by Windows. The mode is parsed from `settings.json` and applied (`InitMode`) before any window so login and main are correct on the first frame. The MediaViewer, previously always-dark, now follows the theme too — only its NATIVE control bar is themed (the VLC video surface is never painted over).

## DPI: system-aware only
`SetProcessDpiAwareness(1)` + `AutoScaleMode.Font`, no manual scaling. MaterialSkin.2 has no per-monitor DPI support; mixing per-monitor (2) with manual math double-scales.

## Custom ScaledTabSelector (planned, not yet built)
`MaterialTabControl` hides its native tab headers, so when tabs are needed we'll build a custom `ScaledTabSelector : Control` painting tabs manually (active = accent bg + white text + 3px indicator; inactive dark/light variants), using a private font field in OnPaint. Recorded as a rule; not implemented yet.

## Search: two scopes (Chats / Messages)
A toggle below the search box. Chats = local name filter (instant). Messages = global `Messages_SearchGlobal`, debounced 500ms, results shown as a flat list reusing the chat-row control; clicking opens the chat centered on that message.

# TelegArm — Bugs and Fixes

Chronological record of bugs encountered and how they were resolved.

---

## Bug: animated `.tgs` stickers don't work on Windows RT 8.1 ("msvcp140.dll is missing")
**File:** native `rlottie\ARM\rlottie.dll` (build artifact) + `Helpers/RLottie.cs`, `Helpers/NativeLibraries.cs`
**Symptom:** Animated stickers stayed as the static `alt` emoji on RT; clicking the "Sticker engine…" diagnostic showed a loader dialog "msvcp140.dll is missing." Worked on the dev PC.
**Root cause:** The ARM32 `rlottie.dll` links the **dynamic** VC++ CRT (`msvcp140`/`vcruntime140` + UCRT), which RT 8.1 doesn't have (no ARM32 VC++ redist) — the dev PC has it, hence the asymmetry.
**Fix / status:** Added `SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOOPENFILEERRORBOX)` so the loader fails silently into the static-emoji fallback (no popup), plus a diagnostic (`RLottie.Diagnose()` via the hamburger menu) that reports the exact Win32 load error. The permanent fix is a **`/MT` static-CRT rebuild** of `rlottie.dll` (or shipping the CRT DLLs beside the exe). The app degrades gracefully without it.

## Bug: folder-tab bar's horizontal scrollbar stayed white on RT
**File:** UI/Controls/ThemedScrollBar.cs, UI/MainForm.cs (`WrapWithHScrollbar`)
**Symptom:** After theming the vertical scrollbars, the horizontal scrollbar under the folder tabs (and the sticker pack strip) was still the native white bar on RT.
**Root cause:** `ThemedScrollBar` was vertical-only; horizontal AutoScroll strips still showed the native `SB_HORZ` bar (and `DarkMode_Explorer` is a no-op on RT anyway).
**Fix:** Generalized `ThemedScrollBar` to vertical **and** horizontal (a `horizontal:` ctor flag using `HorizontalScroll` metrics + `SB_HORZ`), and wrapped the folder bar / sticker pack strip with a bottom-docked themed h-bar.

## Bug: Settings buttons fell behind the taskbar on RT
**File:** UI/SettingsForm.cs
**Symptom:** The fixed 520×800 settings form was taller than RT's screen, so OK/Cancel (y≈748) sat behind the taskbar.
**Fix:** Rebuilt as **category tabs (Media / Storage / Notifications)** with a **docked footer** for OK/Cancel in a short window — fits any screen. Used plain panels (not a fragile tab control) for RT reliability.

---

## Bug: NullReferenceException clicking a chat-folder tab
**File:** UI/MainForm.cs (RebuildFolderBar / MatchesFolder)
**Symptom:** Clicking a folder tab threw `NullReferenceException` at `RebuildFolderBar` (the `f.Title?.text` line) via `SetActiveFolder`.
**Root cause:** `Messages_GetDialogFilters` can return a filter entry whose `DialogFilterBase.Title` getter dereferences a null underlying field (and `DialogFilterDefault` is **not** a TL type in WTelegramClient 4.4.6, so it can't be filtered by type). `DialogFilter.Title` is a `TextWithEntities`, not a string — use `.Title?.text`.
**Fix:** Made both methods defensive — skip null filter entries and wrap title extraction in try/catch (falls back to "Folder"); wrapped the whole `MatchesFolder` body in try/catch returning `true` so a malformed folder can never break the chat list. Type-flag matching remains best-effort; explicit-peer folders match exactly.

---

## Bug: nuget.exe / dotnet not available on build machine
**File:** build tooling (not code)
**Symptom:** The provided nuget.exe path didn't exist; `dotnet` not installed.
**Root cause:** Only MSBuild 15.9 (VS2017 "Vscom") present; no NuGet client, no .NET Core SDK.
**Fix:** Downloaded official nuget.exe to repo root (`C:\Users\hamed\source\repos\TelegArm\nuget.exe`). Use PackageReference + `nuget restore <sln> -MSBuildPath "D:\Program Files\Vscom\MSBuild\15.0\Bin"`, then build with that MSBuild.

---

## Bug: SplitContainer crash on startup (silent exit)
**File:** UI/MainForm.cs (BuildUi)
**Symptom:** App launched then immediately exited; no window.
**Root cause:** `SplitterDistance = 300` was set in the object initializer while the SplitContainer still had its default 150px width, so the value was outside the valid range and threw.
**Fix:** Add the SplitContainer to the form first (so docking gives it the form width), THEN set `Panel1MinSize`/`Panel2MinSize` and `SplitterDistance` inside a try/catch. Also added global exception handlers in Program.cs (`Application.ThreadException`, `AppDomain.UnhandledException`) so future crashes show a message instead of vanishing.

---

## Bug: C# language features not compiling
**File:** TelegArm.csproj
**Symptom:** `default` literal, tuples errors (`CS8107` etc.).
**Root cause:** Default LangVersion was C# 7.0.
**Fix:** Added `<LangVersion>7.3</LangVersion>` (supported by the bundled Roslyn).

---

## Bug: `Message` ambiguous reference
**File:** UI/MainForm.cs, UI/MediaViewerForm.cs
**Symptom:** `CS0104: 'Message' is ambiguous between System.Windows.Forms.Message and TL.Message`.
**Root cause:** `using TL;` brings `TL.Message`, which clashes with WinForms `Message` (used by `ProcessCmdKey`).
**Fix:** In MainForm added `using Message = TL.Message;` (we use TL.Message a lot). For the `ProcessCmdKey` override in both forms, fully-qualified the parameter as `System.Windows.Forms.Message`.

---

## Bug: MaterialSkin overrides Control.Font (custom controls draw wrong font)
**File:** UI/Controls/* (ChatListItemControl, MessageBubbleControl)
**Symptom:** Custom-painted text used the wrong font.
**Root cause:** MaterialSkin overwrites `Control.Font` after construction.
**Fix:** Each custom control stores its fonts in private readonly fields and uses those directly in OnPaint — never `this.Font`.

---

## Bug: DPI double-scaling / blurry UI (preventive)
**File:** Program.cs, all forms
**Symptom:** (Lesson from a prior project) blurry UI / wrong sizes at >100% DPI.
**Root cause:** PROCESS_PER_MONITOR_DPI (2) + manual `_scale = DpiX/96` = double scaling. MaterialSkin.2 has no per-monitor DPI support.
**Fix:** `SetProcessDpiAwareness(1)` (system-DPI) in Program.cs before any window; `AutoScaleMode = AutoScaleMode.Font` on every form; fixed logical sizes, no manual DPI math.

---

## Bug: Session resume still showed the sign-in form
**File:** UI/MainForm.cs (ResumeSessionAsync), Core/TelegramService.cs
**Symptom:** Even with a valid `TelegArm.session`, the app dropped to LoginForm after "Resuming session…".
**Root cause (1):** `OnLoad` caught ANY exception from `LoginAsync()` and fell back to LoginForm — including transient/late errors after the session had actually authorized.
**Root cause (2):** WTelegramClient's Config callback is expected to ALWAYS be able to return `phone_number`; returning null made `LoginUserIfNeeded` bail. With a valid session, supplying the phone logs in WITHOUT a code.
**Root cause (3):** AUTH_KEY_DUPLICATED — running two clients on the same session (e.g. agent-launched second instance) makes Telegram revoke the session.
**Fix:**
- Persist the phone on login (`TelegArm.phone`) and supply it during silent resume (`LoginAsync(silentResume:true)`).
- `IsAuthorized` (`Client?.User != null`) is the source of truth: stay on MainForm whenever authorized even if an exception was thrown.
- Only fall back for genuine auth failures: `NeedsInteractiveLogin` (Config asked for a phone we don't have) or `RpcException` whose message contains AUTH/SESSION. Network errors retry 3× and stay on MainForm.
- Added machine-wide single-instance `Global\TelegArm_SingleInstance` mutex (permissive ACL) in Program.cs.

---

## Bug: Last message hidden behind the input bar
**File:** UI/MainForm.cs (ScrollMessagesToBottom)
**Symptom:** The newest bubble looked jammed/cut off at the bottom.
**Root cause:** `ScrollControlIntoView(last)` stops as soon as the control is just visible (flush against the bottom edge) and ignores the panel's bottom padding.
**Fix:** Scroll to the true bottom: `PerformLayout()` then `AutoScrollPosition = new Point(0, VerticalScroll.Maximum)`. Added 8px bottom padding on the message panel. (Layout already used a TableLayoutPanel so there was no structural overlap.)

---

## Bug: Persian/Arabic (RTL) text overflowed the bubble
**File:** UI/Controls/MessageBubbleControl.cs
**Symptom:** RTL text painted outside the bubble.
**Root cause:** Measure↔draw width mismatch — measured wrapped text at max width but drew into a different width.
**Fix:** Switched to GDI+ `Graphics.MeasureString`/`DrawString` with ONE shared `StringFormat`, measuring and drawing at the same width. RTL detected via Unicode ranges (Hebrew/Arabic/etc.) → `StringFormatFlags.DirectionRightToLeft` + `Alignment.Far` + `RightToLeft=Yes`. Bubble capped at ~66% panel width.

---

## Bug: Short-message timestamps clipped ("hi", "1")
**File:** UI/Controls/MessageBubbleControl.cs (ComputeLayout)
**Symptom:** Tiny bubbles cut off the `HH:mm` stamp.
**Root cause:** Bubble width was based only on message/sender text, not the timestamp width.
**Fix:** Width now also accounts for timestamp width (`needed = max(textW, senderW, timeW)`); enforced `MinBubbleWidth=80`, `MinBubbleHeight=48`.

---

## Bug: Duplicate messages on live update
**File:** UI/MainForm.cs
**Symptom:** Messages appeared multiple times.
**Root cause:** OnUpdates and history reload overlap; updates can fire more than once.
**Fix:** `HashSet<int> _shownMessageIds`; `AddBubble`/`AddMessageBubble` skip if the id is already shown. Sent messages add their returned id to the set too.

---

## Bug: Mouse-wheel scroll didn't load older messages
**File:** UI/MainForm.cs
**Symptom:** Dragging the scrollbar to the top loaded older messages; mouse wheel didn't.
**Root cause:** `FlowLayoutPanel.Scroll` doesn't reliably fire with `NewValue==0` on wheel.
**Fix:** Added a `MouseWheel` handler that, via `BeginInvoke` (so it runs after the wheel scroll applies), checks `VerticalScroll.Value <= SmallChange*3` and calls `LoadOlderMessages()`.

---

## Bug: Chat list full-reload on every incoming message
**File:** UI/MainForm.cs (UpdateChatListForMessage)
**Symptom:** Whole list rebuilt on each message (flicker/cost).
**Fix:** Update the affected row in place (preview/time/badge), move it to top with `Controls.SetChildIndex(item, 0)`, no full re-render.

---

## Bug: Media messages showed empty bubbles
**File:** UI/MainForm.cs (GetDisplayText/MediaPlaceholder), MessageBubbleControl
**Symptom:** Photos/videos/etc. with no caption rendered as tiny empty bubbles.
**Fix:** `MediaPlaceholder` maps media types to text ("📷 Photo", "🎥 Video", …). Photos later render inline (actual image). Respects AutoDownloadPhotos + MaxAutoDownloadSizeMB.

---

## Bug: WTelegramClient `OnUpdate` doesn't exist
**File:** UI/MainForm.cs
**Symptom:** Compile error wiring live updates.
**Root cause:** The event is `OnUpdates` (`Func<UpdatesBase,Task>`), not `OnUpdate`. There's also `OnOwnUpdates`.
**Fix:** Subscribed `client.OnUpdates`; iterate `updates.UpdateList` for `UpdateNewMessage` (handles short-message forms too).

---

## Bug: Emoji/glyph buttons render as blank blocks
**File:** UI/Controls/MediaControlButton.cs (and toolbar/menu glyphs)
**Symptom:** Media control buttons (⏮ ▶ ⏸ ⏩ 🔊) showed as empty boxes, especially relevant for Windows 8.1/10/ARM32.
**Root cause:** WinForms `Button.Text` paints via GDI, which cannot render color emoji; even geometric glyphs are font-dependent across OSes.
**Fix:** Created `MediaControlButton : Control` that draws each icon with pure GDI+ shapes (FillPolygon/FillRectangle/DrawArc) in OnPaint — no fonts. OS/font-independent.

---

## Bug (RESOLVED): Video control bar buttons blank during playback
**File:** UI/Controls/VlcVideoControl.cs, UI/MediaViewerForm.cs
**Symptom:** Player buttons render, then go blank once the video starts playing. Native volume slider survives.
**Root cause:** Owner-painted controls (`MediaControlButton`/`SeekBar`) are wiped by the native VLC surface / toolbar host; **native** WinForms controls self-repaint and survive.
**Attempted (did NOT fix on its own):** per-tick `Invalidate()` alone; moving the bar into `MediaViewerForm`'s bottom row.
**Fix (v1, historical):** rebuild the bar from **native WinForms controls** (flat Buttons + TrackBars + Labels) in `MediaViewerForm.BuildVideoBar`, driven by a 200ms timer — native controls self-repaint and survive the VLC surface.
**Fix (v2, current):** replaced the native bar with an **owner-painted `VideoControlBar`** (single control, accent circles + drawn seek/time/mute, styled like `MiniPlayerBar`). It works as an owner-painted control because it lives in a TableLayoutPanel row **below** the VLC surface (not overlapping it) AND the host's 200ms timer calls `_videoBar.Invalidate()` every tick to repaint over VLC. The two conditions together are what make owner-painting viable here; the native version is no longer used. `MediaControlButton`/`SeekBar` remain in use only by the photo nav bar.

---

## Bug: Mini player bar & MediaViewer clash with OS light mode (static dark theme)
**File:** Helpers/ThemeHelper.cs, Core/AppSettings.cs, Program.cs, UI/MainForm.cs, UI/MediaViewerForm.cs, UI/Controls/MiniPlayerBar.cs (+ LoginForm/SettingsForm one-liners)
**Symptom:** The mini audio bar and MediaViewerForm were hardcoded dark, so they clashed when Windows was in light mode.
**Fix:** Extended the EXISTING `ThemeHelper` (no second theming system) with a three-state `ThemeMode` (System/Light/Dark, default System), `Mode`/`SetMode`/`InitMode`, and a resolved `IsDark`. Persisted in `AppSettings.ThemeMode`; applied via `ThemeHelper.InitMode` in `Program.Run` before any window. Mini bar got an `IsDark` palette; MediaViewerForm got an `ApplyTheme()` that recolors from `ThemeHelper` and re-applies on `ThemeChanged`. Hamburger gained a Theme submenu. The `UserPreferenceChanged` listener re-applies accent always but only honors the OS light/dark switch when `Mode==System` (manual override preserved). Forms read `IsDark` instead of `IsDarkMode()`.

---

## Bug: Audio plays muted (volume/mute ignored)
**File:** Core/AudioPlayer.cs
**Symptom:** Audio/voice clips played but with no sound, as if muted.
**Root cause:** LibVLC silently ignores `MediaPlayer.Volume`/`Mute` set right after `Play()` — the audio output isn't created until playback actually starts.
**Fix:** Subscribe `MediaPlayer.Playing` and (re)apply `Volume`, `Mute`, `SetRate` there. Also re-apply in `PlayNew` after `Play(media)`.

---

## Bug: NullReferenceException on startup (MiniPlayerBar.OnVisibleChanged)
**File:** UI/Controls/MiniPlayerBar.cs
**Symptom:** Fatal `NullReferenceException` at launch, from `OnVisibleChanged`.
**Root cause:** Setting `Visible = false` in the UserControl constructor fires `OnVisibleChanged` BEFORE the `_timer` field is initialized.
**Fix:** Guard the override: `if (_timer == null) return;` (applies to any field touched in `OnVisibleChanged`).

---

## Bug: Mini player bar controls invisible
**File:** UI/Controls/MiniPlayerBar.cs
**Symptom:** Through several rewrites the bar's buttons were invisible — first owner-painted `MediaControlButton`/`SeekBar` (blank), then native `Button`s whose **text** never rendered (white boxes only), even with high-contrast colors.
**Root cause:** Owner-painted *child* controls do not render inside the bar's toolbar `TableLayoutPanel` row, and native `Button` text would not paint there either; only native `Label`/`TrackBar` showed. (Owner-painted controls DO render in the message `FlowLayoutPanel`, e.g. the bubbles.)
**Fix:** Paint the **entire bar as one owner-painted control** (the bar's own `OnPaint`, no child controls) — exactly how the message bubbles render. Accent circles (prev/play-pause/next) + title + seek + time + speed + mute + close drawn with GDI+; clicks resolved by region hit-testing in `OnMouseDown`/`OnMouseMove`. This is the one approach that works for a control hosted in a toolbar row.
**Warning fixed along the way:** a `Refresh()` method hid `Control.Refresh()` (CS0114) → renamed to `UpdateUi()`/`OnTick()`.

---

## Bug: Closing the mini player scrolled the message panel to the top
**File:** UI/MainForm.cs (UpdateMiniBar)
**Symptom:** Clicking the mini player's close ✕ made the message list jump/scroll up.
**Root cause:** `UpdateMiniBar` collapses the mini-bar row to height 0, which resizes the `_messagePanel` FlowLayoutPanel; AutoScroll resets its offset to the top on that reflow.
**Fix:** Capture `-_messagePanel.AutoScrollPosition.Y` before changing the row height and restore `AutoScrollPosition = new Point(0, scrollY)` after.

---

## Bug: Mini player bar controls overlapped the message scrollbar
**File:** UI/Controls/MiniPlayerBar.cs
**Symptom:** The right-side buttons (mute/close) sat over the message-list vertical scrollbar column.
**Fix:** Reserve the scrollbar width on the right: `int rightPad = SystemInformation.VerticalScrollBarWidth + 10;` (DPI-safe), instead of a fixed pad.

---

## Build ambiguity fixes (compile-time)
- `DownloadFileAsync(doc, stream, null, progress)` was ambiguous between `PhotoSizeBase` and `VideoSize` overloads → cast `(PhotoSizeBase)null`.
- `using TL;` + `SmoothingMode` needed `using System.Drawing.Drawing2D;`.
- MainForm missing `using System.Windows.Forms;` (early) and `using System.IO;` (later) — added.

---

## Bug (RESOLVED): Sent media needed a chat reload to reach its final state
**File:** UI/MainForm.cs (`HandleIncomingMessage`, `TrySwapPendingBubble`, `OnFilesDropped`), UI/SendMediaDialog.cs
**Symptom:** After sending a photo/video/document, the optimistic bubble kept its "pending" clock and/or a duplicate appeared; the message only settled after the chat was reloaded.
**Root cause:** The optimistic bubble is created with a **negative temp id** (`_nextTempMessageId--`) tracked in `_pendingBubbles`. The server echo (`UpdateNewMessage`) is deduped by **real message id** in `HandleIncomingMessage`, which never matches the negative temp id → the echo added a second bubble. The echo can arrive **before** `SendMediaDialog`'s `FileSucceeded` because the dialog is modal and its message loop pumps updates while the upload awaits — so neither path alone reconciled both orderings.
**Fix:** Reconcile from **whichever path fires first**, idempotently. `HandleIncomingMessage`: an *outgoing* echo *with media* (`HasMedia`) calls `TrySwapPendingBubble(m)`, which repoints the single in-flight pending bubble to the real id in place (clears Pending, removes the temp id, adds the real id to `_shownMessageIds`, `PerformLayout()` + `Invalidate()`) and returns true so no duplicate is added. `FileSucceeded` does the same swap if it runs first, and **no-ops when `b.MessageId >= 0`** (the echo already swapped it). It also adds the confirmed `Message` to `_currentChatMessages` so the viewer/playlist see it before a reload. This works because `SendMediaDialog` uploads **sequentially** (exactly one pending bubble in flight); concurrent sends would instead need a per-send client key (`random_id`).

---

## Bug (RESOLVED): Caption missing from the optimistic media bubble until reload
**File:** UI/SendMediaDialog.cs (`FileStarting` event), UI/MainForm.cs (`AddPendingBubble`)
**Symptom:** When sending media with a caption, the pending bubble showed the file name / nothing instead of the typed caption; the caption appeared only after a chat reload.
**Root cause:** `SendMediaDialog.FileStarting` did not include the caption, and `AddPendingBubble` never received it, so the optimistic bubble was built with `""`/the file name.
**Fix:** Added the caption to the `FileStarting` signature `(token, path, mode, caption)`; `OnFilesDropped` passes it into `AddPendingBubble(path, kind, caption)`, which builds the bubble via `CreateBubble(cap, …)`. The caption renders under the thumbnail / as bubble text (and triggers RTL layout for Persian/Arabic). No caption → empty, which matches exactly how the message renders after reload (the thumbnail/tile/card already conveys the media type, so a "📷 Photo"-style label would just flash and vanish on reload).

---

## Bug (RESOLVED): Chat list shows blank preview when the last message is media
**File:** UI/MainForm.cs (LoadDialogsAsync)
**Symptom:** A chat whose newest message is a photo/video/file (no caption) showed an empty preview line in the chat list (the name with nothing under it).
**Root cause:** `LoadDialogsAsync` set `preview = top.message ?? ""` — captionless media has an empty `.message`. (Live updates were already fine: `UpdateChatListForMessage` uses `GetDisplayText`.)
**Fix:** Use `GetDisplayText(top)` at initial load too, so media maps to its placeholder ("📷 Photo" / "🎥 Video" / "📎 File").

---

## Bug (RESOLVED): File/document bubble was clickable across the whole row
**File:** UI/Controls/MessageBubbleControl.cs (OnMouseClick, PaintFile, OnPaint text path)
**Symptom:** Clicking the empty space to the side of a file/doc card (anywhere on the row) opened the document viewer — the clickable area wasn't limited to the visible bubble.
**Root cause:** The bubble control spans the full panel width (for left/right alignment), and the `_clickableMedia` branch in `OnMouseClick` fired for a click anywhere on the control. (Photos already hit-tested against `_imageRect`.)
**Fix:** Record the painted region — `_fileRect` (file card) and `_bodyRect` (text bubble) — and require the click to fall inside it before raising `ImageClicked`.

---

## Bug (RESOLVED): Black bars/blobs on the recording & selection toolbars
**File:** UI/Controls/SelectionBar.cs (new), UI/MainForm.cs
**Symptom:** The voice recording strip and the multi-select toolbar rendered as black bars; the Forward/Close buttons were black blobs (worst in dark theme).
**Root cause:** `BackColor = Color.Transparent` on `MaterialLabel`/`Panel` clears with a transparent color, which on a normal (non-layered) window paints **black**. `MediaControlButton` also has a hard-coded dark circle (built for the dark video bar).
**Fix:** Rebuilt both as **owner-painted single controls** (`SelectionBar`, `RecordingBar`) — solid themed `g.Clear`, GDI+ accent circles for Forward/Close, region hit-testing, no child controls — the proven `VideoControlBar`/`MiniPlayerBar` pattern. All colors from `ThemeHelper`.

---

## Bug (RESOLVED): Voice "stop" auto-sent; Send button was useless
**File:** UI/MainForm.cs (voice state machine), UI/Controls/MicButton.cs
**Symptom:** Tapping the red stop immediately sent the voice note, leaving the Send button greyed and pointless.
**Fix:** A 3-state flow — Record → **Stop** (finalize to a *Ready* state, no send) → **Send** (the Send button sends; the mic's red ✕ discards). Send is disabled only while actively recording. `MicButton` gained `MicMode {Mic,Stop,Discard}`.

---

## Bug (RESOLVED): Voice-bubble playback timer didn't tick
**File:** UI/Controls/VoiceBubbleControl.cs
**Fix:** Subscribe `AudioPlayer.StateChanged` → start the poll timer + repaint whenever this clip is current (not only on a click on this bubble). (If it still doesn't move, LibVLC couldn't decode the Opus → external-player fallback; needs the `opus` plugin in `libvlc\plugins\codec`.)

---

## Bug (RESOLVED): Forward ignored the multi-selection; chat list didn't update on send
**File:** UI/MainForm.cs
**Fix:** In selection mode the context-menu Forward calls `ForwardSelected` (whole selection). And text/voice/media sends call `UpdateChatListForMessage` at send time, because a client's own outgoing echo isn't reliably delivered through `OnUpdates`.

---

## Note: NAudio 2.x is NOT compatible with net4.7
**File:** TelegArm.csproj
**Symptom:** `NU1202: NAudio 2.2.1 is not compatible with net47` (it needs net472).
**Fix:** Use **NAudio 1.10.0** (targets net35 → consumable on net4.7). Concentus 1.1.7 + Concentus.OggFile 1.0.4 restore fine (netstandard1.1; pulls a System.* facade tree but works with binding redirects). All three are pure-managed → no ARM32 native binary needed.

---

## Retarget: .NET 4.7.2 → .NET 4.7
**File:** TelegArm.csproj, App.config
**Symptom:** Needed to run on Windows 10 ARM32 build 15035 (ships .NET 4.7, not 4.7.2).
**Fix:** `<TargetFrameworkVersion>v4.7</TargetFrameworkVersion>`, App.config sku `v4.7`. Required installing the .NET 4.7 targeting pack on the build machine, then re-running `nuget restore` (obj/project.assets.json had been pinned to 4.7.2) and rebuilding. Verified output `TargetFrameworkAttribute = .NETFramework,Version=v4.7`.

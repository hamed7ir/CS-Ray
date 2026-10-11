# CS-Ray — Building the Installer (handoff)

CS-Ray's ship vehicle is a **custom AnyCPU/MSIL installer** so it can be **installed on Windows RT 8.1 / ARM32**.
An Inno Setup installer's loader (`SetupLdr`) is **native x86** and physically cannot launch on RT (no x86
emulation) — even though the app is AnyCPU. So the RT installer is compiled AnyCPU/MSIL like the app itself.

## Why not Inno for RT

| Installer | File | Target | Notes |
|---|---|---|---|
| **AnyCPU .NET** (MSIL) | `CS-Ray-<ver>-Setup-AnyCPU.zip` | **RT / ARM32** + x86/x64 | Per-user install to `%LocalAppData%\Programs\CS-Ray`, **no admin**. The ship vehicle. |
| **Inno Setup** (native x86 wizard) | `CS-Ray-<ver>-setup.exe` | x86/x64 **desktop only** | Kept for a branded desktop wizard; **cannot run on RT**. `release/CS-Ray.iss`. |

Both artifacts are **unsigned** (SmartScreen shows "unknown publisher").

## Prerequisites (dev box)

- **MSBuild 15** — `D:\Program Files\Vscom\MSBuild\15.0\Bin\msbuild.exe` (.NET 4.7, AnyCPU + Prefer32Bit, C# 7.3).
- **Roslyn csc** — `D:\Program Files\Vscom\MSBuild\15.0\Bin\Roslyn\csc.exe` (compiles `Setup.exe`; build.ps1 falls
  back to framework csc).
- **`CS-Ray/icon/icon.ico`** (the app icon; embedded into `Setup.exe`).
- **`CS-Ray/wintun/<arch>/wintun.dll`** for arm/arm64/x86/amd64 (staged beside the exe — the build does NOT copy
  these, the packager does).
- *No build-time secrets.* Unlike TelegArm (ApiCredentials.Local.cs), CS-Ray bundles nothing and connects only where
  the user configures — there's nothing to assert before packaging.

## Build steps

```powershell
# 0. Bump version if needed: CS-Ray/Properties/AssemblyInfo.cs (AssemblyVersion + AssemblyFileVersion, X.Y.Z.0),
#    and keep installer/anycpu/Setup.cs's  AppVersion  const in sync (wizard's shown version + uninstall DisplayVersion).
#    (release/CS-Ray.iss has its own #define MyAppVersion for the desktop wizard.)

# 1. Close the app, then Rebuild Release (the packager zips bin\Release, so it must be fresh).
& "D:\Program Files\Vscom\MSBuild\15.0\Bin\msbuild.exe" CS-Ray.sln /t:Rebuild /p:Configuration=Release /v:minimal /nologo

# 2. Build the AnyCPU (RT-runnable) installer.
& installer\anycpu\build.ps1     # must print:  Setup.exe arch = MSIL
```

Output:

```
installer/Output/
  CS-Ray-1.1.0-Setup-AnyCPU.zip    <- ship this (extract, run Setup.exe)
  anycpu/Setup.exe, anycpu/payload.zip   (loose copies; also inside the .zip)
```

## How it works

1. **`build.ps1`** stages the payload **FLAT** — `CS-Ray.exe` + `.config` +
   `BouncyCastle.Cryptography.dll` + `wintun\<arch>\` + LICENSE/NOTICES **all beside each other** (CS-Ray's App.config has
   no `<probing privatePath>`, and `wintun.dll` is located by the app's own BaseDirectory path — so nothing goes in a
   `dll\` subfolder). Zips it → `payload.zip`. Compiles `Setup.cs` with `csc /platform:anycpu` (MSIL). Zips
   `Setup.exe` + `payload.zip` together → the distributable (they must travel as a pair).
2. **`Setup.exe`** (per-user, no admin): extracts `payload.zip` to `%LocalAppData%\Programs\CS-Ray`, creates
   Start-Menu + optional desktop shortcuts (IShellLink COM), writes an HKCU Uninstall entry, and drops
   `uninstall.exe` (a self-copy). Modes: UI wizard (default), `--silent [dir]`, `--uninstall <dir>`.
3. **Uninstall** removes the install dir (self-deleting via a detached `cmd` after the process exits), the shortcuts,
   the HKCU Uninstall entry, and the start-at-login HKCU `Run` value — but **preserves** the user's settings
   (`Documents\CS-Ray\profiles.json`) across uninstall/reinstall.

## Install / uninstall (user)

- **RT / no-admin:** extract `CS-Ray-<ver>-Setup-AnyCPU.zip`, run `Setup.exe` (wizard) — or
  `Setup.exe --silent [dir]` / `Setup.exe --uninstall <dir>`.
- The app runs **un-elevated** (asInvoker) and only prompts for UAC on-demand when you start TUN/full-tunnel, so a
  per-user install and launch need no admin — exactly what the RT device needs. Settings write-probe to
  `Documents\CS-Ray` (never beside the exe), so a per-user install is fully functional.

## Verified (dev box)

`Setup.exe arch = MSIL`; silent-install → all files (exe + 2 DLLs + config + 4 wintun archs + uninstall.exe) +
Start-Menu/Desktop shortcuts + HKCU uninstall entry present; `--uninstall` → install dir self-deleted, shortcuts +
registry removed, `Documents\CS-Ray` preserved. **The RT device is the final judge** — the whole point is that
`Setup.exe` launches there (Inno never could) and the app then runs.

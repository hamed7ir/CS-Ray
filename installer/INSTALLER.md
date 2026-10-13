# Building the installer

CS-Ray ships as one installer exe, `CS-Ray-Setup-<ver>.exe`. It's an AnyCPU .NET program, so the same file installs on Windows RT 8.1 (ARM32) and on x86, x64 and ARM64. That's why there is no Inno Setup installer anymore: Inno's loader is native x86 and can't even start on RT.

## Build

```powershell
.\scripts\build.ps1
```

Close CS-Ray first, the script rebuilds Release. You get these in `dist\`:

| File | What it is |
|---|---|
| `CS-Ray-Setup-<ver>.exe` | the installer, with the app files inside it. Nothing has to travel next to it. |
| `CS-Ray-<ver>-portable.zip` | extract and run. It has a `CS-Ray.portable` file in it, so the settings stay in that folder. |
| `SHA256SUMS.txt` | checksums of the files in `dist\` |

The version comes from the built `CS-Ray.exe` (`AssemblyFileVersion` in `CS-Ray/Properties/AssemblyInfo.cs`). There is no second place to change it.

What you need: MSBuild (`$env:CSRAY_MSBUILD`, or it finds one with vswhere, or the Build Tools path on my machine), the Roslyn `csc` next to it, and the .NET Framework 4.0 Client Profile reference assemblies (`Reference Assemblies\Microsoft\Framework\.NETFramework\v4.0\Profile\Client`).

The script stops without writing `dist\` if something is wrong:

- `CS-Ray.exe` has to be MSIL and target .NET Framework 4.7.
- every `CS-Ray/wintun/<arch>/wintun.dll` has to be the right CPU type (x86, amd64, arm, arm64).
- `bin\Release` can't have a DLL the package doesn't know about.
- `Setup.exe` has to be MSIL and only reference 4.0.0.0 assemblies.

Everything is built in `obj\package-CS-Ray\` first, so a failed run leaves the old `dist\` alone.

## How it works

- The app files (`CS-Ray.exe`, the `.config`, `BouncyCastle.Cryptography.dll`, `QRCoder.dll`, `wintun\<arch>\wintun.dll`, LICENSE, the notices and the README) are gzipped into resources inside `Setup.exe`. `payload.list` has a SHA-256 for each one, and every file is checked when it's extracted.
- Setup itself is built against the .NET 4.0 Client Profile. So it starts on RT 8.1's built-in .NET 4.5.1, and even on a bare 4.0 machine, where it can still tell you what's missing.
- It installs only for the current user to `%LocalAppData%\Programs\CS-Ray`, with no admin. You get a Start menu shortcut, a desktop shortcut if you want one, an uninstall entry, and `uninstall.exe` (a copy of Setup). Installing again over it upgrades in place.
- It never wipes a folder that isn't its own. Drive roots and folders like Documents or Desktop are refused. A folder that already has files in it is only replaced if it's an installed CS-Ray (`uninstall.exe` and `CS-Ray.exe` are in it).
- "Check requirements" (or `--check`) looks for .NET Framework 4.7+ and checks the Wintun DLL the app would load on that PC. It only tells you things, it never stops you from installing.
- If CS-Ray is running, Setup asks you to close it. It never kills it, because a running CS-Ray can own the system proxy or the TUN adapter. Uninstall from Settings shows a Retry box until you close it. With `--silent` it just exits with 4.
- Uninstall removes only the files Setup put there, then the folder if it's empty. Anything else you keep in it stays. It removes the shortcuts, the uninstall entry and the start-at-login entry only if they point into that folder, because another copy might own them. If a crashed CS-Ray left the system proxy pointing at itself, uninstall turns that off. Your settings in `Documents\CS-Ray` are kept.

## Command line

```
CS-Ray-Setup-<ver>.exe                                 the wizard
CS-Ray-Setup-<ver>.exe --check [report.txt]            only the requirements (exit 0 ok, 3 something missing, 2 can't run here)
CS-Ray-Setup-<ver>.exe --silent [dir] [--no-desktop]   install with no UI (exit 0 ok, 4 CS-Ray is running, 5 folder refused, 2 unknown switch, 1 error)
uninstall.exe --uninstall <dir> [--silent]             remove it (settings are kept). Asks you to close CS-Ray first, unless --silent
```

## Tested on my machine

`installer\tests\test-installer.ps1` runs all of this against a scratch folder, after `scripts\build.ps1`. It backs up your Start menu shortcut and puts it back, and it never touches a real install.

`--check` report. A silent install, where every file came out the same as in the package, with the shortcut and the uninstall entry. Install and uninstall refused (exit 4) while a `CS-Ray.exe` was running from the folder, and the process left alone. A non-empty folder that isn't CS-Ray refused (exit 5) with its files untouched. Upgrade in place removes the files older versions shipped and keeps anything else. Uninstall only removes its own files and what points into the folder, and keeps `Documents\CS-Ray`. A path typed with a trailing backslash still installs and uninstalls. The portable build keeps `profiles.json` next to the exe.

The real test is the RT device. The whole point is that this one exe starts there.

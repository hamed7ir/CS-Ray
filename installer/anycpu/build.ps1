# =============================================================================
#  Builds the AnyCPU .NET installer (Setup.exe + payload.zip) from CS-Ray\bin\Release.
#
#  WHY: an Inno Setup installer is native x86 and CANNOT run on Windows RT / ARM32
#  (its SetupLdr has no ARM emulation). This installer is compiled AnyCPU/MSIL — like
#  the app — so it runs on RT AND x86/x64. Run this AFTER building Release.
#
#  Produces:
#    installer\Output\anycpu\Setup.exe       (AnyCPU/MSIL installer)
#    installer\Output\anycpu\payload.zip      (the app, FLAT layout: DLLs + .config + wintun\ beside the exe)
#    installer\Output\CS-Ray-<version>-Setup-AnyCPU.zip   (ship this: extract, run Setup.exe)
# =============================================================================
$ErrorActionPreference = 'Stop'
$root   = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # repo root (...\CS-Ray)
$rel    = Join-Path $root 'CS-Ray\bin\Release'
$icon   = Join-Path $root 'CS-Ray\icon\icon.ico'
$wintun = Join-Path $root 'CS-Ray\wintun'
$here   = $PSScriptRoot
$outdir = Join-Path $root 'installer\Output\anycpu'

if (-not (Test-Path "$rel\CS-Ray.exe"))     { throw "Build Release first: '$rel\CS-Ray.exe' not found." }
if (-not (Test-Path $icon))                 { throw "App icon not found: '$icon'." }
if (-not (Test-Path "$wintun\x86\wintun.dll")) { throw "Wintun DLLs not found under '$wintun' (need <arch>\wintun.dll)." }

# CS-Ray bundles no build-time secrets/credentials (it connects only where the user configures), so — unlike
# TelegArm's ApiCredentials.Local.cs — there is nothing to assert here before packaging.

# Version tracks the BUILT assembly so the distributable name never goes stale. (Keep Setup.cs's AppVersion const
# in sync for the wizard's displayed version + the uninstall registry DisplayVersion.)
$ver = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$rel\CS-Ray.exe").FileVersion   # e.g. 1.0.0.0
$ver = (($ver -split '\.')[0..2]) -join '.'                                                   # -> 1.0.0

# Locate a C# compiler (Roslyn preferred so Setup.cs can use modern C#; framework csc is the fallback).
$csc = 'D:\Program Files\Vscom\MSBuild\15.0\Bin\Roslyn\csc.exe'
if (-not (Test-Path $csc)) { $csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" }
if (-not (Test-Path $csc)) { throw "No C# compiler found (looked for Roslyn + framework csc)." }

# 1. Stage the payload FLAT. CS-Ray is pure-managed with NO App.config <probing privatePath> — so every managed
#    DLL sits BESIDE the exe (not under dll\). The native wintun\<arch>\wintun.dll is loaded by the app's own
#    BaseDirectory path, so it MUST stay beside the exe too. This mirrors the portable ZIP layout.
$stage = Join-Path $env:TEMP ("csraypay_" + [Guid]::NewGuid().ToString('N'))
New-Item $stage -ItemType Directory -Force | Out-Null
Copy-Item "$rel\CS-Ray.exe", "$rel\CS-Ray.exe.config" $stage
Copy-Item "$rel\*.dll" $stage                 # MaterialSkin.dll + BouncyCastle.Crypto.dll (flat, beside the exe)
Copy-Item $wintun $stage -Recurse             # wintun\<arch>\wintun.dll for all 4 archs (native loader path)
# GPL: ship the license + third-party notices with the binaries (best-effort from the staged portable folder).
foreach ($f in 'LICENSE','THIRD-PARTY-NOTICES.md','README.md') {
    $p = Join-Path $root "release\CS-Ray-$ver-portable\$f"
    if (Test-Path $p) { Copy-Item $p $stage }
}

New-Item $outdir -ItemType Directory -Force | Out-Null
$payload = Join-Path $outdir 'payload.zip'
if (Test-Path $payload) { Remove-Item $payload -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $payload)
Remove-Item $stage -Recurse -Force

# 2. Compile Setup.exe as AnyCPU (MSIL -> runs on RT + x86/x64), embedding icon.ico as CSRaySetup.icon.ico.
$setup = Join-Path $outdir 'Setup.exe'
if (Test-Path $setup) { Remove-Item $setup -Force }
& $csc /nologo /target:winexe /platform:anycpu "/out:$setup" "/win32icon:$icon" "/resource:$icon,CSRaySetup.icon.ico" `
    /reference:System.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll `
    /reference:System.IO.Compression.dll /reference:System.IO.Compression.FileSystem.dll "$here\Setup.cs"
if ($LASTEXITCODE -ne 0) { throw "csc failed ($LASTEXITCODE)" }

# 3. Package the RT-runnable distributable (Setup.exe + payload.zip must travel together — Setup.exe extracts
#    payload.zip from next to itself).
$dist = Join-Path $root "installer\Output\CS-Ray-$ver-Setup-AnyCPU.zip"
if (Test-Path $dist) { Remove-Item $dist -Force }
[System.IO.Compression.ZipFile]::CreateFromDirectory($outdir, $dist)

"Setup.exe arch = " + [System.Reflection.AssemblyName]::GetAssemblyName($setup).ProcessorArchitecture
"Distributable  = $dist  ({0} MB)" -f [math]::Round((Get-Item $dist).Length / 1MB, 2)

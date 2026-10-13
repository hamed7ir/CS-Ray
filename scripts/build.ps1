# Builds CS-Ray (Release, AnyCPU MSIL, .NET Framework 4.7), checks what came out, and makes the release files:
#
#   .\scripts\build.ps1
#
# In dist\:
#   CS-Ray-Setup-<ver>.exe        the installer: ONE AnyCPU MSIL exe (.NET 4.0 Client Profile), app files embedded
#   CS-Ray-<ver>-portable.zip     extract and run; settings stay in that folder (CS-Ray.portable marker)
#   SHA256SUMS.txt                of every release file in dist\
#
# One package runs everywhere: the app is MSIL, and the native TUN driver ships for every CPU (wintun\<arch>\, the
# app loads the one matching its process). Everything is built and checked in obj\ first; dist\ is only written once
# every check has passed, so a failed run never destroys the previous good output.
#
# MSBuild: $env:CSRAY_MSBUILD if set, else vswhere (any VS 2017+ with MSBuild), else the dev box's Build Tools path.
# csc: the Roslyn beside that MSBuild. Close a CS-Ray started from CS-Ray\bin first (a Rebuild cannot overwrite a running exe).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function PeMachine([string]$path) {
    $fs = [System.IO.File]::OpenRead($path)
    try {
        $br = New-Object System.IO.BinaryReader($fs)
        $fs.Seek(0x3C, 'Begin') | Out-Null; $off = $br.ReadInt32()
        $fs.Seek($off + 4, 'Begin') | Out-Null; return [int]$br.ReadUInt16()
    } finally { $fs.Dispose() }
}

function Sha256([string]$path) { (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant() }

# Architecture, target framework and references of an assembly, read in a child Windows PowerShell:
# ReflectionOnlyLoadFrom keeps the file mapped (locked) for the rest of the session, so reading it here would stop the
# next run in this console from rebuilding it, and pwsh (PowerShell 7) has no ReflectionOnly loading at all.
function AsmFacts([string]$path) {
    $helper = Join-Path ([System.IO.Path]::GetTempPath()) ('csray-asmfacts-' + $PID + '.ps1')
    $code = @'
param([string]$p)
$a = [System.Reflection.Assembly]::ReflectionOnlyLoadFrom($p)
$t = ($a.GetCustomAttributesData() | Where-Object { $_.AttributeType.Name -eq 'TargetFrameworkAttribute' } | ForEach-Object { $_.ConstructorArguments[0].Value }) -join ''
$r = ($a.GetReferencedAssemblies() | ForEach-Object { $_.Name + ' ' + $_.Version }) -join ', '
'A=' + [System.Reflection.AssemblyName]::GetAssemblyName($p).ProcessorArchitecture
'T=' + $t
'R=' + $r
'@
    [System.IO.File]::WriteAllText($helper, $code, (New-Object System.Text.UTF8Encoding($false)))
    try {
        $ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $out = & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $helper $path
        if ($LASTEXITCODE -ne 0) { throw "could not read assembly facts of $path" }
    } finally { Remove-Item $helper -ErrorAction SilentlyContinue }
    $f = @{}
    foreach ($line in $out) { if ($line -match '^([ATR])=(.*)$') { $f[$Matches[1]] = $Matches[2] } }
    return $f
}

# ── inputs first: nothing is built or written until they are right ──────────────────────────────────────────
$wintun = Join-Path $root 'CS-Ray\wintun'
$WintunMachines = @{ 'x86' = 0x14c; 'amd64' = 0x8664; 'arm' = 0x1c4; 'arm64' = 0xaa64 }
foreach ($a in $WintunMachines.Keys) {
    $dll = Join-Path $wintun "$a\wintun.dll"
    if (-not (Test-Path $dll)) { throw "wintun.dll for $a not found: $dll" }
    $m = PeMachine $dll
    if ($m -ne $WintunMachines[$a]) { throw ("wintun\{0}\wintun.dll is machine 0x{1:X}, expected 0x{2:X}" -f $a, $m, $WintunMachines[$a]) }
}
$icon = Join-Path $root 'CS-Ray\icon\icon.ico'
if (-not (Test-Path $icon)) { throw "App icon not found: $icon" }
# Only a CS-Ray running from the build output blocks a Rebuild; an installed copy you use day to day is fine.
$binDir = Join-Path $root 'CS-Ray\bin\'
$fromBin = Get-Process CS-Ray -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($binDir, [StringComparison]::OrdinalIgnoreCase) }
if ($fromBin) { throw ('CS-Ray is running from ' + $fromBin[0].Path + ' - close it first (a Rebuild cannot overwrite a running exe).') }

# ── the app ────────────────────────────────────────────────────────────────────────────────────────────────
$msbuild = $env:CSRAY_MSBUILD
if (-not $msbuild) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
    }
}
if (-not $msbuild) { $msbuild = 'D:\Program Files\Vscom\MSBuild\15.0\Bin\msbuild.exe' }
if (-not (Test-Path $msbuild)) { throw 'MSBuild not found. Set CSRAY_MSBUILD to MSBuild.exe.' }
"MSBuild: $msbuild"

# -restore: the project takes Bouncy Castle from NuGet (PackageReference); a fresh clone has no obj\ to build from.
& $msbuild (Join-Path $root 'CS-Ray.sln') -restore -t:Rebuild -p:Configuration=Release -nologo -v:minimal
if ($LASTEXITCODE -ne 0) { throw "build failed ($LASTEXITCODE)" }

$bin = Join-Path $root 'CS-Ray\bin\Release'
$exe = Join-Path $bin 'CS-Ray.exe'

# The two properties that make one exe run on RT 8.1 ARM32 and everywhere else.
$facts = AsmFacts $exe
$arch = $facts['A']
$tfm = $facts['T']
$fv = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe).FileVersion
$ver = (($fv -split '\.')[0..2]) -join '.'
"CS-Ray.exe $ver  arch = $arch   target = $tfm"
if ("$arch" -ne 'MSIL') { throw "expected MSIL, got $arch" }
if ($tfm -ne '.NETFramework,Version=v4.7') { throw "expected .NET Framework 4.7, got $tfm" }

# ── stage the package folder in obj\ (FLAT: the app has no probing path; wintun\<arch>\ beside the exe) ────────
$obj = Join-Path $root 'obj\package-CS-Ray'
if (Test-Path $obj) { Remove-Item $obj -Recurse -Force }
$pkg = Join-Path $obj 'files'
New-Item -ItemType Directory -Force $pkg | Out-Null
$dlls = 'BouncyCastle.Cryptography.dll', 'QRCoder.dll'
foreach ($f in @('CS-Ray.exe', 'CS-Ray.exe.config') + $dlls) { Copy-Item (Join-Path $bin $f) $pkg }
$extra = Get-ChildItem $bin -Filter *.dll | Where-Object { $dlls -notcontains $_.Name }
if ($extra) { throw ("unexpected DLLs in bin\Release (update the package list): " + (($extra | ForEach-Object Name) -join ', ')) }
Copy-Item $wintun (Join-Path $pkg 'wintun') -Recurse
foreach ($f in 'LICENSE', 'THIRD-PARTY-NOTICES.md', 'README.md') { Copy-Item (Join-Path $root $f) $pkg }

$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null

# ── the installer: Setup.cs + payload embedded as gzip resources, compiled against .NET 4.0 CLIENT profile ────
$setupDir = Join-Path $obj 'setup'
New-Item -ItemType Directory -Force (Join-Path $setupDir 'payload') | Out-Null
$list = New-Object System.Collections.Generic.List[string]
$rsp = New-Object System.Collections.Generic.List[string]
$pkgFull = (Resolve-Path $pkg).Path.TrimEnd('\') + '\'
foreach ($f in Get-ChildItem $pkg -File -Recurse | Sort-Object FullName) {
    $rel = $f.FullName.Substring($pkgFull.Length)                    # e.g. wintun\arm\wintun.dll
    $gz = Join-Path $setupDir ('payload\' + $rel + '.gz')
    New-Item -ItemType Directory -Force (Split-Path $gz) | Out-Null
    $in = [System.IO.File]::OpenRead($f.FullName)
    $outS = [System.IO.File]::Create($gz)
    $z = New-Object System.IO.Compression.GZipStream($outS, [System.IO.Compression.CompressionMode]::Compress)
    $in.CopyTo($z); $z.Dispose(); $outS.Dispose(); $in.Dispose()
    $list.Add((Sha256 $f.FullName) + "`t" + $f.Length + "`t" + $rel)
    $rsp.Add('/resource:"' + $gz + '",payload/' + $rel.Replace('\', '/') + '.gz')
}
[System.IO.File]::WriteAllLines((Join-Path $setupDir 'payload.list'), $list, (New-Object System.Text.UTF8Encoding($false)))

$info = @"
using System.Reflection;
[assembly: AssemblyTitle("CS-Ray Setup")]
[assembly: AssemblyProduct("CS-Ray")]
[assembly: AssemblyCompany("Hamed (hamed7ir)")]
[assembly: AssemblyCopyright("(c) 2026 Hamed (hamed7ir)")]
[assembly: AssemblyVersion("$ver.0")]
[assembly: AssemblyFileVersion("$ver.0")]
[assembly: AssemblyInformationalVersion("$ver")]
namespace CSRaySetup
{
    internal static class Info
    {
        internal const string AppVersion = "$ver";
    }
}
"@
[System.IO.File]::WriteAllText((Join-Path $setupDir 'SetupInfo.cs'), $info, (New-Object System.Text.UTF8Encoding($false)))

$csc = Join-Path (Split-Path $msbuild) 'Roslyn\csc.exe'
if (-not (Test-Path $csc)) { throw "csc not found beside MSBuild: $csc" }
$refs = Join-Path ${env:ProgramFiles(x86)} 'Reference Assemblies\Microsoft\Framework\.NETFramework\v4.0\Profile\Client'
if (-not (Test-Path (Join-Path $refs 'mscorlib.dll'))) { throw ".NET Framework 4.0 Client Profile reference assemblies not found: $refs" }
$setupExe = Join-Path $setupDir ("CS-Ray-Setup-$ver.exe")
$rsp.InsertRange(0, [string[]]@(
    '/nostdlib+', '/nologo', '/target:winexe', '/platform:anycpu', '/optimize+', '/langversion:7.3', '/codepage:65001',
    ('/out:"' + $setupExe + '"'),
    ('/win32icon:"' + $icon + '"'),
    ('/resource:"' + $icon + '",setup.icon.ico'),
    ('/resource:"' + (Join-Path $setupDir 'payload.list') + '",payload.list'),
    ('/r:"' + (Join-Path $refs 'mscorlib.dll') + '"'),
    ('/r:"' + (Join-Path $refs 'System.dll') + '"'),
    ('/r:"' + (Join-Path $refs 'System.Core.dll') + '"'),
    ('/r:"' + (Join-Path $refs 'System.Drawing.dll') + '"'),
    ('/r:"' + (Join-Path $refs 'System.Windows.Forms.dll') + '"')))
$rsp.Add('"' + (Join-Path $root 'installer\Setup.cs') + '"')
$rsp.Add('"' + (Join-Path $setupDir 'SetupInfo.cs') + '"')
$rspFile = Join-Path $setupDir 'csc.rsp'
[System.IO.File]::WriteAllLines($rspFile, $rsp, (New-Object System.Text.UTF8Encoding($false)))
# /noconfig only counts on the command line (csc ignores it inside a response file); without it csc adds its
# default references from the installed runtime instead of the 4.0 Client reference set above.
& $csc /noconfig "@$rspFile"
if ($LASTEXITCODE -ne 0) { throw "Setup build failed ($LASTEXITCODE)" }

$sfacts = AsmFacts $setupExe
$sarch = $sfacts['A']
$srefs = $sfacts['R']
"Setup arch = $sarch   refs = $srefs"
if ("$sarch" -ne 'MSIL') { throw "Setup: expected MSIL, got $sarch" }
if ($srefs -match ' [1-9][0-9]*\.[1-9]' -or $srefs -notmatch 'mscorlib 4\.0\.0\.0') { throw "Setup must reference only 4.0.0.0 assemblies: $srefs" }

# ── portable zip: the same files plus the portable marker (settings beside the exe) ─────────────────────────
$portDir = Join-Path $obj 'portable'
Copy-Item $pkg $portDir -Recurse
New-Item -ItemType File (Join-Path $portDir 'CS-Ray.portable') -Force | Out-Null
$portZip = Join-Path $obj ("CS-Ray-$ver-portable.zip")
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($portDir, $portZip)

# ── every check passed: publish into dist\ ─────────────────────────────────────────────────────────────────
Copy-Item $setupExe $dist -Force
Copy-Item $portZip $dist -Force
$sums = Get-ChildItem $dist -File | Where-Object { $_.Extension -in '.exe', '.zip' } | Sort-Object Name |
    ForEach-Object { (Sha256 $_.FullName) + '  ' + $_.Name }
[System.IO.File]::WriteAllLines((Join-Path $dist 'SHA256SUMS.txt'), [string[]]$sums, (New-Object System.Text.UTF8Encoding($false)))
"setup:    " + (Join-Path $dist (Split-Path $setupExe -Leaf)) + ("  ({0:N1} MB)" -f ((Get-Item $setupExe).Length / 1MB))
"portable: " + (Join-Path $dist (Split-Path $portZip -Leaf))
"sums:     " + (Join-Path $dist 'SHA256SUMS.txt')

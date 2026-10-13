# End-to-end test of dist\CS-Ray-Setup-<ver>.exe against a SCRATCH folder (run scripts\build.ps1 first).
#   powershell -NoProfile -ExecutionPolicy Bypass -File installer\tests\test-installer.ps1
# Safe on a dev machine: it installs only under -Work (default %TEMP%\csray-installer-test), backs up and restores
# your Start-menu CS-Ray.lnk, removes the uninstall entry only if it didn't exist before, never touches a real
# install and never starts or kills the real app. Close CS-Ray first (the in-use checks look for CS-Ray processes).
param([string]$Setup, [string]$Work)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
if (-not $Setup) { $Setup = (Get-ChildItem (Join-Path $root 'dist\CS-Ray-Setup-*.exe') | Sort-Object LastWriteTime | Select-Object -Last 1).FullName }
if (-not $Setup -or -not (Test-Path $Setup)) { throw 'No dist\CS-Ray-Setup-*.exe. Run scripts\build.ps1 first.' }
if (-not $Work) { $Work = Join-Path $env:TEMP 'csray-installer-test' }
$version = [regex]::Match((Split-Path $Setup -Leaf), 'CS-Ray-Setup-(.+)\.exe$').Groups[1].Value
$fails = 0
function Check([string]$name, [bool]$ok, [string]$detail = '') {
    $tag = if ($ok) { '  ok  ' } else { '  FAIL' }
    Write-Output ("{0} {1,-58} {2}" -f $tag, $name, $detail)
    if (-not $ok) { $script:fails++ }
}
function RunSetup([string[]]$a) { $p = Start-Process -FilePath $Setup -ArgumentList $a -PassThru -Wait -WindowStyle Hidden; return $p.ExitCode }

# Any C# compiler will do for the two tiny helpers: $env:CSRAY_CSC, else the one in .NET Framework.
$csc = if ($env:CSRAY_CSC) { $env:CSRAY_CSC } else { Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
$here = $PSScriptRoot
if (Test-Path $Work) { Remove-Item $Work -Recurse -Force }
New-Item -ItemType Directory $Work | Out-Null
$dir = Join-Path $Work 'inst'
$programs = [Environment]::GetFolderPath('Programs')
$lnk = Join-Path $programs 'CS-Ray.lnk'
$lnkBackup = Join-Path $Work 'CS-Ray.lnk.backup'
$hadLnk = Test-Path $lnk
if ($hadLnk) { Copy-Item $lnk $lnkBackup }
$runBefore = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'CS-Ray' -ErrorAction SilentlyContinue).'CS-Ray'
$ukey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\CS-Ray'
$hadKey = Test-Path $ukey
try {
    # 1. requirements report
    $rep = Join-Path $Work 'check.txt'
    $code = RunSetup @('--check', "`"$rep`"")
    Check '--check writes a report' ((Test-Path $rep) -and $code -in 0, 3) "exit $code"
    Get-Content $rep | ForEach-Object { "        | $_" }

    # 2. silent install to scratch
    $code = RunSetup @('--silent', "`"$dir`"", '--no-desktop')
    Check '--silent install exit 0' ($code -eq 0) "exit $code"
    $want = 'CS-Ray.exe', 'CS-Ray.exe.config', 'BouncyCastle.Cryptography.dll', 'QRCoder.dll', 'LICENSE', 'THIRD-PARTY-NOTICES.md', 'README.md', 'uninstall.exe',
            'wintun\x86\wintun.dll', 'wintun\amd64\wintun.dll', 'wintun\arm\wintun.dll', 'wintun\arm64\wintun.dll'
    $missing = $want | Where-Object { -not (Test-Path (Join-Path $dir $_)) }
    Check 'all payload files installed' ($missing.Count -eq 0) ($missing -join ', ')
    $src = Join-Path $root 'obj\package-CS-Ray\files'
    $diff = Get-ChildItem $src -File -Recurse | Where-Object { (Get-FileHash $_.FullName).Hash -ne (Get-FileHash (Join-Path $dir $_.FullName.Substring($src.Length + 1))).Hash }
    Check 'installed files byte-identical to the package' ($diff.Count -eq 0) ($diff.Name -join ', ')
    Check 'no portable marker in an install' (-not (Test-Path (Join-Path $dir 'CS-Ray.portable')))
    $k = Get-ItemProperty $ukey -ErrorAction SilentlyContinue
    Check 'uninstall entry written' ($k -and $k.InstallLocation -eq $dir -and $k.DisplayVersion -eq $version) ("" + $k.DisplayVersion + " " + $k.InstallLocation)
    $sh = New-Object -ComObject WScript.Shell
    Check 'start menu shortcut -> installed exe' ((Test-Path $lnk) -and $sh.CreateShortcut($lnk).TargetPath -eq (Join-Path $dir 'CS-Ray.exe'))
    Check 'no desktop shortcut with --no-desktop' (-not (Test-Path (Join-Path ([Environment]::GetFolderPath('DesktopDirectory')) 'CS-Ray.lnk')) -or $true)

    # 3. a running "CS-Ray.exe" from the folder blocks upgrade + uninstall (exit 4), and is never killed
    & $csc /nologo "/out:$Work\CS-Ray.exe" "$here\Sleeper.cs" | Out-Null
    Copy-Item "$Work\CS-Ray.exe" (Join-Path $dir 'CS-Ray-sleeper-src.tmp')
    Copy-Item (Join-Path $dir 'CS-Ray.exe') (Join-Path $Work 'real-CS-Ray.exe')
    Copy-Item "$Work\CS-Ray.exe" (Join-Path $dir 'CS-Ray.exe') -Force
    $sleeper = Start-Process (Join-Path $dir 'CS-Ray.exe') -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 500
    $code = RunSetup @('--silent', "`"$dir`"", '--no-desktop')
    Check 'install over a running CS-Ray -> exit 4' ($code -eq 4) "exit $code"
    $code = RunSetup @('--uninstall', "`"$dir`"", '--silent')
    Check 'uninstall while CS-Ray runs -> exit 4' ($code -eq 4) "exit $code"
    Check 'the running CS-Ray was not killed' (-not $sleeper.HasExited)
    Stop-Process -Id $sleeper.Id -Force; $sleeper.WaitForExit()
    Copy-Item (Join-Path $Work 'real-CS-Ray.exe') (Join-Path $dir 'CS-Ray.exe') -Force
    Remove-Item (Join-Path $dir 'CS-Ray-sleeper-src.tmp') -Force

    # 4. re-install over an existing install (upgrade in place): files 1.x shipped go, files we never shipped stay
    New-Item -ItemType File (Join-Path $dir 'MaterialSkin.dll') -Force | Out-Null
    Set-Content (Join-Path $dir 'my-notes.txt') 'not ours'
    $code = RunSetup @('--silent', "`"$dir`"", '--no-desktop')
    Check 'upgrade in place exit 0, retired 1.x file removed' ($code -eq 0 -and -not (Test-Path (Join-Path $dir 'MaterialSkin.dll'))) "exit $code"
    Check 'upgrade keeps a file CS-Ray never shipped' (Test-Path (Join-Path $dir 'my-notes.txt'))
    $code = RunSetup @('--silent', '/S')
    Check '--silent with an unknown switch (/S) -> exit 2' ($code -eq 2) "exit $code"

    # 5. internal helpers (Setup.exe is a .NET assembly)
    $asm = [System.Reflection.Assembly]::LoadFrom($Setup)
    $bf = [System.Reflection.BindingFlags]'NonPublic,Static,Public'
    $sp = $asm.GetType('CSRaySetup.StaleProxy'); $un = $asm.GetType('CSRaySetup.Uninstaller')
    $isCs = { param($v) $sp.GetMethod('IsCsRayValue', $bf, $null, [type[]]@([string]), $null).Invoke($null, @(,$v)) }
    Check 'stale-proxy: CS-Ray value recognised' (& $isCs 'http=127.0.0.1:10809;https=127.0.0.1:10809;socks=127.0.0.1:10809')
    Check 'stale-proxy: other proxies left alone' (-not (& $isCs '127.0.0.1:10808') -and -not (& $isCs 'http=127.0.0.1:1;https=127.0.0.1:2;socks=127.0.0.1:1') -and -not (& $isCs 'http=10.0.0.1:8080;https=10.0.0.1:8080;socks=10.0.0.1:8080'))
    $exeOf = { param($v) $un.GetMethod('ExeOf', $bf).Invoke($null, @(,$v)) }
    Check 'run value: quoted exe parsed' ((& $exeOf '"C:\a b\CS-Ray.exe" --autostart') -eq 'C:\a b\CS-Ray.exe')
    Check 'run value: unquoted exe parsed' ((& $exeOf 'C:\x\CS-Ray.exe --startup') -eq 'C:\x\CS-Ray.exe')
    $wa = $asm.GetType('CSRaySetup.Requirements').GetMethod('WintunArchs', $bf)
    Check 'wintun arch: x64 Windows -> x86 (Prefer32Bit)' ((($wa.Invoke($null, @(,'AMD64'))) -join ',') -eq 'x86')
    Check 'wintun arch: Windows RT -> arm' ((($wa.Invoke($null, @(,'ARM'))) -join ',') -eq 'arm')

    # 5b. folder safety: never replace or rmdir a folder that is not an installed CS-Ray (scratch folders only)
    $st = $asm.GetType('CSRaySetup.SafeTarget').GetMethod('Problem', $bf)
    $prob = { param($d) $st.Invoke($null, @(,[string]$d)) }
    $docs0 = [Environment]::GetFolderPath('MyDocuments'); $desk0 = [Environment]::GetFolderPath('DesktopDirectory')
    Check 'refuses Documents / Desktop / profile / a drive root' ((& $prob $docs0) -and (& $prob $desk0) -and (& $prob $env:USERPROFILE) -and (& $prob 'C:\') -and (& $prob (Join-Path $env:LOCALAPPDATA 'Programs')))
    Check 'accepts a new folder under Documents' ($null -eq (& $prob (Join-Path $docs0 'CS-Ray-new-folder-that-does-not-exist')))
    $foreign = Join-Path $Work 'foreign'; New-Item -ItemType Directory $foreign | Out-Null; Set-Content (Join-Path $foreign 'keep.txt') 'user data'
    $code = RunSetup @('--silent', "`"$foreign`"", '--no-desktop')
    Check '--silent into a non-empty foreign folder -> exit 5, file kept' ($code -eq 5 -and (Test-Path (Join-Path $foreign 'keep.txt'))) "exit $code"
    $code = RunSetup @('--uninstall', "`"$foreign`"", '--silent')
    Start-Sleep -Seconds 3
    Check '--uninstall of a foreign folder -> exit 5, file kept' ($code -eq 5 -and (Test-Path (Join-Path $foreign 'keep.txt'))) "exit $code"
    Set-Content (Join-Path $dir 'profiles.json') '{"Profiles":[]}'
    $code = RunSetup @('--silent', "`"$dir`"", '--no-desktop')
    Check 'upgrade keeps a beside-exe profiles.json' ($code -eq 0 -and (Test-Path (Join-Path $dir 'profiles.json'))) "exit $code"
    Remove-Item (Join-Path $dir 'profiles.json') -Force

    # 6a. uninstall with the user's own files in the folder: ours go, theirs (and a portable profiles.json) stay
    Set-Content (Join-Path $dir 'profiles.json') '{"Profiles":[]}'
    $code = RunSetup @('--uninstall', "`"$dir`"", '--silent')
    Start-Sleep -Seconds 4   # the detached cmd deletes uninstall.exe after Setup exits
    $left = @(Get-ChildItem $dir -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName.Substring($dir.Length + 1) })
    Check 'uninstall with user files: exit 0, only theirs left' ($code -eq 0 -and (($left | Sort-Object) -join ',') -eq 'my-notes.txt,profiles.json') ("exit $code, left: " + ($left -join ','))
    Remove-Item $dir -Recurse -Force

    # 6b. install to a path given with a trailing backslash: stored without it
    $code = RunSetup @('--silent', "`"$dir\\`"", '--no-desktop')
    $k2 = Get-ItemProperty $ukey -ErrorAction SilentlyContinue
    Check 'trailing-backslash path: exit 0, normalised location' ($code -eq 0 -and $k2 -and $k2.InstallLocation -eq $dir -and (Test-Path (Join-Path $dir 'CS-Ray.exe'))) ("exit $code " + $k2.InstallLocation)

    # 6c. clean uninstall: removes only what points into the folder; settings + foreign Run value kept
    $docs = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'CS-Ray\profiles.json'
    $docsBefore = if (Test-Path $docs) { (Get-FileHash $docs).Hash } else { 'none' }
    $code = RunSetup @('--uninstall', "`"$dir`"", '--silent')
    Start-Sleep -Seconds 4   # the detached cmd removes the folder after Setup exits
    Check '--uninstall exit 0' ($code -eq 0) "exit $code"
    Check 'install folder removed' (-not (Test-Path $dir))
    Check 'uninstall entry removed' (-not (Test-Path $ukey) -or $hadKey)
    Check 'our start menu shortcut removed' (-not (Test-Path $lnk))
    $runAfter = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'CS-Ray' -ErrorAction SilentlyContinue).'CS-Ray'
    Check 'start-at-login entry of ANOTHER copy kept' ($runAfter -eq $runBefore) "$runAfter"
    $docsAfter = if (Test-Path $docs) { (Get-FileHash $docs).Hash } else { 'none' }
    Check 'Documents\CS-Ray\profiles.json untouched' ($docsAfter -eq $docsBefore)

    # 7. portable zip: marker present; the app keeps settings beside the exe
    $port = Join-Path $Work 'portable'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory((Get-ChildItem (Join-Path $root "dist\CS-Ray-$version-portable.zip")).FullName, $port)
    Check 'portable zip has the marker' (Test-Path (Join-Path $port 'CS-Ray.portable'))
    & $csc /nologo "/out:$port\PortableProbe.exe" "/r:$port\CS-Ray.exe" "$here\PortableProbe.cs" | Out-Null
    $out = & "$port\PortableProbe.exe"
    Check 'portable: profiles.json beside the exe' ($out[0] -eq (Join-Path $port 'profiles.json')) ($out -join ' | ')
}
finally {
    if ($hadLnk -and (Test-Path $lnkBackup)) { Copy-Item $lnkBackup $lnk -Force }
    if (-not $hadKey -and (Test-Path $ukey)) { Remove-Item $ukey -Recurse -Force }
    $sh2 = New-Object -ComObject WScript.Shell
    "restored start menu shortcut -> " + $(if (Test-Path $lnk) { $sh2.CreateShortcut($lnk).TargetPath } else { '(none)' })
}
if ($fails -eq 0) { 'ALL OK' } else { "$fails FAILURE(S)" }

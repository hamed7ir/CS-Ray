# CS-Ray

Managed-C# proxy client + engine. **Managed-only, no native deps** (must JIT to ARM32).

## Project
- .NET Framework **4.7**, WinForms, **AnyCPU + Prefer32Bit=true**, **C# 7.3** (`<LangVersion>7.3</LangVersion>`)
- Targets: **Windows 10 ARM32 AND Windows RT 8.1**
- NuGet (wired for later AEAD): BouncyCastle. Crypto stays pure-managed.

## Build
```
& "D:\Program Files\Vscom\MSBuild\15.0\Bin\msbuild.exe" "C:\Users\hamed\source\repos\CS-Ray\CS-Ray.sln" /t:Build /p:Configuration=Debug /v:minimal /nologo
```
Restore: `C:\Users\hamed\source\repos\CS-Ray\nuget.exe restore "<sln>" -MSBuildPath "D:\Program Files\Vscom\MSBuild\15.0\Bin"`

## Rules
- **Never run git.** Fix one thing at a time, then build. Close the running exe before rebuild (file lock).
- Crypto/random: `RNGCryptoServiceProvider`, never `System.Random`.
- DPI: `SetProcessDpiAwareness(1)` (system) + `AutoScaleMode.Font`; no manual DPI math.
- Owner-paint bars as a single control (not child-control panels).
- Store fonts in private fields (MaterialSkin overrides `Control.Font`) — once MaterialSkin is added.
- `Stream.ReadAsync` may return fewer bytes than asked — read-fully in a loop for exact counts.
- Bidirectional copy = two independent pump loops, each its own buffer; close both when either ends.

## Deep docs (do NOT auto-read; only when needed)
LESSONS_LEARNED.md / CREATIVE_DECISIONS.md / BUGS_AND_FIXES.md

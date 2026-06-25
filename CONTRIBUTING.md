# Contributing to CS-Ray

Thanks for your interest. CS-Ray is a pure-managed proxy client for **legacy ARM32 Windows**,
and that constraint shapes everything below. Please read before opening a PR.

## Build

- **Visual Studio 2017** (or MSBuild 15 / the .NET Framework 4.7 targeting pack).
- Restore, then build:
  ```powershell
  nuget restore CS-Ray.sln
  msbuild CS-Ray.sln /t:Build /p:Configuration=Debug
  ```
- Project is .NET Framework **4.7**, **C# 7.3**, WinForms, **AnyCPU + Prefer32Bit**.
- TUN mode needs the `wintun/<arch>/wintun.dll` folder beside the built `CS-Ray.exe`, and the
  app must be **run as Administrator** to exercise it.

## Working discipline

This project is built in **small, verifiable steps** — please follow the same rhythm:

- **One thing at a time.** Keep each change focused; small PRs review faster and bisect cleanly.
- **Build clean after every step.** Don't submit a PR that doesn't compile, and prefer changes
  you've actually run.
- **Close the running app before rebuilding** (it locks the exe). For TUN testing, **Exit from
  the tray** (graceful teardown) rather than force-killing — a hard kill can wedge the Wintun
  driver state (`CreateAdapter` error 2) until reboot.
- Note what you tested. If you couldn't test a path, say so.

## The managed-engine ceiling (please don't fight it)

CS-Ray uses .NET's managed `SslStream` and a from-scratch managed netstack. That is **why it
runs on ARM32 at all**, and it means some features are permanently out of scope here:

- **Will not be accepted:** REALITY, uTLS / TLS fingerprint impersonation, XTLS flow, ECH,
  QUIC / HTTP/3, Hysteria/Hysteria2, TUIC, or anything that requires a native core, a custom
  TLS record layer, or a QUIC stack.
- Servers using those are intentionally **imported but marked "unsupported"** — improving how
  that is detected/surfaced is welcome; making them *connect* is not feasible and won't be merged.
- **No new native dependencies.** Everything must JIT to ARM32. The only native artifact is the
  Wintun DLL (used solely via its public `wintun.h` API). Crypto stays pure-managed
  (Bouncy Castle).

Good contributions: new **managed** transports/protocols that fit the ceiling, bug fixes, leak
hardening, UI/touch/accessibility, subscription-format parsers, docs, and testing on real ARM32 /
RT 8.1 hardware.

## Code style

- Match the surrounding code — naming, brace style, comment density. Don't reformat unrelated code.
- C# 7.3 only (no newer language features). Keep it WinForms-idiomatic.
- **Crypto/random:** use `RNGCryptoServiceProvider`, never `System.Random`.
- **DPI:** rely on system-DPI awareness + `AutoScaleMode.Font`; no manual DPI math.
- Reference files/lines precisely in PR descriptions, and explain *why*, not just *what*.

## Licensing of contributions

By submitting a contribution you agree it is licensed under the project's **GPL-3.0-only**
license (see [LICENSE](LICENSE)). Don't paste third-party code under an incompatible license.

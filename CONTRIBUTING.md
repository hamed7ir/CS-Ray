# Contributing

Thanks for wanting to help. Please read this first, it saves time for both of us.

## Build

- Visual Studio 2017 or newer, or MSBuild 15+ with the .NET Framework 4.7 targeting pack.
- `nuget restore CS-Ray.sln`, then build `CS-Ray.sln` (Debug or Release).
- The project is .NET Framework 4.7, C# 7.3, WinForms, AnyCPU with Prefer32Bit. Please don't change that. It's what lets one exe run on ARM32 too.
- For the full tunnel, the `wintun\<arch>\wintun.dll` folders have to be next to `CS-Ray.exe`. Don't start the app as admin yourself, it asks for UAC when you start the full tunnel.

## How I work on it

- One thing at a time. Small PRs are easier to review and easier to undo.
- It has to build with no errors and no warnings.
- Close the app before you rebuild, it locks the exe. When you test the full tunnel, exit from the tray icon. If you kill it, the Wintun adapter can get stuck until you reboot.
- There are self tests in the code (`LinkParserSelfTest`, `VmessSelfTest`). Keep them passing, and add a test when you fix a parser or protocol bug.
- Tell me what you tested, and what you couldn't test.

## What fits and what doesn't

Everything has to be managed .NET code that runs on ARM32. That is the one hard rule.

- No native cores and no new native DLLs. The only native file is wintun.dll, and it's only used through its public API.
- Crypto stays in Bouncy Castle or .NET.
- Anything built on QUIC (Hysteria, TUIC, HTTP/3) is out for now, because there is no managed QUIC stack here.

Things that are welcome: Trojan (it's doable with the TLS code that's already here), gRPC, HTTP/2 for XHTTP over TLS, bug fixes, better subscription parsing, UI and touch fixes, and testing on real Windows RT devices.

## Code style

- Write like the code around it. Same naming, same kind of comments. Don't reformat code you didn't change.
- C# 7.3 only.
- For anything random that matters (keys, nonces, padding) use `RNGCryptoServiceProvider` or Bouncy Castle's `SecureRandom`, never `System.Random`.
- Don't add your own DPI math. Use the helpers that are already there (`DrawHelper.Px` and the font scaling).
- When something has to behave like Xray, write in a comment which Xray file it follows.

## License

Anything you send is under the same GPL-3.0 license as the project (see [LICENSE](LICENSE)). Please don't paste in code under a license that doesn't fit.

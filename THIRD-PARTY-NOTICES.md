# Third-party notices

CS-Ray is licensed under the GNU General Public License v3.0 (see [LICENSE](LICENSE)). It ships with, or uses, the components below. Each one keeps its own license, and CS-Ray's GPL doesn't change that.

---

## Wintun (the prebuilt signed DLLs)

- What it is: a layer 3 TUN driver for Windows, made by WireGuard LLC (Jason A. Donenfeld).
- How CS-Ray uses it: the prebuilt, signed `wintun.dll` files are in this repo under `CS-Ray/wintun/arm/`, `CS-Ray/wintun/arm64/`, `CS-Ray/wintun/x86/` and `CS-Ray/wintun/amd64/`, and they ship next to `CS-Ray.exe`. CS-Ray only calls the public API from `wintun.h` (`WintunCreateAdapter`, `WintunOpenAdapter`, `WintunStartSession`, the packet send and receive calls, and so on).
- License: the Wintun source code is GPL-2.0. The prebuilt signed DLLs, which is what CS-Ray ships, come with a separate "Wintun Prebuilt Binaries License". It's in the official Wintun release zip.
- Why it's OK to ship them: that license allows sharing the unmodified signed DLLs together with software that only uses Wintun through its public API. This is the part that matters:

  > "...resell, redistribute, lease, rent, transfer, sublicense, or otherwise transfer rights
  > of the Software without the prior written consent of WireGuard LLC, **except insofar as the
  > Software is distributed alongside other software that uses the Software only via the
  > Permitted API.**"

  The Permitted API is "only the API interfaces of the `wintun.h` file distributed alongside the Software". CS-Ray only uses `wintun.h`, and the DLLs are not modified.
- Links:
  - Prebuilt binaries license: <https://github.com/WireGuard/wintun/blob/master/prebuilt-binaries-license.txt>
  - Project and downloads: <https://www.wintun.net/>
  - Source: <https://github.com/WireGuard/wintun>

WireGuard says the signed DLLs from wintun.net are the only supported way to ship Wintun, and those are the ones CS-Ray ships.

---

## Bouncy Castle (BouncyCastle.Cryptography)

- What it is: the Bouncy Castle crypto library for C# / .NET, version 2.7.0 (the `net461` build), shipped as `BouncyCastle.Cryptography.dll`.
- What CS-Ray uses it for: the AEAD ciphers (AES-GCM, ChaCha20-Poly1305) in Shadowsocks and VMess, the TLS 1.3 client used for REALITY, XTLS Vision and the optional managed TLS engine, and SHAKE128 for the VMess chunk masking.
- License: the Bouncy Castle License, which is MIT style (based on the MIT X11 Consortium license).
- It comes from NuGet (`BouncyCastle.Cryptography`). Its source is not copied into this repo.
- License text: <https://www.bouncycastle.org/licence.html>
- Project: <https://www.bouncycastle.org/>

---

## QRCoder

- What it is: a QR code library for .NET, version 1.8.0 (the `net40` build), shipped as `QRCoder.dll`.
- What CS-Ray uses it for: making the QR code in the Share window. CS-Ray only takes the module matrix from it and draws the code itself.
- License: MIT. It comes from NuGet (`QRCoder`). Its source is not copied into this repo.
- Project: <https://github.com/Shane32/QRCoder>
- License text:

  > The MIT License (MIT)
  >
  > Copyright (c) 2013-2025 Raffael Herrmann
  > Copyright (c) 2024-2025 Shane Krueger
  >
  > Permission is hereby granted, free of charge, to any person obtaining a copy of
  > this software and associated documentation files (the "Software"), to deal in
  > the Software without restriction, including without limitation the rights to
  > use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
  > the Software, and to permit persons to whom the Software is furnished to do so,
  > subject to the following conditions:
  >
  > The above copyright notice and this permission notice shall be included in all
  > copies or substantial portions of the Software.
  >
  > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  > IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
  > FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
  > COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
  > IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  > CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## Roboto (font)

- What it is: the Roboto font (Regular, Medium, Bold) by Google / Christian Robertson. It's embedded as resources (`CS-Ray/Fonts/Roboto-*.ttf`) and used as the font of the app.
- License: Apache License 2.0 (`SPDX: Apache-2.0`).
- License text: <https://www.apache.org/licenses/LICENSE-2.0>, and the font's own copy: <https://github.com/googlefonts/roboto-2/blob/main/LICENSE>
- Attribution (the Apache 2.0 notice):

  > Roboto font. Copyright Google LLC. Licensed under the Apache License, Version 2.0.
  > You may not use these files except in compliance with the License. Unless required by
  > applicable law or agreed to in writing, software distributed under the License is
  > distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.

---

## Used only as a reference (not included)

- Xray-core (<https://github.com/XTLS/Xray-core>, MPL-2.0). I read Xray's public source to get the wire behavior right (VLESS, VMess, REALITY, XTLS Vision, XHTTP, WebSocket), and I test CS-Ray against the official xray binary. No Xray-core code is included in CS-Ray or linked to it. CS-Ray's code is written from scratch.

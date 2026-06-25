# Third-Party Notices

CS-Ray itself is licensed under the GNU General Public License v3.0 (see [LICENSE](LICENSE)).
It bundles or depends on the third-party components listed below, each under its **own**
license. Those licenses are not changed by CS-Ray's GPLv3 and continue to govern those
components.

---

## Wintun (prebuilt signed DLLs)

- **Component:** Wintun — a layer-3 TUN driver for Windows.
- **Author:** WireGuard LLC / Jason A. Donenfeld.
- **Used by CS-Ray as:** the prebuilt, signed `wintun.dll` binaries, committed in this repo at
  `CS-Ray/wintun/arm/`, `CS-Ray/wintun/arm64/`, `CS-Ray/wintun/x86/`, and `CS-Ray/wintun/amd64/`,
  and shipped beside `CS-Ray.exe`. CS-Ray links to Wintun **only** through the public API
  declared in `wintun.h` (`WintunCreateAdapter`, `WintunOpenAdapter`, `WintunStartSession`,
  the send/receive packet calls, etc.).
- **Licensing:** the Wintun **source code** is licensed **GPL-2.0**. The **prebuilt signed
  DLLs** (which is what CS-Ray redistributes) are released under a separate, more permissive
  **"Wintun Prebuilt Binaries License"**, included in the official Wintun release ZIP.
- **Redistribution basis:** that license permits redistributing the unmodified signed DLLs
  when they are distributed alongside software that uses Wintun only via its public API. The
  operative clause:

  > "...resell, redistribute, lease, rent, transfer, sublicense, or otherwise transfer rights
  > of the Software without the prior written consent of WireGuard LLC, **except insofar as the
  > Software is distributed alongside other software that uses the Software only via the
  > Permitted API.**"

  where the **Permitted API** is "only the API interfaces of the `wintun.h` file distributed
  alongside the Software." CS-Ray uses Wintun strictly via `wintun.h`, so this exception
  applies. The DLLs are redistributed **unmodified**.
- **Full license text & source:**
  - Prebuilt-binaries license: <https://github.com/WireGuard/wintun/blob/master/prebuilt-binaries-license.txt>
  - Project / downloads: <https://www.wintun.net/>
  - Source (mirror): <https://github.com/WireGuard/wintun>

> Note: per WireGuard, the signed DLLs from wintun.net are the only supported way to
> distribute Wintun; CS-Ray ships those unmodified signed DLLs.

---

## Bouncy Castle (Portable.BouncyCastle)

- **Component:** Portable.BouncyCastle (the Legion of the Bouncy Castle C#/.NET crypto APIs),
  version 1.9.0 — used for AEAD ciphers (AES-GCM / ChaCha20-Poly1305) in Shadowsocks and VMess.
- **License:** MIT-style — the **Bouncy Castle License**, an adaptation of the MIT X11
  Consortium license.
- **Obtained via:** NuGet (`Portable.BouncyCastle`), not vendored as source.
- **License text:** <https://www.bouncycastle.org/licence.html>
- **Project:** <https://www.bouncycastle.org/>

---

## MaterialSkin.2

- **Component:** MaterialSkin.2, version 2.3.1 — Material Design theming for WinForms.
- **Author:** Ignace Maes and contributors.
- **License:** **MIT License**.
- **Obtained via:** NuGet (`MaterialSkin.2`), not vendored as source.
- **License text:** <https://github.com/IgnaceMaes/MaterialSkin/blob/master/LICENSE>
- **Project:** <https://github.com/IgnaceMaes/MaterialSkin>

---

## Roboto (font)

- **Component:** Roboto (Regular, Medium, Bold) — embedded as resources
  (`CS-Ray/Fonts/Roboto-*.ttf`) and used as the application UI font.
- **Author:** Google / Christian Robertson.
- **License:** **Apache License, Version 2.0** (`SPDX: Apache-2.0`).
- **License text:** <https://www.apache.org/licenses/LICENSE-2.0> — and the font's own copy:
  <https://github.com/googlefonts/roboto-2/blob/main/LICENSE>
- **Attribution (Apache 2.0 NOTICE):**

  > Roboto font. Copyright Google LLC. Licensed under the Apache License, Version 2.0.
  > You may not use these files except in compliance with the License. Unless required by
  > applicable law or agreed to in writing, software distributed under the License is
  > distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.

---

## Reference (not bundled)

- **Xray-core** (<https://github.com/XTLS/Xray-core>, MPL-2.0) — CS-Ray's XHTTP / SplitHTTP
  transport was implemented by reading the public protocol behavior of Xray-core. **No
  Xray-core source code is included or linked** in CS-Ray; this is a clean-room reference only.

# CS-Ray

A pure-managed C# (.NET Framework 4.7, WinForms) proxy client with a hand-written
userspace TUN TCP/IP netstack — built to run a modern proxy client on **legacy ARM32
Windows** where native cores can't.

> **Status: alpha.** This is censorship-circumvention software under active
> development. It works, but expect rough edges. No warranty (see [LICENSE](LICENSE)).

## Why

The mainstream proxy cores (Xray, sing-box, etc.) ship architecture-specific **native**
binaries. There are no builds for **Windows 10 ARM32 (build 15035)** or **Windows RT 8.1**,
so those devices are stranded — they can't run a modern VLESS/VMess/XHTTP client at all.

CS-Ray is written **entirely in managed C#** with **no native dependencies of its own**, so
the CLR JITs it to ARM32 and it runs on those machines (and on ordinary x86/x64 Windows too).
The TCP/IP stack that turns captured TUN packets into proxied streams is implemented by hand
in managed code. The one unavoidable native piece — the TUN driver — is Wintun, whose signed
DLL ships for arm/arm64/x86/amd64.

This managed-only approach is the whole point, and it comes with a hard ceiling — see
**[Supported vs. Not Supported](#supported-vs-not-supported)** below.

## Features

- **Outbound protocols:** VLESS, VMess (AEAD, alterId 0), Shadowsocks (AEAD), and plain
  **SOCKS5** / **HTTP(S)** proxy outbounds.
- **Transports:** raw TCP, TLS, WebSocket (over TLS), and **XHTTP** (SplitHTTP, packet-up
  mode over HTTP/1.1 + TLS).
- **Mixed inbound:** SOCKS5 **and** HTTP/HTTPS-CONNECT on a single local port,
  `127.0.0.1:10810`.
- **Full-device TUN** (Wintun) with a hand-written userspace TCP/UDP/ICMP netstack:
  **system-proxy** mode and **full-tunnel** mode, with DNS-leak / IPv6-leak / WebRTC-leak
  handling.
- **Subscriptions:** imports 3x-ui (base64 share-links), V2Board/SSPanel, Clash YAML, and
  sing-box JSON formats; per-sub update / delete / rename; group tabs.
- **Delay testing** (real connect+round-trip), **hot-swap** of the active server, **server
  list** with active-server indicator.
- **MaterialSkin GUI** (system/dark/light + Windows accent, Roboto), **touch-optimized**
  (long-press menus, drag-to-scroll), **tray icon**, single-instance, and warnings when
  another route-managing VPN/proxy app is detected.

## Supported vs. Not Supported

CS-Ray reaches servers using .NET's managed `SslStream` for TLS. That is what lets it run on
ARM32 — and it's also what it **cannot** go beyond.

**Supported** (servers must use one of these):

- **Transports:** raw TCP, **TLS 1.2** (plain), **WebSocket over TLS**, **XHTTP** (SplitHTTP
  packet-up, over TLS).
- **Protocols:** VLESS, VMess (AEAD / alterId 0), Shadowsocks (AEAD: `aes-256-gcm`,
  `aes-128-gcm`, `chacha20-ietf-poly1305`), SOCKS5, HTTP(S).

**Not supported** (and why):

| Feature | Why it can't work here |
|---|---|
| **REALITY** | Needs a custom/forged TLS ClientHello and key exchange that managed `SslStream` does not expose. |
| **uTLS fingerprinting** | `SslStream` controls the ClientHello, not the app; you can't impersonate a browser fingerprint. |
| **XTLS / flow (`xtls-rprx-vision`)** | Requires direct manipulation of the TLS record layer, unavailable in managed TLS. |
| **ECH (Encrypted Client Hello)** | Not implemented by .NET Framework `SslStream`. |
| **QUIC / HTTP/3 / Hysteria / Hysteria2 / TUIC** | UDP-based transports needing a QUIC stack (and HTTP/3); not feasible in the managed stack on these OSes. |

Servers that use these are **still imported** from links/subscriptions, but appear **greyed
out** in the list with an "unsupported" reason — they cannot be set active or started. This
is intentional, so you can see your whole subscription and understand what's excluded.

The trade is deliberate: dropping native-only features is the price of running at all on
legacy ARM32 Windows.

## Supported platforms

- **Windows 10 ARM32** (build 15035) — the primary target.
- **Windows RT 8.1** (jailbroken).
- **x86 / x64 Windows 7+** (also works; useful for development/testing).

Built **AnyCPU + Prefer32Bit** so a single binary JITs to ARM32 or runs 32-bit on x64.
Requires **.NET Framework 4.7** on the target. **Administrator/elevation is required for TUN
mode** (see [Usage](#usage)); the system-proxy mode works without elevation.

## Build

Requirements: **Visual Studio 2017** (or MSBuild 15 / the .NET Framework 4.7 targeting pack).

```powershell
# 1. Restore NuGet packages (Portable.BouncyCastle, MaterialSkin.2)
nuget restore CS-Ray.sln

# 2. Build (Debug or Release)
msbuild CS-Ray.sln /t:Build /p:Configuration=Release
```

Open `CS-Ray.sln` in Visual Studio 2017 and Build, or use the commands above. The project is
.NET Framework 4.7, C# 7.3, WinForms, AnyCPU + Prefer32Bit.

**Wintun DLLs:** the architecture-specific `wintun.dll` files are committed under
`CS-Ray/wintun/<arch>/`. The running executable loads `wintun/<arch>/wintun.dll` from beside
itself, so make sure that `wintun/` folder sits **next to `CS-Ray.exe`** in your build/output
directory (copy it from `CS-Ray/wintun/` if your build doesn't stage it automatically). If the
matching DLL is missing, TUN mode is disabled gracefully and the rest of the app still runs.

## Usage

1. **Run as Administrator** to use TUN (full-tunnel / full-device capture). Without
   elevation, only the local-proxy and system-proxy paths work. CS-Ray runs as `asInvoker`
   (it does not silently self-elevate) — right-click → *Run as administrator*.
2. **Add servers**: paste a `vless://` / `vmess://` / `ss://` / `socks://` / `http(s)://` link
   (☰ menu → *Add link from clipboard*, or the Add-from-link box in Settings), use the
   **Add Server** dialog, or add a **subscription** URL in Settings → Subscriptions.
3. **Pick a server** in the list, then **Start Engine**. The local mixed SOCKS5+HTTP inbound
   listens on **`127.0.0.1:10810`** — point any app there, or use one of the modes below.
4. **Modes** (independent toggles in the bottom bar):
   - **System proxy** — sets the Windows (WinINET) proxy to `127.0.0.1:10810`. Covers
     browsers and WinINET apps. No elevation needed.
   - **Full tunnel (TUN)** — captures the whole device's traffic through the engine via
     Wintun. Needs Administrator. Handles DNS/IPv6/WebRTC leaks; private/LAN stays direct.
5. **Delay-test** servers to measure latency; **right-click** a server for Set-active / Test /
   Edit / Remove; **right-click** a subscription tab to update/rename/remove it.

> The chosen DNS resolver (default `8.8.8.8`) is configurable in Settings; under full tunnel
> all DNS is forced through it to prevent leaks.

## Security / trust

CS-Ray is a **censorship-circumvention tool**. Running it routes your traffic through servers
you configure, and in TUN mode it manipulates your machine's routes, DNS, and IPv6 settings.

- **Review the source.** This is exactly the kind of software you should not run on trust. The
  whole point of a pure-managed, from-scratch implementation is that it's auditable — read it.
- **You supply the servers.** CS-Ray bundles no servers and phones nothing home; it only
  connects where you tell it to.
- **Build it yourself** if you can, rather than trusting a binary.
- **No warranty.** See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md). This is alpha
  software; do not rely on it where a leak could put you at risk without verifying behavior
  yourself (the app surfaces a verbose log to help).

To report a vulnerability privately, see [SECURITY.md](SECURITY.md).

## Third-party components & acknowledgements

CS-Ray stands on these — full details and license texts in
**[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)**:

- **[Wintun](https://www.wintun.net/)** (WireGuard LLC) — the userspace TUN driver. The
  signed prebuilt DLLs are redistributed under the **Wintun Prebuilt Binaries License**
  (separate from CS-Ray's GPLv3); CS-Ray uses them only via the public `wintun.h` API.
- **[Bouncy Castle](https://www.bouncycastle.org/)** (Portable.BouncyCastle) — AEAD crypto.
  MIT-style license.
- **[MaterialSkin.2](https://github.com/IgnaceMaes/MaterialSkin)** — Material Design WinForms
  theming. MIT license.
- **[Roboto](https://github.com/googlefonts/roboto)** — the UI font. Apache License 2.0.

The XHTTP / SplitHTTP transport was implemented against the public
[Xray-core](https://github.com/XTLS/Xray-core) protocol behavior (no Xray code is included).

## License

CS-Ray is licensed under the **GNU General Public License v3.0** (GPLv3).
SPDX-License-Identifier: **GPL-3.0-only**. See [LICENSE](LICENSE); the canonical text is at
<https://www.gnu.org/licenses/gpl-3.0.txt>. Bundled third-party components keep their own
licenses (see above).

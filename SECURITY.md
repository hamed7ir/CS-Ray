# Security Policy

## ⚠️ Read this first

CS-Ray is **alpha-quality censorship-circumvention software**, provided **with no warranty**
(see [LICENSE](LICENSE)). It manipulates your machine's routing, DNS, and IPv6 configuration in
TUN mode, and it carries your traffic to servers you configure.

**Do not rely on it where a leak or failure could put you at risk** without verifying its
behavior yourself first. Review the source, build it yourself if you can, and use the in-app
verbose log + a DNS/IP/WebRTC leak test to confirm it behaves as you expect in your setup. The
managed-engine ceiling (no REALITY/uTLS/QUIC/etc., see the README) is a real limitation, not a
bug.

## Supported versions

This is pre-1.0 software under active development. Only the latest commit on the default branch
is supported; there are no maintained release branches yet.

## Reporting a vulnerability

Please report security issues **privately** — do **not** open a public GitHub issue for a
vulnerability, and do not disclose it publicly until it has been addressed.

- **Preferred:** open a private report via GitHub **Security Advisories**
  ("Report a vulnerability" on the repository's *Security* tab).
- **Email:** hamedghrobani17@live.com

Please include: what you found, steps to reproduce, affected component/version (commit hash),
and the potential impact (e.g. a DNS/IP leak, a TLS-validation bypass, a route/teardown flaw,
RCE, etc.).

You'll get an acknowledgement as soon as is practical. Because this protects users who may be
at real risk, **leak and validation-bypass reports are taken seriously** even if they're not
"classic" memory-safety bugs.

There is currently no bug-bounty program.

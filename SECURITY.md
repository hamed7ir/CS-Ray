# Security

## Read this first

CS-Ray is free software made by one person, and it comes with no warranty (see [LICENSE](LICENSE)). In full tunnel mode it changes your routes, DNS and IPv6 settings, and it sends your traffic to the servers you add.

If a leak could put you in danger, don't just trust it. Test it in your own setup first. Turn on the verbose log, use a DNS / IP / WebRTC leak test site, and check that it does what you expect. If you can, read the code and build it yourself.

## Supported versions

Only the latest release (2.0.0 right now) and the latest commit get fixes.

## Reporting a problem

Please don't open a public issue for a security problem, and don't post about it anywhere until it's fixed.

- Best way: the "Report a vulnerability" button on the Security tab of the repo (a private GitHub advisory).
- Or email: hamedghrobani17@live.com

Tell me what you found, how to reproduce it, which version or commit you used, and what can happen because of it. For example a DNS or IP leak, a TLS check that can be skipped, or routes that stay broken after you exit.

I'll answer as soon as I can. Leaks and TLS validation problems matter a lot here, because people use this in places where they can get in real trouble. I take those seriously even when they're not the usual memory bugs.

There is no bug bounty.

# Security Policy

Wifimonitor is a Wi-Fi auditing/pentesting tool: deauthentication, PMKID/handshake
capture, and WPS attacks are its intended purpose when used against networks you
own or are authorized to test. This policy covers vulnerabilities in the tool
itself, not the inherent risk of the features it deliberately provides.

## Supported versions

Only the latest release on the `main` branch receives security fixes. There is no
long-term-support branch.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue:

- Use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
  on this repository (**Security** tab → **Report a vulnerability**), or
- open a regular issue asking a maintainer to set up a private channel if that
  option isn't available to you.

Include: the affected version/commit, a description of the issue, and — where
possible — steps to reproduce or a proof of concept. We aim to acknowledge
reports within a few days.

## Scope

In scope:
- The REST API (`wifimonitor/rest_api.py`) and its bundled web dashboard —
  authentication bypass, injection, XSS, request forgery, etc.
- The desktop app and CLI's handling of untrusted input (captured 802.11 frames,
  imported files, exported reports).
- Data handling: the SQLite database, exported captures/reports, and logs.

Out of scope (by design, not a bug):
- The tool's core capability to deauthenticate clients, capture handshakes/PMKIDs,
  or attempt WPS PINs — that is its documented purpose for authorized testing.
- Requiring root/`CAP_NET_ADMIN` for packet injection and monitor mode.

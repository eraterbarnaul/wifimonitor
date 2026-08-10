# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- REST API bearer-token authentication (`--api-token`, `WIFIMONITOR_API_TOKEN`).
  The API now binds to `127.0.0.1` by default and warns when exposed on a
  non-local host without a token.
- `GET /api/plugins` endpoint that lists the registered attack plugins, so the
  plugin registry is reachable instead of dead code.
- WiGLE-compatible CSV export for wardriving (`MonitorUseCase.export_wigle`,
  `wifimonitor.wardriving`, and the `--wigle` CLI flag) built from the
  GPS-tagged `ap_locations` rows.
- `iw`/`ip` in-place monitor-mode fallback in `InterfaceManager` for systems
  without `airmon-ng`; monitor mode is torn down symmetrically on disable.

### Changed
- Silent `except Exception: pass` blocks in the event bus, cracking/WPS process
  teardown, and the UI cleanup paths now log via the `wifimonitor` logger
  instead of swallowing errors.
- Dependencies now carry upper version bounds (`scapy<3`, `PyQt5<6`,
  `openpyxl<4`) in `pyproject.toml` and `requirements.txt`; `ruff` is pinned in
  the `dev` extra.

## [2.0.0]

### Added
- GPS wardriving: NMEA GPS ingestion, per-AP location tracking, and session
  snapshots persisted to SQLite.
- REST API server and lightweight web UI for remote control of capture.
- Attack plugin registry (deauth, WPS, PMKID solicitation, cracking).
- One-click auto-attack pipeline (lock channel → deauth → capture handshake →
  export) with progress events.
- OUI vendor lookup that auto-loads full vendor databases from system files
  (Wireshark `manuf`, nmap prefixes, arp-scan) when present.

### Fixed
- Monitor-mode enable-then-start bug: `ensure_monitor_mode` is now idempotent
  and reuses an already-active monitor interface.
- Locator tab now refreshes more frequently and tracks signal more accurately.

## [1.0.0]

### Added
- PyQt5 GUI for passive 802.11 monitoring with live AP/station tables.
- WPA handshake and clientless PMKID capture with quality validation.
- Native hashcat 22000 export (EAPOL + PMKID) without external tools.
- Security audit engine: RSN/MFP parsing, WPS detection, attackability scoring.
- Blue-team detection (deauth floods, evil twins) and a pentest HTML report.
- Timezone-aware storage with safe migration for older databases.
- Headless unattended survey CLI.

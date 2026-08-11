# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-08-11

### Added
- GPS wardriving: NMEA GPS ingestion, per-AP location tracking, and session
  snapshots persisted to SQLite.
- REST API server and lightweight web UI for remote control of capture.
- Attack plugin registry (deauth, WPS, PMKID solicitation, cracking).
- One-click auto-attack pipeline (lock channel → deauth → capture handshake →
  export) with progress events.
- OUI vendor lookup that auto-loads full vendor databases from system files
  (Wireshark `manuf`, nmap prefixes, arp-scan) when present.
- REST API bearer-token authentication (`--api-token`, `--api-token-file`,
  `WIFIMONITOR_API_TOKEN`). The API binds to `127.0.0.1` by default and warns
  when exposed on a non-local host without a token.
- `GET /api/plugins` endpoint that lists the registered attack plugins, so the
  plugin registry is reachable instead of dead code.
- WiGLE-compatible CSV export for wardriving (`MonitorUseCase.export_wigle`,
  `wifimonitor.wardriving`, and the `--wigle` CLI flag) built from the
  GPS-tagged `ap_locations` rows.
- `iw`/`ip` in-place monitor-mode fallback in `InterfaceManager` for systems
  without `airmon-ng`; monitor mode is torn down symmetrically on disable.
- `mypy` (with `PyQt5-stubs`) runs in CI alongside `ruff`.
- A GUI smoke test (`tests/test_main_window_smoke.py`) that constructs and
  closes `MainWindow` under `QT_QPA_PLATFORM=offscreen`.
- `requirements-lock.txt` for a fully reproducible dev setup; `LICENSE` (MIT,
  matching `pyproject.toml`'s declared license — previously missing),
  `SECURITY.md`, `CONTRIBUTING.md`, and `.github/dependabot.yml`.

### Changed
- Silent `except Exception: pass` blocks in the event bus, cracking/WPS process
  teardown, and the UI cleanup paths now log via the `wifimonitor` logger
  instead of swallowing errors.
- Dependencies now carry upper version bounds (`scapy<3`, `PyQt5<6`,
  `openpyxl<4`) in `pyproject.toml` and `requirements.txt`; `ruff`, `mypy`,
  and `PyQt5-stubs` are pinned in the `dev` extra.
- The REST API server now uses `ThreadingHTTPServer` instead of the
  single-threaded `HTTPServer`, so one slow client can no longer stall every
  other request.

### Fixed
- Monitor-mode enable-then-start bug: `ensure_monitor_mode` is now idempotent
  and reuses an already-active monitor interface.
- Locator tab now refreshes more frequently and tracks signal more accurately.
- The bundled REST API dashboard (`/`) now loads and authenticates correctly
  when `--api-token` is set: the page itself is served without a token (it
  carries no data of its own), and its JavaScript now attaches the saved
  token as an `Authorization: Bearer` header to every API call it makes.
  Previously, enabling the token — the documented way to expose the API
  beyond localhost — made the dashboard unusable.
- Stored XSS in the REST API dashboard: access-point/handshake fields
  (ESSID, BSSID, station MAC, …) are attacker-controlled over the air and
  were interpolated into `innerHTML` unescaped. They're now HTML-escaped
  client-side before rendering.
- `capture.py`: station discovery from ordinary (non-EAPOL) data frames used
  `addr3` as the BSSID unconditionally, which is only correct for management
  frames — for a station's uplink frame (ToDS=1) the real BSSID is `addr1`,
  and `addr3` is the frame's actual destination beyond the AP. Stations first
  seen this way could be attributed to the wrong access point in the UI/DB.
  Handshake/PMKID capture itself was unaffected (EAPOL frames resolve to the
  same BSSID either way).
- `auto_attack.py`: the auto-attack pipeline accepted *any* captured
  handshake/PMKID as its own result, without checking it was for the BSSID it
  was actually targeting. An unrelated AP's handshake, captured by the
  passive scanner while sharing the locked channel, could be mistaken for
  success on the intended target. `notify_handshake` now requires and checks
  the handshake's BSSID.
- 15 pre-existing `mypy` type errors across `hashcat.py`, `detect.py`,
  `report.py`, `database.py`, `plugins.py`, `usecases.py`, and (once checked
  against real `PyQt5`) ~50 Qt-enum errors in `ui/main_window.py`.

### Security
- `POST` bodies are capped at 1 MiB; a client claiming a larger
  `Content-Length` gets `413` instead of the server buffering it in memory.
- Added `--api-token-file` to read the bearer token from a file instead of a
  command-line argument, which is otherwise visible to other local users via
  `ps`/`/proc/<pid>/cmdline`.
- The REST API now rate-limits failed token attempts per client IP (10
  failures / 60s by default, `429` while locked out) to make brute-forcing a
  token over the network impractical.

Verified against the real dependencies (`scapy`, `PyQt5`, `openpyxl`) in an
installed environment: 219 tests pass, `mypy` and `ruff` are clean, and
`MainWindow` boots under `QT_QPA_PLATFORM=offscreen`.

## [1.0.0]

### Added
- PyQt5 GUI for passive 802.11 monitoring with live AP/station tables.
- WPA handshake and clientless PMKID capture with quality validation.
- Native hashcat 22000 export (EAPOL + PMKID) without external tools.
- Security audit engine: RSN/MFP parsing, WPS detection, attackability scoring.
- Blue-team detection (deauth floods, evil twins) and a pentest HTML report.
- Timezone-aware storage with safe migration for older databases.
- Headless unattended survey CLI.

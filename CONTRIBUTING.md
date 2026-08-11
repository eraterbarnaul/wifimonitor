# Contributing

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

This installs the runtime dependencies (`scapy`, `PyQt5`, `openpyxl`) plus the
dev tools (`pytest`, `ruff`, `mypy`, `PyQt5-stubs`).

## Before opening a PR

```bash
ruff check wifimonitor/ tests/
mypy wifimonitor/
QT_QPA_PLATFORM=offscreen pytest tests/ -v
```

All three run in CI (`.github/workflows/ci.yml`) and must pass. `QT_QPA_PLATFORM=offscreen`
lets the Qt-based tests (including the `MainWindow` smoke test) run headless — set it
whenever you run the suite in a terminal without a display.

If you don't have `scapy`/`PyQt5`/`openpyxl` available (e.g. a restricted sandbox),
you can still validate pure-logic modules:

```bash
pytest tests/ -q --ignore=tests/test_auto_attack.py --ignore=tests/test_capture_mock.py \
  --ignore=tests/test_controller_mock.py --ignore=tests/test_integration.py \
  --ignore=tests/test_rest_api.py --ignore=tests/test_main_window_smoke.py
```

but note this skips real coverage of the capture/UI/API layers — CI is the source
of truth.

## Code style

- Follow the patterns already in the file you're editing over introducing new ones.
- Keep the shared logic layer (`wifimonitor/usecases.py`, `MonitorUseCase`) scapy-coupled
  but free of PyQt5; the Qt controller (`controller.py`) and `ui/main_window.py` are thin
  adapters over it. `cli.py` and `rest_api.py` use the same use-case layer so GUI, headless,
  and remote-control stay in sync.
- Modules that don't need scapy/PyQt5 at import time (`auth.py`, `hashcat.py`, `wifi_ie.py`,
  `wardriving.py`, `timeutil.py`, `models.py`, ...) should stay that way — it's what makes
  them unit-testable without a wireless adapter or a display. If a module needs a heavy
  dependency only inside one function, import it lazily there rather than at module scope.
- No comments explaining *what* code does; only *why*, when it's non-obvious (a workaround,
  an invariant, a subtle constraint).
- Русскоязычные строки в UI/CLI-сообщениях — существующее соглашение проекта, придерживайтесь
  его в пользовательских сообщениях.

## Reporting bugs / requesting features

Open a GitHub issue. For security issues, see [SECURITY.md](SECURITY.md) instead of a
public issue.

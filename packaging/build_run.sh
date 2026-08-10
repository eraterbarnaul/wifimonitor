#!/usr/bin/env bash
# Build a distro-agnostic self-extracting installer (wifimonitor_<ver>.run).
# The .run is a shell stub with a gzipped tar payload appended; running it
# extracts to a temp dir and executes install.sh (needs root). Unlike the .deb
# it does NOT resolve dependencies — it prints what to install.
set -euo pipefail

VERSION="${1:-1.0.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/dist"
BUILD="$(mktemp -d)"
PAY="$BUILD/payload"
mkdir -p "$PAY" "$DEST"

# Application package (drop bytecode caches).
cp -r "$ROOT/wifimonitor" "$PAY/wifimonitor"
find "$PAY/wifimonitor" -name '__pycache__' -type d -prune -exec rm -rf {} +

# Installer that runs on the target.
cat > "$PAY/install.sh" <<'INSTALL'
#!/bin/sh
set -e
if [ "$(id -u)" -ne 0 ]; then
    echo "Запустите установку с правами root: sudo ./wifimonitor_*.run" >&2
    exit 1
fi
DEST=/usr/lib/python3/dist-packages
mkdir -p "$DEST"
rm -rf "$DEST/wifimonitor"
cp -r wifimonitor "$DEST/wifimonitor"
cat > /usr/bin/wifimonitor <<'LAUNCH'
#!/bin/sh
exec python3 -m wifimonitor.app "$@"
LAUNCH
chmod 0755 /usr/bin/wifimonitor
echo "wifimonitor установлен в $DEST"
echo "Зависимости (установите вручную): python3-pyqt5 python3-scapy python3-openpyxl aircrack-ng iw"
echo "Запуск: sudo wifimonitor"
INSTALL
chmod +x "$PAY/install.sh"

tar -C "$PAY" -czf "$BUILD/payload.tgz" .

OUT="$DEST/wifimonitor_${VERSION}.run"
cat > "$OUT" <<'STUB'
#!/bin/sh
# Self-extracting wifimonitor installer.
set -e
ARCHIVE_LINE=$(awk '/^__ARCHIVE_BELOW__/ { print NR + 1; exit 0; }' "$0")
TMP=$(mktemp -d)
tail -n +"$ARCHIVE_LINE" "$0" | tar xz -C "$TMP"
( cd "$TMP" && sh ./install.sh )
rm -rf "$TMP"
exit 0
__ARCHIVE_BELOW__
STUB
cat "$BUILD/payload.tgz" >> "$OUT"
chmod 0755 "$OUT"
rm -rf "$BUILD"
echo "built $OUT"

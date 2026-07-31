#!/usr/bin/env bash
# Build a wifimonitor .deb into dist/. Pure-Python package (Architecture: all),
# installed under dist-packages with a /usr/bin/wifimonitor launcher.
set -euo pipefail

VERSION="${1:-1.0.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/dist"
BUILD="$(mktemp -d)"
PKG="$BUILD/wifimonitor_${VERSION}"

mkdir -p "$PKG/DEBIAN" "$PKG/usr/lib/python3/dist-packages" "$PKG/usr/bin" \
         "$PKG/usr/share/applications" "$DEST"

# Application package (drop bytecode caches).
cp -r "$ROOT/wifimonitor" "$PKG/usr/lib/python3/dist-packages/wifimonitor"
find "$PKG/usr/lib/python3/dist-packages/wifimonitor" -name '__pycache__' -type d -prune -exec rm -rf {} +

# Launcher.
cat > "$PKG/usr/bin/wifimonitor" <<'LAUNCH'
#!/bin/sh
exec python3 -m wifimonitor.app "$@"
LAUNCH
chmod 0755 "$PKG/usr/bin/wifimonitor"

# Desktop entry (must run as root for monitor mode).
cat > "$PKG/usr/share/applications/wifimonitor.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=Wifimonitor
Comment=Wi-Fi monitoring and handshake capture
Exec=pkexec wifimonitor
Icon=network-wireless
Terminal=false
Categories=Network;Security;
DESKTOP

# Control metadata.
cat > "$PKG/DEBIAN/control" <<CONTROL
Package: wifimonitor
Version: ${VERSION}
Architecture: all
Maintainer: eraterbarnaul <eraterbarnaul@users.noreply.github.com>
Section: net
Priority: optional
Depends: python3 (>= 3.10), python3-pyqt5, python3-scapy, python3-openpyxl, aircrack-ng, iw
Recommends: hcxtools, reaver
Description: GUI-инструмент для мониторинга Wi-Fi и перехвата handshake
 Утилита с интерфейсом на PyQt5 для Kali/Debian. Поддерживает мониторинг,
 перехват WPA/WPA2/WPA3 handshakes и PMKID, деаутентификацию, оценку
 атакуемости сетей и экспорт в Hashcat/Excel/CSV.
CONTROL

OUT="$DEST/wifimonitor_${VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$PKG" "$OUT"
echo "built $OUT"

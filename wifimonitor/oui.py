"""Minimal built-in OUI (MAC prefix) -> vendor lookup.

This is a small, high-confidence subset aimed at spotting common device classes
during an audit (IoT boards, virtual machines, well-known network gear). It is
intentionally short; for full coverage point ``load_oui_file`` at an IEEE
``oui.txt`` / Wireshark ``manuf`` file.

Extended: automatically loads system OUI files at import time if available.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional

_BUILTIN: Dict[str, str] = {
    # Virtualization
    "000C29": "VMware",
    "005056": "VMware",
    "080027": "VirtualBox",
    "525400": "QEMU/KVM",
    "00155D": "Microsoft Hyper-V",
    "00163E": "Xen",
    # Single-board computers / IoT
    "B827EB": "Raspberry Pi",
    "DCA632": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    "2CCF67": "Raspberry Pi",
    "240AC4": "Espressif (ESP32/8266)",
    "3C71BF": "Espressif (ESP32/8266)",
    "8CAAB5": "Espressif (ESP32/8266)",
    "A020A6": "Espressif (ESP32/8266)",
    # Network gear
    "00000C": "Cisco",
    "4C5E0C": "MikroTik",
    "6C3B6B": "MikroTik",
    "0418D6": "Ubiquiti",
    "24A43C": "Ubiquiti",
    "DC9FDB": "Ubiquiti",
    # Apple
    "A4B197": "Apple",
    "F0D1A9": "Apple",
    "38C986": "Apple",
    "70DEE2": "Apple",
    "3CE072": "Apple",
    # Samsung
    "A8F274": "Samsung",
    "C44602": "Samsung",
    "8C71F8": "Samsung",
    # Intel
    "8086F2": "Intel",
    "A4C494": "Intel",
    "7C5CF8": "Intel",
    # TP-Link
    "10FEED": "TP-Link",
    "5C628B": "TP-Link",
    "C006C3": "TP-Link",
    # Netgear
    "A42B8C": "Netgear",
    "B07FB9": "Netgear",
    # Huawei
    "00E0FC": "Huawei",
    "0034FE": "Huawei",
    "0025D3": "Huawei",
    "001882": "Huawei",
    # Xiaomi
    "28E31F": "Xiaomi",
    "7CE9D3": "Xiaomi",
}

_TABLE: Dict[str, str] = dict(_BUILTIN)

# Standard system paths for OUI/manuf files
_SYSTEM_OUI_PATHS: List[str] = [
    "/usr/share/wireshark/manuf",
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/share/arp-scan/ieee-oui.txt",
    "/etc/manuf",
    "/usr/local/share/wireshark/manuf",
    "/usr/share/misc/oui.txt",
]


def lookup_vendor(mac: Optional[str]) -> str:
    """Return the vendor for a MAC's OUI, or ``""`` if unknown."""
    if not mac:
        return ""
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    return _TABLE.get(prefix, "")


def is_randomized_mac(mac: Optional[str]) -> bool:
    """True if the MAC has the locally-administered bit set (randomized)."""
    if not mac:
        return False
    hexmac = mac.replace(":", "").replace("-", "")
    if len(hexmac) < 2:
        return False
    try:
        first_octet = int(hexmac[:2], 16)
    except ValueError:
        return False
    return bool(first_octet & 0x02)


def load_oui_file(path: Path) -> int:
    """Merge an IEEE ``oui.txt``/``manuf``-style file into the lookup table.

    Accepts lines like ``AABBCC<sep>Vendor`` or ``AA:BB:CC<sep>Vendor``.
    Returns the number of entries added. Best-effort: malformed lines are
    skipped.
    """
    added = 0
    try:
        content = Path(path).read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return 0
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.replace("\t", " ").split(None, 1)
        if len(parts) != 2:
            continue
        prefix = parts[0].replace(":", "").replace("-", "").replace(".", "").upper()[:6]
        if len(prefix) == 6 and all(c in "0123456789ABCDEF" for c in prefix):
            _TABLE[prefix] = parts[1].strip()
            added += 1
    return added


def load_nmap_prefixes(path: Path) -> int:
    """Load nmap-mac-prefixes format (6-char-hex followed by vendor name)."""
    added = 0
    try:
        content = Path(path).read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return 0
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if len(line) < 7:
            continue
        prefix = line[:6].upper()
        if all(c in "0123456789ABCDEF" for c in prefix):
            vendor = line[7:].strip() if len(line) > 7 else line[6:].strip()
            if vendor:
                _TABLE[prefix] = vendor
                added += 1
    return added


def auto_load_system_oui() -> int:
    """Try to load OUI data from common system locations. Returns total entries added."""
    total = 0
    for path_str in _SYSTEM_OUI_PATHS:
        path = Path(path_str)
        if not path.exists():
            continue
        if "nmap-mac-prefixes" in path_str:
            total += load_nmap_prefixes(path)
        else:
            total += load_oui_file(path)
        if total > 1000:
            break  # Got a good source, no need to load more
    return total


def table_size() -> int:
    """Return the number of entries in the OUI table."""
    return len(_TABLE)


# Auto-load on import (best-effort, silent on failure)
auto_load_system_oui()

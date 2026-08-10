"""Minimal built-in OUI (MAC prefix) -> vendor lookup.

This is a small, high-confidence subset aimed at spotting common device classes
during an audit (IoT boards, virtual machines, well-known network gear). It is
intentionally short; for full coverage point ``load_oui_file`` at an IEEE
``oui.txt`` / Wireshark ``manuf`` file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional

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
}

_TABLE: Dict[str, str] = dict(_BUILTIN)


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
    for raw in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
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

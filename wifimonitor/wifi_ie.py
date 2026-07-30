"""Pure parsing of 802.11 information elements (no scapy dependency).

Kept separate from :mod:`wifimonitor.capture` so the bit-twiddling can be unit
tested without importing scapy or bringing up a capture stack.
"""

from __future__ import annotations

from typing import Optional

RSN_AKM_OUI = b"\x00\x0f\xac"
RSN_SAE_SUITES = {RSN_AKM_OUI + b"\x08", RSN_AKM_OUI + b"\x09"}  # SAE / FT-SAE => WPA3
WPA_VENDOR_HEADER = b"\x00\x50\xf2\x01"  # Microsoft WPA1 vendor-specific IE


def classify_rsn(info: bytes) -> str:
    """Classify an RSN (802.11i) element body as WPA2 and/or WPA3.

    WPA3 is signalled by the SAE AKM suites (00-0F-AC-08 / 00-0F-AC-09).
    Any parse error falls back to "WPA2", since the presence of an RSN
    element already implies at least WPA2.
    """
    try:
        # layout: version(2) group(4) pair_count(2) pair*4 akm_count(2) akm*4 ...
        idx = 2 + 4
        pair_count = int.from_bytes(info[idx:idx + 2], "little")
        idx += 2 + 4 * pair_count
        akm_count = int.from_bytes(info[idx:idx + 2], "little")
        idx += 2
        akms = []
        for _ in range(akm_count):
            suite = info[idx:idx + 4]
            if len(suite) < 4:
                break
            akms.append(suite)
            idx += 4
        has_wpa3 = any(a in RSN_SAE_SUITES for a in akms)
        has_wpa2 = any(a[:3] == RSN_AKM_OUI and a not in RSN_SAE_SUITES for a in akms)
        if has_wpa3 and has_wpa2:
            return "WPA2/WPA3"
        if has_wpa3:
            return "WPA3"
        return "WPA2"
    except Exception:  # noqa: BLE001 - malformed IE, degrade gracefully
        return "WPA2"


def frequency_to_channel(freq: Optional[int]) -> Optional[int]:
    """Map a RadioTap centre frequency (MHz) to a Wi-Fi channel number.

    Covers 2.4 GHz, 5 GHz and 6 GHz (Wi-Fi 6E). Returns ``None`` for unknown
    or missing frequencies so the caller can leave the channel blank.
    """
    if not freq:
        return None
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    if 5000 <= freq < 5900:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return None

"""Pure parsing of 802.11 information elements (no scapy dependency).

Kept separate from :mod:`wifimonitor.capture` so the bit-twiddling can be unit
tested without importing scapy or bringing up a capture stack.
"""

from __future__ import annotations

from typing import Dict, Optional

RSN_AKM_OUI = b"\x00\x0f\xac"
RSN_SAE_SUITES = {RSN_AKM_OUI + b"\x08", RSN_AKM_OUI + b"\x09"}  # SAE / FT-SAE => WPA3
WPA_VENDOR_HEADER = b"\x00\x50\xf2\x01"  # Microsoft WPA1 vendor-specific IE
WPS_VENDOR_HEADER = b"\x00\x50\xf2\x04"  # Wi-Fi Simple Config (WPS) vendor IE


def parse_rsn(info: bytes) -> Dict[str, object]:
    """Parse an RSN (802.11i) element body.

    Returns ``classification`` (WPA2 / WPA3 / WPA2/WPA3), plus the Management
    Frame Protection capability/requirement flags from RSN Capabilities. Any
    parse error degrades to a plain WPA2 result, since the presence of an RSN
    element already implies at least WPA2.
    """
    result: Dict[str, object] = {"classification": "WPA2", "mfp_required": False, "mfp_capable": False}
    try:
        # layout: version(2) group(4) pair_count(2) pair*4 akm_count(2) akm*4 caps(2)
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
            result["classification"] = "WPA2/WPA3"
        elif has_wpa3:
            result["classification"] = "WPA3"
        if idx + 2 <= len(info):
            caps = int.from_bytes(info[idx:idx + 2], "little")
            result["mfp_required"] = bool(caps & 0x0040)
            result["mfp_capable"] = bool(caps & 0x0080)
    except Exception:  # noqa: BLE001 - malformed IE, degrade gracefully
        pass
    return result


def classify_rsn(info: bytes) -> str:
    """Return just the WPA2/WPA3 classification of an RSN element body."""
    return str(parse_rsn(info)["classification"])


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

"""Pure parsing of 802.11 information elements (no scapy dependency).

Kept separate from :mod:`wifimonitor.capture` so the bit-twiddling can be unit
tested without importing scapy or bringing up a capture stack.

Extended to parse VHT Operation (802.11ac), HE Capabilities (802.11ax),
and EHT (802.11be) indicators for Wi-Fi generation and bandwidth detection.
"""

from __future__ import annotations

from typing import Dict, Optional

RSN_AKM_OUI = b"\x00\x0f\xac"
RSN_SAE_SUITES = {RSN_AKM_OUI + b"\x08", RSN_AKM_OUI + b"\x09"}  # SAE / FT-SAE => WPA3
WPA_VENDOR_HEADER = b"\x00\x50\xf2\x01"  # Microsoft WPA1 vendor-specific IE
WPS_VENDOR_HEADER = b"\x00\x50\xf2\x04"  # Wi-Fi Simple Config (WPS) vendor IE

# IE Element IDs
IE_SSID = 0
IE_DS_PARAMETER = 3
IE_HT_CAPABILITIES = 45
IE_RSN = 48
IE_HT_OPERATION = 61
IE_VHT_CAPABILITIES = 191
IE_VHT_OPERATION = 192
IE_VENDOR_SPECIFIC = 221
IE_EXTENSION = 255

# Extension Element IDs
IE_EXT_HE_CAPABILITIES = 35
IE_EXT_HE_OPERATION = 36
IE_EXT_EHT_CAPABILITIES = 108
IE_EXT_EHT_OPERATION = 106


def parse_rsn(info: bytes) -> Dict[str, object]:
    """Parse an RSN (802.11i) element body.

    Returns ``classification`` (WPA2 / WPA3 / WPA2/WPA3), plus the Management
    Frame Protection capability/requirement flags from RSN Capabilities.
    """
    result: Dict[str, object] = {"classification": "WPA2", "mfp_required": False, "mfp_capable": False}
    try:
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
    except Exception:  # noqa: BLE001
        pass
    return result


def classify_rsn(info: bytes) -> str:
    """Return just the WPA2/WPA3 classification of an RSN element body."""
    return str(parse_rsn(info)["classification"])


def parse_ht_capabilities(info: bytes) -> Dict[str, object]:
    """Parse HT Capabilities (IE 45) for 802.11n info.

    Returns supported channel width and short GI support.
    """
    result: Dict[str, object] = {"ht_supported": True, "ht_40mhz": False, "short_gi_20": False, "short_gi_40": False}
    if len(info) < 2:
        return result
    cap_info = int.from_bytes(info[0:2], "little")
    result["ht_40mhz"] = bool(cap_info & 0x0002)  # Supported Channel Width Set
    result["short_gi_20"] = bool(cap_info & 0x0020)
    result["short_gi_40"] = bool(cap_info & 0x0040)
    return result


def parse_vht_capabilities(info: bytes) -> Dict[str, object]:
    """Parse VHT Capabilities (IE 191) for 802.11ac info.

    Returns supported channel width and short GI support for 80/160 MHz.
    """
    result: Dict[str, object] = {
        "vht_supported": True,
        "max_bandwidth": "80",
        "short_gi_80": False,
        "short_gi_160": False,
    }
    if len(info) < 4:
        return result
    cap_info = int.from_bytes(info[0:4], "little")
    bw_bits = cap_info & 0x0003
    if bw_bits == 1:
        result["max_bandwidth"] = "160"
    elif bw_bits == 2:
        result["max_bandwidth"] = "160"  # 80+80
    else:
        result["max_bandwidth"] = "80"
    result["short_gi_80"] = bool(cap_info & 0x0020)
    result["short_gi_160"] = bool(cap_info & 0x0040)
    return result


def parse_vht_operation(info: bytes) -> Dict[str, object]:
    """Parse VHT Operation (IE 192).

    Returns the actual operating channel width.
    """
    result: Dict[str, object] = {"vht_op_bandwidth": "20/40"}
    if len(info) < 1:
        return result
    channel_width = info[0]
    if channel_width == 0:
        result["vht_op_bandwidth"] = "20/40"
    elif channel_width == 1:
        result["vht_op_bandwidth"] = "80"
    elif channel_width == 2:
        result["vht_op_bandwidth"] = "160"
    elif channel_width == 3:
        result["vht_op_bandwidth"] = "80+80"
    return result


def parse_he_capabilities(info: bytes) -> Dict[str, object]:
    """Parse HE Capabilities (IE 255, ext 35) for 802.11ax/Wi-Fi 6.

    Minimal parsing — just detecting presence indicates Wi-Fi 6 support.
    """
    result: Dict[str, object] = {"he_supported": True, "wifi_generation": "6"}
    # If the AP is on 6 GHz, it's Wi-Fi 6E
    # (channel detection handled separately)
    return result


def parse_eht_capabilities(info: bytes) -> Dict[str, object]:
    """Parse EHT Capabilities (IE 255, ext 108) for 802.11be/Wi-Fi 7.

    Presence indicates Wi-Fi 7 support.
    """
    return {"eht_supported": True, "wifi_generation": "7"}


def detect_wifi_generation(
    has_ht: bool = False,
    has_vht: bool = False,
    has_he: bool = False,
    has_eht: bool = False,
    channel: Optional[int] = None,
) -> str:
    """Determine the Wi-Fi generation from detected capabilities.

    Returns: "4" (n), "5" (ac), "6" (ax), "6E" (ax on 6GHz), "7" (be)
    """
    if has_eht:
        return "7"
    if has_he:
        # 6 GHz channels start at 1 (UNII-5) for Wi-Fi 6E
        if channel is not None and channel >= 1 and _is_6ghz_channel(channel):
            return "6E"
        return "6"
    if has_vht:
        return "5"
    if has_ht:
        return "4"
    return ""


def detect_bandwidth(
    has_ht: bool = False,
    ht_40mhz: bool = False,
    has_vht: bool = False,
    vht_bandwidth: str = "",
    has_he: bool = False,
    has_eht: bool = False,
) -> str:
    """Determine the operating bandwidth from detected capabilities."""
    if has_eht:
        return "320"  # Wi-Fi 7 can do 320 MHz
    if has_he and has_vht:
        return vht_bandwidth if vht_bandwidth else "80"
    if has_vht:
        return vht_bandwidth if vht_bandwidth else "80"
    if has_ht and ht_40mhz:
        return "40"
    if has_ht:
        return "20"
    return "20"


def _is_6ghz_channel(channel: int) -> bool:
    """Check if a channel number belongs to the 6 GHz band (UNII-5 through UNII-8)."""
    # 6 GHz channels: 1, 5, 9, ..., 233 (spaced by 4)
    return 1 <= channel <= 233 and channel not in range(1, 14) and channel not in _5GHZ_CHANNELS


_5GHZ_CHANNELS = set(range(36, 178))  # Simplified 5 GHz range


def frequency_to_channel(freq: Optional[int]) -> Optional[int]:
    """Map a RadioTap centre frequency (MHz) to a Wi-Fi channel number.

    Covers 2.4 GHz, 5 GHz and 6 GHz (Wi-Fi 6E).
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


def frequency_to_band(freq: Optional[int]) -> str:
    """Return the band name for a given frequency."""
    if not freq:
        return ""
    if 2400 <= freq <= 2500:
        return "2.4GHz"
    if 5000 <= freq < 5900:
        return "5GHz"
    if 5925 <= freq <= 7125:
        return "6GHz"
    return ""

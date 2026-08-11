"""Native hashcat 22000 (WPA-PBKDF2-PMKID+EAPOL) generation.

This module is deliberately free of scapy so the byte-level parsing can be unit
tested. :mod:`wifimonitor.exporters` walks a pcap with scapy and feeds the raw
802.1X EAPOL-Key frames and addresses in here.

hashcat 22000 line layout (9 ``*``-separated fields)::

    WPA*TYPE*PMKID_OR_MIC*MAC_AP*MAC_STA*ESSID*ANONCE*EAPOL*MESSAGEPAIR

* TYPE ``01`` -> PMKID (ANONCE/EAPOL/MESSAGEPAIR empty)
* TYPE ``02`` -> EAPOL handshake (MIC + AP nonce + M2 frame with the MIC zeroed)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

# Offsets inside the 802.1X EAPOL-Key frame (EAPOL header + key descriptor).
_KEY_INFO = slice(5, 7)
_NONCE = slice(17, 49)
_MIC = slice(81, 97)
_KEY_DATA_LEN = slice(97, 99)
_KEY_DATA_START = 99

RSN_OUI = b"\x00\x0f\xac"
PMKID_KDE_TYPE = 0x04

# messagepair codes understood by hashcat.
MP_M1_M2 = 0x00
MP_M2_M3 = 0x02


@dataclass
class KeyFrame:
    message: int  # 1..4, or 0 if unknown
    key_info: int
    nonce: bytes
    mic: bytes
    key_data: bytes
    eapol_zeroed: bytes  # full EAPOL frame with the MIC field set to zero


def message_number(key_info: int) -> int:
    """Classify a 4-way-handshake message (1..4) from the Key Information field."""
    ack = bool(key_info & 0x0080)
    install = bool(key_info & 0x0040)
    mic = bool(key_info & 0x0100)
    secure = bool(key_info & 0x0200)
    if ack and not mic:
        return 1
    if mic and ack and install:
        return 3
    if mic and not ack and not install:
        return 4 if secure else 2
    return 0


def parse_key_frame(raw: bytes) -> Optional[KeyFrame]:
    """Parse a raw 802.1X EAPOL-Key frame. Returns ``None`` if it is too short."""
    if len(raw) < _KEY_DATA_START:
        return None
    # Trim any trailing FCS/padding captured after the 802.1X body so the
    # exported EAPOL frame matches exactly what hashcat expects.
    declared = int.from_bytes(raw[2:4], "big") + 4
    if 4 < declared <= len(raw):
        raw = raw[:declared]
    key_info = int.from_bytes(raw[_KEY_INFO], "big")
    key_data_len = int.from_bytes(raw[_KEY_DATA_LEN], "big")
    key_data = raw[_KEY_DATA_START:_KEY_DATA_START + key_data_len]
    eapol_zeroed = raw[:_MIC.start] + b"\x00" * 16 + raw[_MIC.stop:]
    return KeyFrame(
        message=message_number(key_info),
        key_info=key_info,
        nonce=raw[_NONCE],
        mic=raw[_MIC],
        key_data=key_data,
        eapol_zeroed=eapol_zeroed,
    )


def capture_quality(messages: set, has_pmkid: bool = False) -> str:
    """Rate how usable a capture is for cracking, from the observed messages.

    ``messages`` is the set of 4-way-handshake message numbers (1..4) seen for
    a station. A crackable EAPOL pair needs M2 (SNONCE+MIC) plus an ANONCE
    source (M1 or M3).
    """
    if has_pmkid:
        return "crackable (PMKID)"
    if 2 in messages and (1 in messages or 3 in messages):
        return "crackable"
    if 2 in messages:
        return "partial (нет ANONCE)"
    if messages:
        return "partial"
    return "none"


def find_pmkid(key_data: bytes) -> Optional[bytes]:
    """Return the 16-byte PMKID from an M1 key-data blob, or ``None``."""
    i = 0
    n = len(key_data)
    while i + 2 <= n:
        tag = key_data[i]
        length = key_data[i + 1]
        if length == 0:
            break
        value = key_data[i + 2:i + 2 + length]
        if tag == 0xDD and len(value) >= 4 and value[:3] == RSN_OUI and value[3] == PMKID_KDE_TYPE:
            pmkid = value[4:20]
            if len(pmkid) == 16 and any(pmkid):
                return pmkid
        i += 2 + length
    return None


def _mac_hex(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").lower()


def pmkid_line(pmkid: bytes, ap_mac: str, sta_mac: str, essid: bytes) -> str:
    return "*".join(
        [
            "WPA",
            "01",
            pmkid.hex(),
            _mac_hex(ap_mac),
            _mac_hex(sta_mac),
            essid.hex(),
            "",
            "",
            "",
        ]
    )


def eapol_line(
    mic: bytes,
    ap_mac: str,
    sta_mac: str,
    essid: bytes,
    anonce: bytes,
    eapol_zeroed: bytes,
    messagepair: int,
) -> str:
    return "*".join(
        [
            "WPA",
            "02",
            mic.hex(),
            _mac_hex(ap_mac),
            _mac_hex(sta_mac),
            essid.hex(),
            anonce.hex(),
            eapol_zeroed.hex(),
            f"{messagepair:02x}",
        ]
    )


def build_hash_lines(
    frames: Sequence[Tuple[str, str, str, bytes]],
    essid: bytes,
) -> List[str]:
    """Build hashcat 22000 lines for one (AP, STA) conversation.

    ``frames`` is a sequence of ``(src_mac, dst_mac, ap_mac, raw_eapol)``. Emits
    at most one PMKID line and one EAPOL line, de-duplicated.
    """
    by_msg: Dict[int, KeyFrame] = {}
    ap_mac = sta_mac = None
    pmkid_val: Optional[bytes] = None
    for src, dst, ap, raw in frames:
        parsed = parse_key_frame(raw)
        if parsed is None:
            continue
        ap_mac = ap
        # In M1/M3 the AP transmits; the station is the other address.
        sta_mac = dst if src == ap else src
        if parsed.message:
            by_msg[parsed.message] = parsed
        if parsed.message == 1 and pmkid_val is None:
            pmkid_val = find_pmkid(parsed.key_data)

    if ap_mac is None or sta_mac is None:
        return []

    lines: List[str] = []
    if pmkid_val is not None:
        lines.append(pmkid_line(pmkid_val, ap_mac, sta_mac, essid))

    m2 = by_msg.get(2)
    if m2 is not None:
        if 1 in by_msg:
            anonce = by_msg[1].nonce
            messagepair = MP_M1_M2
        elif 3 in by_msg:
            anonce = by_msg[3].nonce
            messagepair = MP_M2_M3
        else:
            anonce = None
            messagepair = None
        if anonce is not None:
            assert messagepair is not None  # set together with anonce above
            lines.append(
                eapol_line(m2.mic, ap_mac, sta_mac, essid, anonce, m2.eapol_zeroed, messagepair)
            )
    return lines

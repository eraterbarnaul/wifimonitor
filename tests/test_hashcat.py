"""Unit tests for the scapy-free hashcat 22000 generation."""

from wifimonitor.hashcat import (
    build_hash_lines,
    find_pmkid,
    message_number,
    parse_key_frame,
)

AP = "aa:bb:cc:dd:ee:ff"
STA = "11:22:33:44:55:66"
ESSID = b"TestNet"

KI_M1 = 0x008A  # ACK, pairwise
KI_M2 = 0x010A  # MIC, pairwise
KI_M3 = 0x03CA  # ACK+MIC+Install+Secure, pairwise


def make_eapol(key_info: int, nonce: bytes, mic: bytes, key_data: bytes = b"") -> bytes:
    assert len(nonce) == 32 and len(mic) == 16
    body = bytes([0x02])                      # descriptor type (RSN)
    body += key_info.to_bytes(2, "big")
    body += (0x0010).to_bytes(2, "big")       # key length
    body += b"\x00" * 8                        # replay counter
    body += nonce                              # key nonce (32)
    body += b"\x00" * 16                        # key IV
    body += b"\x00" * 8                         # key RSC
    body += b"\x00" * 8                         # key ID
    body += mic                                # key MIC (16)
    body += len(key_data).to_bytes(2, "big")
    body += key_data
    return bytes([0x02, 0x03]) + len(body).to_bytes(2, "big") + body


def pmkid_kde(pmkid: bytes) -> bytes:
    return b"\xdd\x14\x00\x0f\xac\x04" + pmkid


def test_message_number():
    assert message_number(KI_M1) == 1
    assert message_number(KI_M2) == 2
    assert message_number(KI_M3) == 3


def test_parse_key_frame_offsets():
    nonce = bytes(range(32))
    mic = b"\xab" * 16
    frame = make_eapol(KI_M2, nonce, mic, key_data=b"\x30\x02\x00\x00")
    kf = parse_key_frame(frame)
    assert kf is not None
    assert kf.message == 2
    assert kf.nonce == nonce
    assert kf.mic == mic
    assert kf.key_data == b"\x30\x02\x00\x00"
    # the MIC must be zeroed in the exported EAPOL frame, everything else intact
    assert kf.eapol_zeroed[81:97] == b"\x00" * 16
    assert kf.eapol_zeroed[:81] == frame[:81]
    assert kf.eapol_zeroed[97:] == frame[97:]


def test_parse_key_frame_too_short():
    assert parse_key_frame(b"\x02\x03\x00\x05abcde") is None


def test_find_pmkid():
    pmkid = bytes(range(16, 32))
    assert find_pmkid(pmkid_kde(pmkid)) == pmkid
    # all-zero PMKID is treated as absent
    assert find_pmkid(pmkid_kde(b"\x00" * 16)) is None
    assert find_pmkid(b"") is None
    assert find_pmkid(b"\x30\x02\x00\x00") is None  # RSN element, no PMKID


def test_build_lines_pmkid_and_eapol_m1_m2():
    anonce = b"\x01" * 32
    snonce = b"\x02" * 32
    mic = b"\x0a" * 16
    pmkid = bytes(range(16))
    m1 = make_eapol(KI_M1, anonce, b"\x00" * 16, key_data=pmkid_kde(pmkid))
    m2 = make_eapol(KI_M2, snonce, mic)
    frames = [
        (AP, STA, AP, m1),   # AP -> STA
        (STA, AP, AP, m2),   # STA -> AP
    ]
    lines = build_hash_lines(frames, ESSID)
    assert len(lines) == 2

    pmkid_l = next(l for l in lines if l.startswith("WPA*01"))
    eapol_l = next(l for l in lines if l.startswith("WPA*02"))

    p = pmkid_l.split("*")
    assert len(p) == 9
    assert p[2] == pmkid.hex()
    assert p[3] == "aabbccddeeff" and p[4] == "112233445566"
    assert p[5] == ESSID.hex()
    assert p[6:] == ["", "", ""]

    e = eapol_l.split("*")
    assert len(e) == 9
    assert e[2] == mic.hex()
    assert e[6] == anonce.hex()          # ANONCE comes from M1
    assert e[8] == "00"                   # M1+M2 message pair
    assert e[7] == parse_key_frame(m2).eapol_zeroed.hex()


def test_build_lines_m2_m3_without_m1():
    anonce = b"\x03" * 32
    snonce = b"\x04" * 32
    mic = b"\x0b" * 16
    m2 = make_eapol(KI_M2, snonce, mic)
    m3 = make_eapol(KI_M3, anonce, b"\x0c" * 16)
    frames = [
        (STA, AP, AP, m2),   # STA -> AP
        (AP, STA, AP, m3),   # AP -> STA
    ]
    lines = build_hash_lines(frames, ESSID)
    assert len(lines) == 1
    e = lines[0].split("*")
    assert e[1] == "02"
    assert e[6] == anonce.hex()          # ANONCE from M3
    assert e[8] == "02"                   # M2+M3 message pair


def test_build_lines_empty_without_usable_frames():
    assert build_hash_lines([], ESSID) == []

"""Unit tests for the attackability assessment, MFP parsing and OUI lookup."""

from wifimonitor.audit import assess, priority_rank
from wifimonitor.oui import is_randomized_mac, lookup_vendor
from wifimonitor.wifi_ie import parse_rsn


def _label(*args, **kwargs):
    return assess(*args, **kwargs)[0]


def test_open_network():
    label, detail = assess("")
    assert label == "Открытая"
    assert "шифрования" in detail


def test_wep_is_critical():
    assert _label("WEP") == "Критично"


def test_wpa3_is_low():
    assert _label("WPA3") == "Низкий"


def test_wpa2_with_clients_is_medium():
    assert _label("WPA2", client_count=3) == "Средний"


def test_wpa2_no_clients_is_low():
    assert _label("WPA2", client_count=0) == "Низкий"


def test_pmkid_raises_wpa2():
    assert _label("WPA2", client_count=0, has_pmkid=True) == "Высокий"


def test_wps_lifts_wpa2():
    label, detail = assess("WPA2", wps=True, client_count=0)
    assert label == "Высокий"
    assert "WPS" in detail


def test_mfp_note_present():
    _, detail = assess("WPA2", mfp_required=True, client_count=2)
    assert "MFP" in detail


def test_priority_rank_orders_open_above_low():
    assert priority_rank("Открытая") > priority_rank("Средний") > priority_rank("Низкий")


def _rsn(akms, caps=b"\x00\x00", pairwise=(b"\x00\x0f\xac\x04",)):
    body = b"\x01\x00" + b"\x00\x0f\xac\x04"
    body += len(pairwise).to_bytes(2, "little") + b"".join(pairwise)
    body += len(akms).to_bytes(2, "little") + b"".join(akms)
    body += caps
    return body


def test_parse_rsn_mfp_flags():
    sae = b"\x00\x0f\xac\x08"
    # RSN capabilities bit 6 = MFP required, bit 7 = MFP capable
    r = parse_rsn(_rsn([sae], caps=b"\xc0\x00"))
    assert r["classification"] == "WPA3"
    assert r["mfp_required"] is True
    assert r["mfp_capable"] is True
    r2 = parse_rsn(_rsn([b"\x00\x0f\xac\x02"], caps=b"\x00\x00"))
    assert r2["mfp_required"] is False


def test_oui_lookup():
    assert lookup_vendor("B8:27:EB:11:22:33") == "Raspberry Pi"
    assert lookup_vendor("00-0C-29-aa-bb-cc") == "VMware"
    assert lookup_vendor("FF:FF:FF:00:00:00") == ""
    assert lookup_vendor(None) == ""


def test_is_randomized_mac():
    assert is_randomized_mac("DE:AD:BE:EF:00:01") is True   # 0xDE has bit 0x02
    assert is_randomized_mac("B8:27:EB:00:00:01") is False  # real Raspberry Pi OUI
    assert is_randomized_mac("02:11:22:33:44:55") is True
    assert is_randomized_mac(None) is False
    assert is_randomized_mac("") is False

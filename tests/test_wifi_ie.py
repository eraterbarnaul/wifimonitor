"""Unit tests for RSN/WPA information-element classification.

These import only :mod:`wifimonitor.wifi_ie`, so they run without scapy, PyQt5
or a wireless adapter present.
"""

from wifimonitor.wifi_ie import classify_rsn, frequency_to_channel

WPA2_PSK = b"\x00\x0f\xac\x02"
WPA2_ENT = b"\x00\x0f\xac\x01"
SAE = b"\x00\x0f\xac\x08"
FT_SAE = b"\x00\x0f\xac\x09"


def _rsn(akms, group=b"\x00\x0f\xac\x04", pairwise=(b"\x00\x0f\xac\x04",)):
    body = b"\x01\x00"  # version
    body += group
    body += len(pairwise).to_bytes(2, "little") + b"".join(pairwise)
    body += len(akms).to_bytes(2, "little") + b"".join(akms)
    body += b"\x0c\x00"  # RSN capabilities
    return body


def test_wpa2_psk():
    assert classify_rsn(_rsn([WPA2_PSK])) == "WPA2"


def test_wpa2_enterprise():
    assert classify_rsn(_rsn([WPA2_ENT])) == "WPA2"


def test_wpa3_sae_only():
    assert classify_rsn(_rsn([SAE])) == "WPA3"
    assert classify_rsn(_rsn([FT_SAE])) == "WPA3"


def test_wpa2_wpa3_transition():
    assert classify_rsn(_rsn([WPA2_PSK, SAE])) == "WPA2/WPA3"


def test_multiple_pairwise_ciphers_are_skipped():
    two_pairwise = (b"\x00\x0f\xac\x04", b"\x00\x0f\xac\x02")
    assert classify_rsn(_rsn([SAE], pairwise=two_pairwise)) == "WPA3"


def test_malformed_bodies_degrade_to_wpa2():
    assert classify_rsn(b"") == "WPA2"
    assert classify_rsn(b"\x01\x00") == "WPA2"
    assert classify_rsn(b"\x01\x00\x00\x0f\xac\x04\xff\xff") == "WPA2"


def test_frequency_to_channel_24ghz():
    assert frequency_to_channel(2412) == 1
    assert frequency_to_channel(2437) == 6
    assert frequency_to_channel(2472) == 13
    assert frequency_to_channel(2484) == 14


def test_frequency_to_channel_5ghz():
    assert frequency_to_channel(5180) == 36
    assert frequency_to_channel(5745) == 149
    assert frequency_to_channel(5825) == 165


def test_frequency_to_channel_6ghz():
    assert frequency_to_channel(5955) == 1
    assert frequency_to_channel(6175) == 45


def test_frequency_to_channel_unknown_or_missing():
    assert frequency_to_channel(None) is None
    assert frequency_to_channel(0) is None
    assert frequency_to_channel(3000) is None

"""Tests for extended WiFi IE parsing."""
from wifimonitor.wifi_ie import (
    parse_ht_capabilities,
    parse_vht_capabilities,
    parse_vht_operation,
    parse_he_capabilities,
    parse_eht_capabilities,
    detect_wifi_generation,
    detect_bandwidth,
    frequency_to_band,
    frequency_to_channel,
)


def test_parse_ht_capabilities_20mhz():
    # HT cap info with 20 MHz only
    info = b"\x00\x00" + b"\x00" * 24
    result = parse_ht_capabilities(info)
    assert result["ht_supported"] is True
    assert result["ht_40mhz"] is False


def test_parse_ht_capabilities_40mhz():
    # HT cap info with 40 MHz support (bit 1 set)
    info = b"\x02\x00" + b"\x00" * 24
    result = parse_ht_capabilities(info)
    assert result["ht_40mhz"] is True


def test_parse_vht_capabilities_80mhz():
    info = b"\x00\x00\x00\x00" + b"\x00" * 8
    result = parse_vht_capabilities(info)
    assert result["vht_supported"] is True
    assert result["max_bandwidth"] == "80"


def test_parse_vht_capabilities_160mhz():
    info = b"\x01\x00\x00\x00" + b"\x00" * 8
    result = parse_vht_capabilities(info)
    assert result["max_bandwidth"] == "160"


def test_parse_vht_operation():
    info = b"\x01\x00\x00"  # 80 MHz
    result = parse_vht_operation(info)
    assert result["vht_op_bandwidth"] == "80"


def test_parse_he_capabilities():
    result = parse_he_capabilities(b"\x00" * 10)
    assert result["he_supported"] is True
    assert result["wifi_generation"] == "6"


def test_parse_eht_capabilities():
    result = parse_eht_capabilities(b"\x00" * 10)
    assert result["eht_supported"] is True
    assert result["wifi_generation"] == "7"


def test_detect_wifi_generation_wifi4():
    assert detect_wifi_generation(has_ht=True) == "4"


def test_detect_wifi_generation_wifi5():
    assert detect_wifi_generation(has_ht=True, has_vht=True) == "5"


def test_detect_wifi_generation_wifi6():
    assert detect_wifi_generation(has_ht=True, has_vht=True, has_he=True) == "6"


def test_detect_wifi_generation_wifi7():
    assert detect_wifi_generation(has_ht=True, has_vht=True, has_he=True, has_eht=True) == "7"


def test_detect_bandwidth_ht_20():
    assert detect_bandwidth(has_ht=True, ht_40mhz=False) == "20"


def test_detect_bandwidth_ht_40():
    assert detect_bandwidth(has_ht=True, ht_40mhz=True) == "40"


def test_detect_bandwidth_vht_80():
    assert detect_bandwidth(has_ht=True, has_vht=True, vht_bandwidth="80") == "80"


def test_detect_bandwidth_eht_320():
    assert detect_bandwidth(has_eht=True) == "320"


def test_frequency_to_band_24ghz():
    assert frequency_to_band(2437) == "2.4GHz"


def test_frequency_to_band_5ghz():
    assert frequency_to_band(5180) == "5GHz"


def test_frequency_to_band_6ghz():
    assert frequency_to_band(5955) == "6GHz"


def test_frequency_to_channel_6ghz():
    assert frequency_to_channel(5955) == 1
    assert frequency_to_channel(5975) == 5

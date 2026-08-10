"""Tests for extended OUI module."""
from pathlib import Path
from wifimonitor.oui import lookup_vendor, is_randomized_mac, load_oui_file, load_nmap_prefixes, table_size


def test_lookup_builtin():
    assert lookup_vendor("00:0C:29:aa:bb:cc") == "VMware"
    assert lookup_vendor("B8:27:EB:11:22:33") == "Raspberry Pi"


def test_lookup_unknown():
    assert lookup_vendor("FF:FF:FF:FF:FF:FF") == ""


def test_lookup_none():
    assert lookup_vendor(None) == ""


def test_is_randomized_mac_true():
    # 02:xx:xx means locally administered
    assert is_randomized_mac("02:00:00:11:22:33") is True


def test_is_randomized_mac_false():
    assert is_randomized_mac("00:0C:29:11:22:33") is False


def test_is_randomized_mac_none():
    assert is_randomized_mac(None) is False


def test_load_oui_file(tmp_path):
    oui_file = tmp_path / "oui.txt"
    oui_file.write_text("AABBCC  TestVendor\nDDEEFF  AnotherVendor\n")
    count = load_oui_file(oui_file)
    assert count == 2
    assert lookup_vendor("AA:BB:CC:11:22:33") == "TestVendor"


def test_load_nmap_prefixes(tmp_path):
    nmap_file = tmp_path / "nmap-mac-prefixes"
    nmap_file.write_text("112233 NmapVendor\n445566 SecondVendor\n")
    count = load_nmap_prefixes(nmap_file)
    assert count == 2
    assert lookup_vendor("11:22:33:AA:BB:CC") == "NmapVendor"


def test_table_size():
    size = table_size()
    assert size > 30  # At least builtin entries

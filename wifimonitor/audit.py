"""Attackability assessment for discovered access points.

Pure, dependency-free scoring used by the UI (a per-network verdict column) and
by the pentest report. It turns the passively observed facts — encryption, WPS,
802.11w/MFP, presence of clients, a captured PMKID — into a short priority label
and a human-readable recommendation. This is decision support for *authorised*
audits, not an attack automation.
"""

from __future__ import annotations

from typing import Optional, Tuple

# Higher rank == more attackable; used for sorting the AP table by verdict.
_PRIORITY_RANK = {
    "Открытая": 5,
    "Критично": 4,
    "Высокий": 3,
    "Средний": 2,
    "Низкий": 1,
    "—": 0,
}


def assess(
    encryption: Optional[str],
    wps: bool = False,
    mfp_required: bool = False,
    signal: Optional[int] = None,
    client_count: int = 0,
    has_pmkid: bool = False,
) -> Tuple[str, str]:
    """Return ``(priority_label, recommendation)`` for one access point."""
    enc = (encryption or "").upper()
    notes = []
    if wps:
        notes.append("WPS вкл — кандидат на Pixie Dust")
    if mfp_required:
        notes.append("MFP включён — deauth не сработает")

    if enc == "":
        label, base = "Открытая", "нет шифрования, доступ тривиален"
    elif "WEP" in enc:
        label, base = "Критично", "WEP — взлом за минуты"
    elif "WPA3" in enc and "WPA2" not in enc:
        label, base = "Низкий", "WPA3/SAE — только онлайн-словарь"
    elif enc == "WPA":
        label, base = "Высокий", "WPA1 устарел, перехват handshake"
    else:  # WPA2 or WPA2/WPA3 transition
        if has_pmkid:
            label, base = "Высокий", "PMKID получен — словарь без клиента"
        elif client_count > 0 and not mfp_required:
            label, base = "Средний", "есть клиенты — deauth→handshake→словарь"
        elif client_count > 0:
            label, base = "Средний", "клиенты есть, но MFP мешает deauth"
        else:
            label, base = "Низкий", "нет клиентов — ждать подключения"

    # WPS lifts otherwise-modest WPA2 targets: the router PIN is a separate path.
    if wps and label in ("Средний", "Низкий"):
        label = "Высокий"

    detail = base if not notes else base + "; " + "; ".join(notes)
    return label, detail


def priority_rank(label: str) -> int:
    return _PRIORITY_RANK.get(label, 0)

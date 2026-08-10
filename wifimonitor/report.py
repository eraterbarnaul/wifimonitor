"""Self-contained HTML pentest report of an audit session.

Pure (stdlib + :mod:`wifimonitor.audit` / :mod:`wifimonitor.oui`) so it can be
unit tested and produced off the GUI thread. Every field is HTML-escaped, since
ESSIDs and vendor strings are attacker-controlled.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from html import escape
from typing import Optional, Sequence

from .audit import assess
from .oui import is_randomized_mac, lookup_vendor

_VERDICT_CLASS = {
    "Открытая": "v-crit",
    "Критично": "v-crit",
    "Высокий": "v-high",
    "Средний": "v-med",
    "Низкий": "v-low",
}

_STYLE = """
body{font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:24px;color:#12232e;background:#fff}
h1{margin:0 0 4px} .meta{color:#5a6b76;margin-bottom:20px}
h2{margin-top:28px;border-bottom:2px solid #e3e9ee;padding-bottom:4px}
table{border-collapse:collapse;width:100%;margin-top:10px;font-size:14px}
th,td{border:1px solid #dfe6ec;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f2f6f9} tr:nth-child(even) td{background:#fafcfd}
.summary span{display:inline-block;margin-right:18px;font-weight:600}
.v-crit{background:#ffd9d6;font-weight:600} .v-high{background:#ffe2c2;font-weight:600}
.v-med{background:#fff4c2} .v-low{background:#dff3df}
.note{margin-top:28px;color:#5a6b76;font-size:13px;border-top:1px solid #e3e9ee;padding-top:12px}
"""


def _cell(value) -> str:
    return escape("" if value is None else str(value))


def build_html_report(
    access_points: Sequence[dict],
    stations: Sequence[dict],
    handshakes: Sequence[dict],
    generated_at: Optional[datetime] = None,
    probes: Optional[dict] = None,
) -> str:
    generated_at = generated_at or datetime.now(timezone.utc)
    clients_by_ap: defaultdict = defaultdict(int)
    for station in stations:
        bssid = station.get("associated_bssid")
        if bssid:
            clients_by_ap[bssid] += 1
    pmkid_aps = {h.get("bssid") for h in handshakes if h.get("kind") == "pmkid"}

    parts = [
        "<!doctype html><html lang='ru'><head><meta charset='utf-8'>",
        "<title>Wifimonitor — отчёт аудита</title>",
        f"<style>{_STYLE}</style></head><body>",
        "<h1>Wifimonitor — отчёт аудита Wi-Fi</h1>",
        f"<div class='meta'>Сформировано: {_cell(generated_at.strftime('%Y-%m-%d %H:%M UTC'))}</div>",
        "<div class='summary'>"
        f"<span>Сети: {len(access_points)}</span>"
        f"<span>Клиенты: {len(stations)}</span>"
        f"<span>Захваты: {len(handshakes)}</span>"
        "</div>",
        "<h2>Точки доступа</h2>",
        "<table><tr><th>BSSID</th><th>ESSID</th><th>Производитель</th><th>Канал</th>"
        "<th>Шифрование</th><th>WPS</th><th>MFP</th><th>Сигнал</th><th>Клиенты</th>"
        "<th>Оценка</th><th>Рекомендация</th></tr>",
    ]
    ranked = []
    for ap in access_points:
        bssid = ap.get("bssid")
        count = clients_by_ap.get(bssid, 0)
        label, detail = assess(
            ap.get("encryption"),
            wps=bool(ap.get("wps")),
            mfp_required=bool(ap.get("mfp_required")),
            signal=ap.get("signal"),
            client_count=count,
            has_pmkid=bssid in pmkid_aps,
        )
        ranked.append((ap, count, label, detail))
    for ap, count, label, detail in ranked:
        cls = _VERDICT_CLASS.get(label, "")
        parts.append(
            "<tr>"
            f"<td>{_cell(ap.get('bssid'))}</td>"
            f"<td>{_cell(ap.get('essid'))}</td>"
            f"<td>{_cell(lookup_vendor(ap.get('bssid')))}</td>"
            f"<td>{_cell(ap.get('channel'))}</td>"
            f"<td>{_cell(ap.get('encryption'))}</td>"
            f"<td>{'да' if ap.get('wps') else ''}</td>"
            f"<td>{'да' if ap.get('mfp_required') else ''}</td>"
            f"<td>{_cell(ap.get('signal'))}</td>"
            f"<td>{_cell(count)}</td>"
            f"<td class='{cls}'>{_cell(label)}</td>"
            f"<td>{_cell(detail)}</td>"
            "</tr>"
        )
    parts.append("</table>")

    parts.append("<h2>Клиенты</h2>")
    parts.append(
        "<table><tr><th>MAC</th><th>Производитель</th><th>MAC рандомизирован</th>"
        "<th>Точка доступа</th><th>Сигнал</th><th>Обновлено</th></tr>"
    )
    for station in stations:
        mac = station.get("mac")
        parts.append(
            "<tr>"
            f"<td>{_cell(mac)}</td>"
            f"<td>{_cell(lookup_vendor(mac))}</td>"
            f"<td>{'да' if is_randomized_mac(mac) else ''}</td>"
            f"<td>{_cell(station.get('associated_bssid'))}</td>"
            f"<td>{_cell(station.get('signal'))}</td>"
            f"<td>{_cell(station.get('last_seen'))}</td>"
            "</tr>"
        )
    parts.append("</table>")

    if probes:
        parts.append("<h2>Probe requests (искомые сети)</h2>")
        parts.append("<table><tr><th>Клиент</th><th>Запрошенные SSID</th></tr>")
        for mac, ssids in sorted(probes.items()):
            parts.append(
                "<tr>"
                f"<td>{_cell(mac)}</td>"
                f"<td>{_cell(', '.join(ssids))}</td>"
                "</tr>"
            )
        parts.append("</table>")

    parts.append("<h2>Захваты</h2>")
    parts.append(
        "<table><tr><th>Тип</th><th>Качество</th><th>BSSID</th><th>Клиент</th>"
        "<th>Файл</th><th>Создан</th></tr>"
    )
    for hs in handshakes:
        parts.append(
            "<tr>"
            f"<td>{_cell(hs.get('kind') or 'handshake')}</td>"
            f"<td>{_cell(hs.get('quality'))}</td>"
            f"<td>{_cell(hs.get('bssid'))}</td>"
            f"<td>{_cell(hs.get('station_mac'))}</td>"
            f"<td>{_cell(hs.get('capture_path'))}</td>"
            f"<td>{_cell(hs.get('created_at'))}</td>"
            "</tr>"
        )
    parts.append("</table>")

    parts.append(
        "<div class='note'>Отчёт предназначен для авторизованного тестирования. "
        "Проводите аудит только с письменного разрешения владельца сети.</div>"
    )
    parts.append("</body></html>")
    return "".join(parts)

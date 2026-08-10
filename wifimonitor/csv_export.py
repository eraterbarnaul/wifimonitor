"""CSV export with injection protection (stdlib only)."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Sequence

# Characters that trigger formula interpretation in Excel/LibreOffice
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def _sanitize_cell(value) -> str:
    """Sanitize a cell value to prevent CSV injection attacks.

    If a string starts with a character that Excel interprets as a formula,
    prefix it with a single quote to force text mode.
    """
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in _FORMULA_PREFIXES:
        return f"'{s}"
    return s


class CsvExporter:
    def export(
        self,
        output_path: Path,
        access_points: Sequence[dict],
        stations: Sequence[dict],
    ) -> Path:
        """Write access points to ``output_path`` and clients to a sibling file.

        Returns the path of the clients file (``<stem>_clients.csv``).
        All cell values are sanitized to prevent CSV injection.
        """
        output_path = Path(output_path)
        with output_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["BSSID", "ESSID", "Channel", "Encryption", "Signal", "Bandwidth", "WiFi Gen", "Last Seen"])
            for ap in access_points:
                writer.writerow([
                    _sanitize_cell(ap.get("bssid")),
                    _sanitize_cell(ap.get("essid")),
                    _sanitize_cell(ap.get("channel")),
                    _sanitize_cell(ap.get("encryption")),
                    _sanitize_cell(ap.get("signal")),
                    _sanitize_cell(ap.get("bandwidth")),
                    _sanitize_cell(ap.get("wifi_generation")),
                    _sanitize_cell(ap.get("last_seen")),
                ])

        clients_path = output_path.with_name(f"{output_path.stem}_clients.csv")
        with clients_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["MAC", "Associated BSSID", "Signal", "Last Seen"])
            for station in stations:
                writer.writerow([
                    _sanitize_cell(station.get("mac")),
                    _sanitize_cell(station.get("associated_bssid")),
                    _sanitize_cell(station.get("signal")),
                    _sanitize_cell(station.get("last_seen")),
                ])
        return clients_path

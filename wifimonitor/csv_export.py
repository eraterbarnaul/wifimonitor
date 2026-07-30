"""CSV export of the discovered networks and clients (stdlib only)."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Sequence


class CsvExporter:
    def export(
        self,
        output_path: Path,
        access_points: Sequence[dict],
        stations: Sequence[dict],
    ) -> Path:
        """Write access points to ``output_path`` and clients to a sibling file.

        Returns the path of the clients file (``<stem>_clients.csv``).
        """
        output_path = Path(output_path)
        with output_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["BSSID", "ESSID", "Channel", "Encryption", "Signal", "Last Seen"])
            for ap in access_points:
                writer.writerow([
                    ap.get("bssid"),
                    ap.get("essid"),
                    ap.get("channel"),
                    ap.get("encryption"),
                    ap.get("signal"),
                    ap.get("last_seen"),
                ])

        clients_path = output_path.with_name(f"{output_path.stem}_clients.csv")
        with clients_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["MAC", "Associated BSSID", "Signal", "Last Seen"])
            for station in stations:
                writer.writerow([
                    station.get("mac"),
                    station.get("associated_bssid"),
                    station.get("signal"),
                    station.get("last_seen"),
                ])
        return clients_path

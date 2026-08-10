"""WiGLE-compatible CSV export for wardriving (stdlib only).

Turns the ``ap_locations`` GPS rows (joined with access-point metadata) into the
``WigleWifi-1.4`` pre-CSV format that wigle.net accepts for upload.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Dict, Optional, Sequence

_PRE_HEADER = (
    "WigleWifi-1.4,appRelease=2.0.0,model=wifimonitor,release=2.0.0,"
    "device=wifimonitor,display=,board=,brand=wifimonitor"
)
_COLUMNS = [
    "MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI",
    "CurrentLatitude", "CurrentLongitude", "AltitudeMeters", "AccuracyMeters", "Type",
]


def build_wigle_csv(locations: Sequence[dict], ap_index: Optional[Dict[str, dict]] = None) -> str:
    """Return WiGLE pre-CSV text for the given GPS location rows.

    ``locations`` rows carry ``bssid, latitude, longitude, altitude, signal,
    timestamp``; ``ap_index`` maps a BSSID to its AP dict (essid/channel/
    encryption) for the SSID/AuthMode/Channel columns.
    """
    ap_index = ap_index or {}
    buffer = io.StringIO()
    buffer.write(_PRE_HEADER + "\n")
    writer = csv.writer(buffer)
    writer.writerow(_COLUMNS)
    for loc in locations:
        bssid = loc.get("bssid", "")
        ap = ap_index.get(bssid, {})
        channel = ap.get("channel")
        signal = loc.get("signal")
        altitude = loc.get("altitude")
        writer.writerow([
            bssid,
            ap.get("essid") or "",
            ap.get("encryption") or "",
            loc.get("timestamp") or "",
            channel if channel is not None else "",
            signal if signal is not None else "",
            loc.get("latitude"),
            loc.get("longitude"),
            altitude if altitude is not None else "",
            "",  # AccuracyMeters (unknown)
            "WIFI",
        ])
    return buffer.getvalue()


def export_wigle(output_path: Path, locations: Sequence[dict], ap_index: Optional[Dict[str, dict]] = None) -> Path:
    output_path = Path(output_path)
    output_path.write_text(build_wigle_csv(locations, ap_index), encoding="utf-8")
    return output_path

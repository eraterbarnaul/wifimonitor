import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

from openpyxl import Workbook
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, EAPOL, rdpcap  # type: ignore

from .hashcat import build_hash_lines


class HashcatExporter:
    """Export captured pcaps to the hashcat 22000 format.

    The default path is native (parses the pcap with scapy — no external
    dependency). ``export_with_tool`` keeps the option of shelling out to
    ``hcxpcapngtool`` for users who prefer it.
    """

    def __init__(self, tool_path: str = "hcxpcapngtool") -> None:
        self.tool_path = tool_path

    def export(self, capture_path: Path, output_path: Path) -> None:
        packets = rdpcap(str(capture_path))
        essid = self._find_essid(packets)
        groups: Dict[Tuple[str, str], List[Tuple[str, str, str, bytes]]] = defaultdict(list)
        for pkt in packets:
            if not pkt.haslayer(EAPOL) or not pkt.haslayer(Dot11):
                continue
            dot11 = pkt[Dot11]
            src, dst, ap = dot11.addr2, dot11.addr1, dot11.addr3
            if not (src and dst and ap):
                continue
            station = dst if src == ap else src
            eapol_layer = pkt.getlayer(EAPOL)
            assert eapol_layer is not None  # guaranteed by the haslayer(EAPOL) check above
            groups[(ap, station)].append((src, dst, ap, bytes(eapol_layer)))

        lines: List[str] = []
        for frames in groups.values():
            lines.extend(build_hash_lines(frames, essid))
        if not lines:
            raise RuntimeError("В файле не найдено PMKID или пригодного handshake")
        output_path.write_text("\n".join(lines) + "\n", encoding="ascii")

    def export_with_tool(self, capture_path: Path, output_path: Path) -> None:
        command = [self.tool_path, "-o", str(output_path), str(capture_path)]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
        except FileNotFoundError as exc:
            raise FileNotFoundError(
                f"Утилита '{self.tool_path}' не найдена. Установите hcxpcapngtool или укажите путь к ней."
            ) from exc
        if result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip() or "Failed to export handshake"
            raise RuntimeError(error)

    def _find_essid(self, packets) -> bytes:
        for pkt in packets:
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                elt = pkt.getlayer(Dot11Elt)
                while elt is not None:
                    if elt.ID == 0 and elt.info:
                        return bytes(elt.info)
                    elt = elt.payload.getlayer(Dot11Elt)
        return b""


class ExcelExporter:
    def export(
        self,
        output_path: Path,
        access_points: Sequence[dict],
        stations: Sequence[dict],
        handshakes: Sequence[dict],
    ) -> None:
        workbook = Workbook()
        ws_ap = workbook.active
        ws_ap.title = "AccessPoints"
        ws_ap.append(["BSSID", "ESSID", "Channel", "Encryption", "Signal", "Last Seen"])
        for ap in access_points:
            ws_ap.append([
                ap.get("bssid"),
                ap.get("essid"),
                ap.get("channel"),
                ap.get("encryption"),
                ap.get("signal"),
                ap.get("last_seen"),
            ])

        ws_stations = workbook.create_sheet("Stations")
        ws_stations.append(["MAC", "Associated BSSID", "Signal", "Last Seen"])
        for station in stations:
            ws_stations.append([
                station.get("mac"),
                station.get("associated_bssid"),
                station.get("signal"),
                station.get("last_seen"),
            ])

        ws_handshakes = workbook.create_sheet("Handshakes")
        ws_handshakes.append(["BSSID", "Station", "Type", "Quality", "Capture Path", "Created At"])
        for handshake in handshakes:
            ws_handshakes.append([
                handshake.get("bssid"),
                handshake.get("station_mac"),
                handshake.get("kind"),
                handshake.get("quality"),
                handshake.get("capture_path"),
                handshake.get("created_at"),
            ])

        workbook.save(output_path)

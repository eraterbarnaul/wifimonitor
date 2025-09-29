import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, EAPOL, sniff, wrpcap  # type: ignore
from scapy.packet import Packet  # type: ignore

from .models import AccessPoint, Handshake, Station

DEFAULT_CHANNELS_24GHZ = list(range(1, 14))
DEFAULT_CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
DEFAULT_CHANNELS = DEFAULT_CHANNELS_24GHZ + DEFAULT_CHANNELS_5GHZ


def set_interface_channel(interface: str, channel: int) -> bool:
    commands = [
        ["iw", "dev", interface, "set", "channel", str(channel)],
        ["iwconfig", interface, "channel", str(channel)],
    ]
    for command in commands:
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
        except FileNotFoundError:
            continue
        if result.returncode == 0:
            return True
    return False


class ChannelHopper:
    def __init__(
        self,
        interface: str,
        channels: Optional[List[int]] = None,
        dwell_time: float = 0.5,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.interface = interface
        self.channels = channels or DEFAULT_CHANNELS
        self.dwell_time = dwell_time
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._log = on_log
        self._last_cycle_logged = -1

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        if not self.channels:
            return
        self._running.set()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        if self._log:
            self._log(f"Перебор каналов запущен ({len(self.channels)} каналов, шаг {self.dwell_time:.2f} с)")

    def stop(self) -> None:
        self._running.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        if self._log:
            self._log("Перебор каналов остановлен")

    def _loop(self) -> None:
        index = 0
        while self._running.is_set() and self.channels:
            channel = self.channels[index % len(self.channels)]
            success = self._set_channel(channel)
            if not success and self._log:
                self._log(f"Не удалось переключить {self.interface} на канал {channel}")
            cycle = index // len(self.channels)
            if self._log and cycle != self._last_cycle_logged and index % len(self.channels) == 0:
                self._last_cycle_logged = cycle
                self._log(f"Завершён цикл перебора каналов #{cycle + 1}")
            index += 1
            time.sleep(self.dwell_time)

    def _set_channel(self, channel: int) -> bool:
        return set_interface_channel(self.interface, channel)


class MonitorService:
    def __init__(
        self,
        interface: str,
        capture_dir: Path,
        on_access_point: Optional[Callable[[AccessPoint], None]] = None,
        on_station: Optional[Callable[[Station], None]] = None,
        on_handshake: Optional[Callable[[Handshake], None]] = None,
        channels: Optional[List[int]] = None,
        channel_hop_interval: float = 0.5,
        enable_channel_hopper: bool = True,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.interface = interface
        self.capture_dir = capture_dir
        self.on_access_point = on_access_point
        self.on_station = on_station
        self.on_handshake = on_handshake
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self._handshake_buffers: Dict[Tuple[str, str], List[Packet]] = defaultdict(list)
        self._channel_hopper: Optional[ChannelHopper] = None
        self._channels = channels
        self._channel_hop_interval = channel_hop_interval
        self._channel_hopper_enabled = enable_channel_hopper
        self._log = on_log
        self._seen_access_points: Set[str] = set()
        self._seen_stations: Set[str] = set()
        self._locked_channel: Optional[int] = None
        self._last_beacon: Dict[str, Packet] = {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._running.set()
        if self._log:
            self._log(f"Старт пассивного сканирования на {self.interface}")
        if self._channel_hopper_enabled and self._locked_channel is None:
            hopper_channels = self._channels if self._channels is not None else DEFAULT_CHANNELS
            self._channel_hopper = ChannelHopper(
                self.interface,
                hopper_channels,
                self._channel_hop_interval,
                on_log=self._log,
            )
            self._channel_hopper.start()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        if self._channel_hopper:
            self._channel_hopper.stop()
            self._channel_hopper = None
        if self._log:
            self._log("Пассивное сканирование остановлено")

    def _sniff_loop(self) -> None:
        sniff(iface=self.interface, prn=self._handle_packet, store=False, stop_filter=self._should_stop)

    def _should_stop(self, _) -> bool:
        return not self._running.is_set()

    def _handle_packet(self, packet) -> None:
        if not packet.haslayer(Dot11):
            return
        dot11 = packet[Dot11]
        bssid = dot11.addr3
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            ap = self._parse_access_point(packet, bssid)
            if ap and self.on_access_point:
                self.on_access_point(ap)
                if self._log and ap.bssid not in self._seen_access_points:
                    self._seen_access_points.add(ap.bssid)
                    essid = ap.essid or "<hidden>"
                    self._log(f"Обнаружена точка доступа {essid} ({ap.bssid}) канал {ap.channel}")
                if bssid:
                    try:
                        self._last_beacon[bssid] = packet.copy()
                    except AttributeError:
                        self._last_beacon[bssid] = packet
        elif dot11.type == 2:
            station_mac = dot11.addr2
            station = Station(mac=station_mac, associated_bssid=bssid, last_seen=datetime.utcnow())
            signal = getattr(packet, "dBm_AntSignal", None)
            if signal is not None:
                station.signal = int(signal)
            if self.on_station:
                self.on_station(station)
                if self._log and station.mac not in self._seen_stations:
                    self._seen_stations.add(station.mac)
                    label = bssid or "неизвестный BSSID"
                    self._log(f"Обнаружен клиент {station.mac} (BSSID {label})")
        if packet.haslayer(EAPOL):
            self._process_handshake(packet, bssid)

    def _parse_access_point(self, packet, bssid: Optional[str]) -> Optional[AccessPoint]:
        if not bssid:
            return None
        essid = None
        channel = None
        encryption = []
        signal = getattr(packet, "dBm_AntSignal", None)
        elt = packet.getlayer(Dot11Elt)
        while elt is not None:
            if elt.ID == 0:
                essid = elt.info.decode(errors="ignore") or None
            elif elt.ID == 3 and elt.info:
                channel = elt.info[0]
            elif elt.ID == 48:
                encryption.append("WPA2")
            elif elt.ID == 221:
                if b"RSN" in elt.info:
                    encryption.append("WPA3")
            elt = elt.payload.getlayer(Dot11Elt)
        ap = AccessPoint(
            bssid=bssid,
            essid=essid,
            channel=channel,
            encryption="/".join(encryption) if encryption else None,
            last_seen=datetime.utcnow(),
        )
        if signal is not None:
            ap.signal = int(signal)
        return ap

    def _process_handshake(self, packet, bssid: Optional[str]) -> None:
        dot11 = packet[Dot11]
        if not bssid:
            return
        transmitter = dot11.addr2
        receiver = dot11.addr1
        if not transmitter or not receiver:
            return
        if transmitter == bssid:
            station_mac = receiver
        else:
            station_mac = transmitter
        if not station_mac:
            return
        key = (bssid, station_mac)
        buffer = self._handshake_buffers[key]
        buffer.append(packet)
        if self._log and packet.haslayer(EAPOL):
            eapol = packet.getlayer(EAPOL)
            info = self._parse_eapol_key_info(eapol)
            if info:
                msg_label = {0: "?", 1: "M1", 2: "M2", 3: "M3", 4: "M4"}.get(info[5], "?")
                direction_ap = transmitter == bssid
                arrow = "AP→STA" if direction_ap else "STA→AP"
                self._log(
                    f"Получен EAPOL кадр #{len(buffer)} {arrow} {msg_label} ack={'Y' if info[1] else 'N'} mic={'Y' if info[3] else 'N'} secure={'Y' if info[4] else 'N'}"
                )
        if self._is_complete_handshake(buffer):
            capture_path = self._write_handshake(key, buffer)
            handshake = Handshake(bssid=bssid, station_mac=station_mac, capture_path=str(capture_path))
            if self.on_handshake:
                self.on_handshake(handshake)
            if self._log:
                self._log(
                    f"Сохранён handshake для {bssid} ⇄ {station_mac}: {capture_path.name}"
                )
            self._handshake_buffers.pop(key, None)

    def lock_channel(self, channel: int) -> bool:
        if channel <= 0:
            return False
        if self._channel_hopper:
            self._channel_hopper.stop()
            self._channel_hopper = None
        success = set_interface_channel(self.interface, channel)
        if success:
            self._locked_channel = channel
            if self._log:
                self._log(f"Фиксация канала {channel} для {self.interface}")
        else:
            if self._log:
                self._log(f"Не удалось зафиксировать канал {channel} для {self.interface}")
        return success

    def unlock_channel(self) -> None:
        if self._locked_channel is None:
            return
        self._locked_channel = None
        if self._channel_hopper_enabled and self._running.is_set():
            hopper_channels = self._channels if self._channels is not None else DEFAULT_CHANNELS
            self._channel_hopper = ChannelHopper(
                self.interface,
                hopper_channels,
                self._channel_hop_interval,
                on_log=self._log,
            )
            self._channel_hopper.start()

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _is_complete_handshake(self, packets: List[Packet]) -> bool:
        ap_msgs: Set[int] = set()
        sta_msgs: Set[int] = set()
        for pkt in packets:
            eapol = pkt.getlayer(EAPOL)
            if not eapol:
                continue
            dot11 = pkt[Dot11]
            info = self._parse_eapol_key_info(eapol)
            if not info:
                continue
            msg = info[5]
            if msg <= 0:
                continue
            if dot11.addr2 == pkt.addr3:
                ap_msgs.add(msg)
            else:
                sta_msgs.add(msg)
        if 3 in ap_msgs and 2 in sta_msgs:
            return True
        if 3 in ap_msgs and 4 in sta_msgs:
            return True
        return False

    def _parse_eapol_key_info(self, eapol: Packet) -> Optional[Tuple[int, bool, bool, bool, bool, int]]:
        raw = bytes(eapol)
        if len(raw) < 7:
            return None
        key_info = int.from_bytes(raw[5:7], "big")
        ack = bool(key_info & 0x0080)
        install = bool(key_info & 0x0040)
        mic = bool(key_info & 0x0100)
        secure = bool(key_info & 0x0200)
        if ack and not mic:
            msg = 1
        elif mic and ack and install:
            msg = 3
        elif mic and not ack and not install:
            msg = 4 if secure else 2
        else:
            msg = 0
        return key_info, ack, install, mic, secure, msg

    def _write_handshake(self, key: Tuple[str, str], packets: List[Packet]) -> Path:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"handshake_{key[0].replace(':', '')}_{key[1].replace(':', '')}_{timestamp}.pcap"
        path = self.capture_dir / filename
        to_dump: List[Packet] = []
        beacon = self._last_beacon.get(key[0])
        if beacon is not None:
            try:
                to_dump.append(beacon.copy())
            except AttributeError:
                to_dump.append(beacon)
        to_dump.extend(packets)
        wrpcap(str(path), to_dump)
        return path

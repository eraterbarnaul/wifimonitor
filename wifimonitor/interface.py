import re
import subprocess
from typing import List, Optional


class InterfaceManager:
    def __init__(self, monitor_interface: Optional[str] = None) -> None:
        self.base_interface: Optional[str] = None
        self.monitor_interface = monitor_interface
        self._auto_started = False

    def set_base_interface(self, interface: str) -> None:
        self.base_interface = interface
        self.monitor_interface = interface
        self._auto_started = False

    def ensure_monitor_mode(self, interface: Optional[str] = None) -> str:
        if interface:
            self.set_base_interface(interface)
        if not self.base_interface:
            raise ValueError("Не указан интерфейс для активации мониторного режима")
        if self._is_monitor_mode(self.base_interface):
            self.monitor_interface = self.base_interface
            self._auto_started = False
            return self.monitor_interface
        output = self._start_monitor_mode(self.base_interface)
        monitor_iface = self._parse_monitor_interface(output) or f"{self.base_interface}mon"
        self.monitor_interface = monitor_iface
        self._auto_started = True
        return monitor_iface

    def enable_monitor_mode(self) -> str:
        return self.ensure_monitor_mode()

    def disable_monitor_mode(self) -> None:
        if not self.monitor_interface:
            raise ValueError("Мониторный интерфейс не задан")
        if not self._auto_started:
            return
        output = self._run_command(["airmon-ng", "stop", self.monitor_interface], check=False)
        if output.returncode != 0:
            message = output.stderr.strip() or output.stdout.strip() or "Не удалось остановить мониторный режим"
            raise RuntimeError(message)
        self.monitor_interface = self.base_interface
        self._auto_started = False

    def get_active_interface(self) -> Optional[str]:
        return self.monitor_interface

    def list_wireless_interfaces(self) -> List[str]:
        interfaces: List[str] = []
        try:
            result = self._run_command(["iw", "dev"], check=False)
            output = (result.stdout or "") + (result.stderr or "")
            interfaces.extend(re.findall(r"Interface\s+(\S+)", output))
        except FileNotFoundError:
            pass
        if not interfaces:
            try:
                result = self._run_command(["iwconfig"], check=False)
            except FileNotFoundError:
                return interfaces
            output = (result.stdout or "") + (result.stderr or "")
            for line in output.splitlines():
                line = line.strip()
                if not line or "no wireless extensions" in line.lower():
                    continue
                iface = line.split()[0]
                if iface not in interfaces:
                    interfaces.append(iface)
        return interfaces

    def _start_monitor_mode(self, interface: str) -> str:
        try:
            result = self._run_command(["airmon-ng", "start", interface])
        except RuntimeError as exc:
            message = str(exc)
            if "process" in message.lower():
                self._run_command(["airmon-ng", "check", "kill"], check=False)
                result = self._run_command(["airmon-ng", "start", interface])
            else:
                raise
        return (result.stdout or "") + (result.stderr or "")

    def _is_monitor_mode(self, interface: str) -> bool:
        try:
            result = self._run_command(["iwconfig", interface], check=False)
        except FileNotFoundError:
            return interface.endswith("mon")
        output = (result.stdout or "") + (result.stderr or "")
        return "Mode:Monitor" in output

    def _parse_monitor_interface(self, output: str) -> Optional[str]:
        patterns = [
            r"monitor mode vif enabled for .* on ([\w-]+)",
            r"new monitor mode interface ([\w-]+)",
            r"monitor mode enabled on ([\w-]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                return match.group(1)
        candidates = re.findall(r"\b[\w-]+mon\b", output)
        if candidates:
            return candidates[-1]
        return None

    def _run_command(self, command: List[str], check: bool = True) -> subprocess.CompletedProcess:
        try:
            process = subprocess.run(command, capture_output=True, text=True, check=False)
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"Команда '{command[0]}' не найдена. Установите необходимые утилиты.") from exc
        if check and process.returncode != 0:
            message = process.stderr.strip() or process.stdout.strip() or "Не удалось выполнить команду"
            raise RuntimeError(message)
        return process

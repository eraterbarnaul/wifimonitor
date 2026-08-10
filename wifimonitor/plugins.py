"""Plugin architecture for attack modules.

Each attack plugin implements the AttackPlugin protocol and registers itself
with the PluginRegistry. This allows easy extension without modifying core code.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Type


@dataclass
class AttackResult:
    """Outcome of an attack plugin execution."""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    message: str = ""


class AttackPlugin(ABC):
    """Base class for all attack plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for the plugin."""

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name shown in the UI."""

    @property
    @abstractmethod
    def description(self) -> str:
        """Short description of what the plugin does."""

    @property
    def requires_monitor(self) -> bool:
        """Whether the plugin needs the interface in monitor mode."""
        return True

    @property
    def requires_clients(self) -> bool:
        """Whether the plugin needs active clients on the target AP."""
        return False

    @abstractmethod
    def start(self, context: "AttackContext") -> None:
        """Begin the attack. Should be non-blocking (launch a thread)."""

    @abstractmethod
    def stop(self) -> None:
        """Stop the attack gracefully."""

    @abstractmethod
    def is_running(self) -> bool:
        """Whether the attack is currently in progress."""


@dataclass
class AttackContext:
    """Runtime context passed to attack plugins."""
    interface: str
    bssid: str
    channel: Optional[int] = None
    essid: Optional[str] = None
    clients: List[str] = field(default_factory=list)
    capture_dir: str = ""
    log: Optional[Callable[[str], None]] = None
    on_result: Optional[Callable[[AttackResult], None]] = None
    extra: Dict[str, Any] = field(default_factory=dict)


class PluginRegistry:
    """Registry of available attack plugins."""

    def __init__(self) -> None:
        self._plugins: Dict[str, Type[AttackPlugin]] = {}
        self._lock = threading.Lock()

    def register(self, plugin_class: Type[AttackPlugin]) -> Type[AttackPlugin]:
        """Register a plugin class. Can be used as a decorator."""
        instance = plugin_class.__new__(plugin_class)
        # Get name from class without full __init__
        name = plugin_class.name.fget(instance) if hasattr(plugin_class.name, 'fget') else ""
        if not name:
            name = plugin_class.__name__
        with self._lock:
            self._plugins[name] = plugin_class
        return plugin_class

    def get(self, name: str) -> Optional[Type[AttackPlugin]]:
        with self._lock:
            return self._plugins.get(name)

    def list_plugins(self) -> List[Dict[str, str]]:
        with self._lock:
            result = []
            for name, cls in self._plugins.items():
                instance = cls.__new__(cls)
                result.append({
                    "name": name,
                    "display_name": cls.display_name.fget(instance) if hasattr(cls.display_name, 'fget') else name,
                    "description": cls.description.fget(instance) if hasattr(cls.description, 'fget') else "",
                })
            return result

    @property
    def names(self) -> List[str]:
        with self._lock:
            return list(self._plugins.keys())


# Global registry
registry = PluginRegistry()


class DeauthAttackPlugin(AttackPlugin):
    """Deauthentication attack plugin."""

    def __init__(self) -> None:
        self._service = None

    @property
    def name(self) -> str:
        return "deauth"

    @property
    def display_name(self) -> str:
        return "Деаутентификация"

    @property
    def description(self) -> str:
        return "Отключение клиентов от точки доступа для перехвата handshake"

    @property
    def requires_clients(self) -> bool:
        return True

    def start(self, context: AttackContext) -> None:
        from .deauth import DeauthService
        if not context.clients:
            raise ValueError("Нет клиентов для деаутентификации")
        self._service = DeauthService(context.interface, log_callback=context.log)
        packets = context.extra.get("packets", 5)
        interval = context.extra.get("interval", 1.0)
        self._service.start(context.bssid, context.clients, packets, interval)

    def stop(self) -> None:
        if self._service:
            self._service.stop()
            self._service = None

    def is_running(self) -> bool:
        return self._service is not None and self._service.is_running()


class WpsAttackPlugin(AttackPlugin):
    """WPS PIN attack plugin (reaver/bully)."""

    def __init__(self) -> None:
        self._service = None

    @property
    def name(self) -> str:
        return "wps"

    @property
    def display_name(self) -> str:
        return "WPS-атака"

    @property
    def description(self) -> str:
        return "Подбор WPS PIN через reaver/bully (Pixie Dust / онлайн)"

    def start(self, context: AttackContext) -> None:
        from .wps_attack import WpsAttackService

        def on_wps_result(result: dict) -> None:
            if context.on_result:
                context.on_result(AttackResult(success=True, data=result))

        tool = context.extra.get("tool", "reaver")
        self._service = WpsAttackService(
            context.interface,
            tool=tool,
            log_callback=context.log,
            on_result=on_wps_result,
        )
        self._service.start(context.bssid, context.channel)

    def stop(self) -> None:
        if self._service:
            self._service.stop()
            self._service = None

    def is_running(self) -> bool:
        return self._service is not None and self._service.is_running()


class PmkidRequestPlugin(AttackPlugin):
    """Active PMKID solicitation plugin."""

    def __init__(self) -> None:
        self._running = False

    @property
    def name(self) -> str:
        return "pmkid_request"

    @property
    def display_name(self) -> str:
        return "Запрос PMKID"

    @property
    def description(self) -> str:
        return "Активный запрос PMKID (association request без клиента)"

    def start(self, context: AttackContext) -> None:
        from .pmkid_request import request_pmkid
        self._running = True
        request_pmkid(
            context.interface,
            context.bssid,
            essid=context.essid or "",
            channel=context.channel,
            log=context.log,
        )
        self._running = False
        if context.on_result:
            context.on_result(AttackResult(success=True, message="PMKID запрос отправлен"))

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return self._running


class CrackPlugin(AttackPlugin):
    """Dictionary cracking via aircrack-ng."""

    def __init__(self) -> None:
        self._service = None

    @property
    def name(self) -> str:
        return "crack"

    @property
    def display_name(self) -> str:
        return "Словарный взлом"

    @property
    def description(self) -> str:
        return "Подбор пароля по словарю через aircrack-ng"

    @property
    def requires_monitor(self) -> bool:
        return False

    def start(self, context: AttackContext) -> None:
        from .crack import CrackService

        def on_crack_result(result: dict) -> None:
            if context.on_result:
                context.on_result(AttackResult(success=bool(result.get("key")), data=result))

        self._service = CrackService(
            log_callback=context.log,
            on_result=on_crack_result,
        )
        capture_path = context.extra.get("capture_path", "")
        wordlist = context.extra.get("wordlist", "")
        self._service.start(capture_path, context.bssid, wordlist)

    def stop(self) -> None:
        if self._service:
            self._service.stop()
            self._service = None

    def is_running(self) -> bool:
        return self._service is not None and self._service.is_running()


# Register built-in plugins
registry.register(DeauthAttackPlugin)
registry.register(WpsAttackPlugin)
registry.register(PmkidRequestPlugin)
registry.register(CrackPlugin)

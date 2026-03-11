"""tor_manager.py - AnonShare Tor Connection Manager."""
import socket, time, logging
from typing import Optional
import config

log = logging.getLogger(__name__)

try:
    import socks as _socks
    _SOCKS_AVAILABLE = True
except ImportError:
    _socks = None
    _SOCKS_AVAILABLE = False

try:
    import requests as _requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _requests = None
    _REQUESTS_AVAILABLE = False


class TorError(Exception):
    pass


class TorManager:
    """Route all socket traffic through Tor SOCKS5; verify anonymity; rotate circuits."""

    def __init__(self, socks_host: str = config.TOR_SOCKS_HOST,
                 socks_port: int = config.TOR_SOCKS_PORT,
                 control_port: int = config.TOR_CONTROL_PORT):
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.control_port = control_port
        self._original_socket = socket.socket
        self._active = False

    def enable(self) -> None:
        if not _SOCKS_AVAILABLE:
            raise TorError("PySocks not installed. Run: pip install PySocks")
        if self._active: return
        _socks.setdefaultproxy(_socks.PROXY_TYPE_SOCKS5, self.socks_host, self.socks_port, rdns=True)
        socket.socket = _socks.socksocket
        self._active = True

    def disable(self) -> None:
        if not self._active: return
        if _SOCKS_AVAILABLE:
            _socks.setdefaultproxy()
        socket.socket = self._original_socket
        self._active = False

    def is_tor_running(self) -> bool:
        try:
            with socket.create_connection((self.socks_host, self.socks_port), timeout=3):
                return True
        except OSError:
            return False

    def verify_tor_connection(self, timeout: int = 15) -> bool:
        if not _REQUESTS_AVAILABLE:
            return False
        proxies = {
            "http":  f"socks5h://{self.socks_host}:{self.socks_port}",
            "https": f"socks5h://{self.socks_host}:{self.socks_port}",
        }
        try:
            r = _requests.get("https://check.torproject.org/api/ip", proxies=proxies, timeout=timeout)
            return bool(r.json().get("IsTor", False))
        except Exception:
            return False

    def verify_or_raise(self) -> None:
        if not self.is_tor_running():
            raise TorError(
                f"Tor SOCKS5 proxy not reachable at {self.socks_host}:{self.socks_port}.\n"
                "Start Tor:  sudo systemctl start tor  (Linux) | brew services start tor  (macOS)"
            )
        if not self.verify_tor_connection():
            raise TorError("Tor is running but traffic does not appear to exit via Tor. Check your Tor configuration.")

    def new_circuit(self, wait: float = 1.0) -> bool:
        try:
            from stem import Signal
            from stem.control import Controller
            with Controller.from_port(port=self.control_port) as ctrl:
                ctrl.authenticate()
                ctrl.signal(Signal.NEWNYM)
            time.sleep(wait)
            return True
        except Exception as exc:
            log.warning("Failed to rotate Tor circuit: %s", exc)
            return False

    def get_exit_ip(self, timeout: int = 15) -> Optional[str]:
        if not _REQUESTS_AVAILABLE:
            return None
        proxies = {"https": f"socks5h://{self.socks_host}:{self.socks_port}"}
        try:
            return _requests.get("https://check.torproject.org/api/ip",
                                proxies=proxies, timeout=timeout).json().get("IP")
        except Exception:
            return None

    def __enter__(self): self.enable(); return self
    def __exit__(self, *_): self.disable()

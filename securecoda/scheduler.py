from __future__ import annotations

import logging
import threading

from .scanner import Scanner


logger = logging.getLogger(__name__)


class Poller:
    def __init__(self, scanner: Scanner, interval_seconds: int) -> None:
        self.scanner = scanner
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="securecoda-poller", daemon=True)
        self._thread.start()
        logger.info("Started SecureCoda poller with %s second interval", self.interval_seconds)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def trigger_once(self) -> bool:
        if not self._lock.acquire(blocking=False):
            logger.info("Scan skipped because another scan is already running")
            return False
        try:
            self.scanner.scan()
            return True
        finally:
            self._lock.release()

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self.trigger_once()


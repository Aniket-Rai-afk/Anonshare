"""
utils.py - Utility helpers for AnonShare.
"""

from __future__ import annotations

import os
import re
import sys
import time
import random
import logging
import hashlib
import struct

from config import TIMING_DELAY_MIN, TIMING_DELAY_MAX

log = logging.getLogger(__name__)

_CODE_PATTERN = re.compile(r"^\d+-[a-z]+-[a-z]+(-[a-z0-9]+)*$", re.IGNORECASE)


def human_size(num_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.2f} {unit}"
        num_bytes /= 1024.0  # type: ignore[assignment]
    return f"{num_bytes:.2f} PB"


def validate_code(code: str) -> bool:
    return bool(_CODE_PATTERN.match(code.strip()))


def save_file_securely(data: bytes, filename: str, output_dir: str = ".") -> str:
    os.makedirs(output_dir, exist_ok=True)
    dest = os.path.join(output_dir, os.path.basename(filename))
    tmp_path = dest + ".tmp"
    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.rename(tmp_path, dest)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    try:
        os.chmod(dest, 0o600)
    except (AttributeError, NotImplementedError):
        pass
    return os.path.abspath(dest)


def timing_delay() -> None:
    delay = random.uniform(TIMING_DELAY_MIN, TIMING_DELAY_MAX)
    log.debug("Timing delay: %.2fs", delay)
    time.sleep(delay)


class ProgressBar:
    def __init__(self, total: int, label: str = "", width: int = 40) -> None:
        self.total = max(total, 1)
        self.label = label
        self.width = width
        self._done = 0
        self._start = time.monotonic()

    def update(self, chunk_size: int) -> None:
        self._done = min(self._done + chunk_size, self.total)
        self._render()

    def finish(self) -> None:
        self._done = self.total
        self._render()
        sys.stderr.write("\n")
        sys.stderr.flush()

    def _render(self) -> None:
        frac = self._done / self.total
        filled = int(self.width * frac)
        bar = "█" * filled + "░" * (self.width - filled)
        elapsed = time.monotonic() - self._start
        speed = self._done / elapsed if elapsed > 0 else 0
        pct = frac * 100
        line = (
            f"\r{self.label} [{bar}] {pct:5.1f}%  "
            f"{human_size(self._done)}/{human_size(self.total)}  "
            f"{human_size(int(speed))}/s"
        )
        sys.stderr.write(line)
        sys.stderr.flush()

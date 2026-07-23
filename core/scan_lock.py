from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from pathlib import Path

LOCK_PATH = Path(__file__).resolve().parent.parent / "data" / "scan.lock"


class ScanBusyError(RuntimeError):
    pass


def _lock_age_seconds() -> float | None:
    try:
        return max(0.0, time.time() - LOCK_PATH.stat().st_mtime)
    except OSError:
        return None


@contextmanager
def global_scan_lock(
    stale_after_seconds: int = 180,
    wait_seconds: float = 20.0,
    poll_interval: float = 0.25,
):
    """Cross-session/process FIFO-ish serialization for connect+scan operations.

    Callers wait briefly for the previous scan instead of opening a parallel SSH
    management session. The OS O_EXCL lock remains the source of truth.
    """
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + max(0.0, float(wait_seconds))
    fd = None

    while True:
        age = _lock_age_seconds()
        if age is not None and age > max(60, stale_after_seconds):
            try:
                LOCK_PATH.unlink()
            except OSError:
                pass

        try:
            fd = os.open(str(LOCK_PATH), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            payload = json.dumps({"pid": os.getpid(), "started_at": time.time()}).encode("utf-8")
            os.write(fd, payload)
            os.close(fd)
            fd = None
            break
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise ScanBusyError(
                    "Scan queue đang bận quá lâu. Không mở thêm SSH session song song; hãy thử lại sau khi scan hiện tại kết thúc."
                )
            time.sleep(max(0.05, float(poll_interval)))

    try:
        yield
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            LOCK_PATH.unlink()
        except OSError:
            pass

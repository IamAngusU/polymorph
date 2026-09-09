from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write_text(
    path: str | Path,
    text: str,
    *,
    encoding: str = "utf-8",
    private: bool = False,
) -> None:
    """Replace a text file atomically within its directory where the OS supports rename."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        if private and os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding=encoding, newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        if private and os.name == "posix":
            os.chmod(target, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise

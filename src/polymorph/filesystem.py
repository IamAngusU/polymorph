from __future__ import annotations

import errno
import hashlib
import importlib
import math
import os
import stat
import tempfile
import threading
import time
from _thread import LockType
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Protocol, cast


class PathLockError(OSError):
    """Raised when a destination path cannot be locked safely."""


class PathLockTimeout(PathLockError):
    """Raised when another writer holds a destination path past the configured deadline."""


_THREAD_LOCKS_GUARD = threading.Lock()
_THREAD_LOCKS: dict[str, tuple[LockType, int]] = {}


class _MsvcrtModule(Protocol):
    LK_NBLCK: int
    LK_UNLCK: int

    def locking(self, fd: int, mode: int, nbytes: int) -> None: ...


class _FcntlModule(Protocol):
    LOCK_EX: int
    LOCK_NB: int
    LOCK_UN: int

    def flock(self, fd: int, operation: int) -> None: ...


def _msvcrt() -> _MsvcrtModule:
    return cast(_MsvcrtModule, importlib.import_module("msvcrt"))


def _fcntl() -> _FcntlModule:
    return cast(_FcntlModule, importlib.import_module("fcntl"))


def _canonical_path(path: str | Path) -> tuple[Path, str]:
    target = Path(path).resolve(strict=False)
    return target, os.path.normcase(str(target))


def _thread_lock_for(key: str) -> LockType:
    with _THREAD_LOCKS_GUARD:
        current = _THREAD_LOCKS.get(key)
        if current is None:
            lock = threading.Lock()
            _THREAD_LOCKS[key] = (lock, 1)
            return lock
        lock, users = current
        _THREAD_LOCKS[key] = (lock, users + 1)
        return lock


def _release_thread_lock_reference(key: str, lock: LockType) -> None:
    with _THREAD_LOCKS_GUARD:
        current = _THREAD_LOCKS.get(key)
        if current is None or current[0] is not lock:
            return
        users = current[1] - 1
        if users:
            _THREAD_LOCKS[key] = (lock, users)
        else:
            del _THREAD_LOCKS[key]


def _lock_file_for(target: Path, key: str) -> Path:
    digest = hashlib.sha256(key.encode("utf-8", errors="surrogatepass")).hexdigest()
    return target.parent / f".polymorph-write-{digest}.lock"


def _open_lock_file(path: Path) -> int:
    flags = os.O_CREAT | os.O_RDWR
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise PathLockError("could not open the destination write lock") from exc
    try:
        opened = os.fstat(fd)
        linked = path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(linked.st_mode)
            or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
        ):
            raise PathLockError("destination write lock is not a stable regular file")
        if opened.st_size == 0:
            os.write(fd, b"\0")
            os.fsync(fd)
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except Exception:
        os.close(fd)
        raise


def _try_lock(fd: int) -> bool:
    try:
        if os.name == "nt":
            os.lseek(fd, 0, os.SEEK_SET)
            win_module = _msvcrt()
            win_module.locking(fd, win_module.LK_NBLCK, 1)
        else:
            posix_module = _fcntl()
            posix_module.flock(fd, posix_module.LOCK_EX | posix_module.LOCK_NB)
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK} or getattr(
            exc, "winerror", None
        ) in {33, 36, 158}:
            return False
        raise PathLockError("could not acquire the destination write lock") from exc
    return True


def _unlock(fd: int) -> None:
    if os.name == "nt":
        os.lseek(fd, 0, os.SEEK_SET)
        win_module = _msvcrt()
        win_module.locking(fd, win_module.LK_UNLCK, 1)
    else:
        posix_module = _fcntl()
        posix_module.flock(fd, posix_module.LOCK_UN)


@contextmanager
def exclusive_path_lock(
    path: str | Path,
    *,
    timeout_seconds: float = 30.0,
    poll_interval_seconds: float = 0.05,
) -> Iterator[None]:
    """Serialize cooperative writers to one path across threads and processes.

    The adjacent lock file is deliberately persistent. Removing it after release would allow
    concurrent writers to lock different inodes. The target itself is never created or opened
    by this helper.
    """

    if not math.isfinite(timeout_seconds) or timeout_seconds < 0:
        raise ValueError("path lock timeout must be a finite non-negative number")
    if not math.isfinite(poll_interval_seconds) or poll_interval_seconds <= 0:
        raise ValueError("path lock poll interval must be a finite positive number")

    target, key = _canonical_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout_seconds
    thread_lock = _thread_lock_for(key)
    thread_acquired = False
    fd: int | None = None
    locked = False
    try:
        thread_acquired = thread_lock.acquire(timeout=max(0.0, deadline - time.monotonic()))
        if not thread_acquired:
            raise PathLockTimeout("timed out waiting for the destination write lock")

        fd = _open_lock_file(_lock_file_for(target, key))
        while not (locked := _try_lock(fd)):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PathLockTimeout("timed out waiting for the destination write lock")
            time.sleep(min(poll_interval_seconds, remaining))
        yield
    finally:
        if locked and fd is not None:
            # Closing the descriptor also releases the kernel lock. An explicit unlock keeps
            # normal operation immediate; close remains the safety net if unlock is interrupted.
            with suppress(OSError):
                _unlock(fd)
        if fd is not None:
            with suppress(OSError):
                os.close(fd)
        if thread_acquired:
            thread_lock.release()
        _release_thread_lock_reference(key, thread_lock)


def atomic_write_text(
    path: str | Path,
    text: str,
    *,
    encoding: str = "utf-8",
    private: bool = False,
    overwrite: bool = True,
) -> None:
    """Publish a complete text file atomically within its directory."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        if private and os.name == "posix":
            os.chmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding=encoding, newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        if overwrite:
            os.replace(temporary, target)
        else:
            # Linking a fully flushed temporary file creates the destination name only if it
            # does not already exist. This avoids a check-then-replace race for key material.
            os.link(temporary, target)
            os.unlink(temporary)
        if private and os.name == "posix":
            os.chmod(target, 0o600)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise

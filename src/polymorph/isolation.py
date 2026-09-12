from __future__ import annotations

import contextlib
import hashlib
import importlib
import json
import math
import os
import re
import secrets
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Final, Protocol, cast

from .errors import PolymorphError

_PROTOCOL: Final[str] = "polymorph.parser-worker"
_PROTOCOL_VERSION: Final[int] = 1
_MAX_REQUEST_BYTES: Final[int] = 64 * 1024
_MAX_RESPONSE_BYTES: Final[int] = 256 * 1024
_MAX_JSON_DEPTH: Final[int] = 8
_MAX_JSON_NODES: Final[int] = 4096
_MAX_INSPECTION_ITEMS: Final[int] = 256
_MAX_TEXT_BYTES: Final[int] = 4096
_MAX_SHORT_TEXT_BYTES: Final[int] = 256
_COPY_CHUNK_BYTES: Final[int] = 1024 * 1024
_FREE_SPACE_RESERVE_BYTES: Final[int] = 1024 * 1024
_MAX_INPUT_BYTES: Final[int] = 1024 * 1024 * 1024 * 1024
_MAX_MEMORY_BYTES: Final[int] = 64 * 1024 * 1024 * 1024
_MAX_OUTPUT_FILE_BYTES: Final[int] = 16 * 1024 * 1024 * 1024
_MAX_PARSER_LOG_BYTES: Final[int] = 16 * 1024 * 1024
_MAX_TMPFS_BYTES: Final[int] = 64 * 1024 * 1024 * 1024
_APP_ROOT_TMPFS_BYTES: Final[int] = 1024 * 1024
_MAX_CAPTURE_BYTES: Final[int] = _MAX_RESPONSE_BYTES
_MAX_POLICY_SECONDS: Final[int] = 3600
_MAX_OPEN_FILES: Final[int] = 65536
_MAX_PROCESSES: Final[int] = 4096
_MAX_SIGNED_INTEGER: Final[int] = (1 << 63) - 1
_BWRAP_MIN_VERSION: Final[tuple[int, int, int]] = (0, 12, 0)
_BWRAP_PROBE_MAX_BYTES: Final[int] = 64 * 1024
_BWRAP_PROBE_TIMEOUT_SECONDS: Final[float] = 2.0
_RESOURCE_SAMPLE_INTERVAL_SECONDS: Final[float] = 0.005
_BWRAP_REQUIRED_OPTIONS: Final[tuple[str, ...]] = (
    "--assert-userns-disabled",
    "--cap-drop",
    "--chdir",
    "--clearenv",
    "--dev",
    "--disable-userns",
    "--die-with-parent",
    "--new-session",
    "--proc",
    "--remount-ro",
    "--ro-bind",
    "--setenv",
    "--size",
    "--tmpfs",
    "--unshare-all",
)
_BWRAP_VERSION_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(?:^|\s)bubblewrap\s+(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?=\s|$)"
)
_WORKER_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        "input_changed",
        "input_digest_mismatch",
        "input_link_rejected",
        "input_not_regular",
        "input_size_mismatch",
        "input_unavailable",
        "inspection_failed",
        "invalid_arguments",
        "invalid_inspection_result",
        "invalid_request",
        "invalid_request_encoding",
        "invalid_request_json",
        "parser_log_limit_exceeded",
        "request_not_regular",
        "request_too_large",
        "resource_limit_failed",
        "resource_limits_unavailable",
        "response_too_large",
        "unsupported_operation",
        "unsupported_protocol",
        "unsupported_version",
        "worker_failed",
    }
)

_CONTENT_KINDS: Final[frozenset[str]] = frozenset(
    {
        "xlsx",
        "docx",
        "pptx",
        "zip",
        "json",
        "json5",
        "delimited_text",
        "text",
        "xml",
        "pdf",
        "sqlite",
        "parquet",
        "ole_compound",
        "gzip",
        "image",
        "executable",
        "binary",
        "empty",
        "unknown",
    }
)
_RISK_CODES: Final[frozenset[str]] = frozenset(
    {
        "symlink_input",
        "non_regular_input",
        "file_too_large",
        "archive_too_many_entries",
        "archive_too_large",
        "archive_member_too_large",
        "archive_high_compression_ratio",
        "archive_scan_budget_exceeded",
        "archive_path_traversal",
        "archive_symlink",
        "archive_duplicate_entry",
        "archive_encrypted_member",
        "archive_metadata_too_large",
        "office_macro",
        "office_external_link",
        "office_external_data",
        "classifier_disagreement",
        "malformed_archive",
        "file_changed_during_inspection",
        "json_nesting_too_deep",
        "json_too_many_items",
        "xml_nesting_too_deep",
        "xml_too_many_elements",
        "xml_too_many_attributes",
    }
)


class IsolationLevel(IntEnum):
    """Containment guarantees in increasing order."""

    PROCESS = 10
    RESOURCE_LIMITED_PROCESS = 20
    OS_SANDBOX = 30


class SandboxErrorCode(StrEnum):
    INPUT_NOT_REGULAR = "input_not_regular"
    INPUT_SYMLINK = "input_symlink"
    INPUT_REPARSE_POINT = "input_reparse_point"
    INPUT_TOO_LARGE = "input_too_large"
    INPUT_CHANGED = "input_changed"
    INPUT_SNAPSHOT_CHANGED = "input_snapshot_changed"
    INSUFFICIENT_FREE_SPACE = "insufficient_free_space"
    SNAPSHOT_FAILED = "snapshot_failed"
    BACKEND_UNAVAILABLE = "backend_unavailable"
    CONTAINMENT_TOO_WEAK = "containment_too_weak"
    WORKER_START_FAILED = "worker_start_failed"
    WORKER_TIMEOUT = "worker_timeout"
    WORKER_OUTPUT_LIMIT = "worker_output_limit"
    WORKER_TERMINATION_FAILED = "worker_termination_failed"
    WORKER_IO_FAILED = "worker_io_failed"
    WORKER_FAILED = "worker_failed"
    PROTOCOL_ERROR = "protocol_error"
    REQUEST_MISMATCH = "request_mismatch"


class SandboxError(PolymorphError):
    def __init__(
        self,
        code: SandboxErrorCode,
        message: str,
        *,
        worker_error_code: str | None = None,
        stderr_digest: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.worker_error_code = worker_error_code
        self.stderr_digest = stderr_digest


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    """Limits and minimum containment required for a parser worker."""

    minimum_level: IsolationLevel = IsolationLevel.OS_SANDBOX
    wall_timeout_seconds: float = 15.0
    cpu_seconds: int = 10
    max_input_bytes: int = 512 * 1024 * 1024
    max_memory_bytes: int = 512 * 1024 * 1024
    max_stdout_bytes: int = _MAX_RESPONSE_BYTES
    max_stderr_bytes: int = 128 * 1024
    max_output_file_bytes: int = _MAX_RESPONSE_BYTES
    max_parser_log_bytes: int = 64 * 1024
    max_tmpfs_bytes: int = 512 * 1024 * 1024
    max_open_files: int = 64
    max_processes: int = 64

    def __post_init__(self) -> None:
        if not isinstance(self.minimum_level, IsolationLevel):
            raise TypeError("minimum_level must be an IsolationLevel")
        if isinstance(self.wall_timeout_seconds, bool) or not isinstance(
            self.wall_timeout_seconds, (int, float)
        ):
            raise TypeError("wall_timeout_seconds must be a finite number")
        try:
            timeout = float(self.wall_timeout_seconds)
        except (OverflowError, ValueError):
            raise ValueError(
                f"wall_timeout_seconds must be finite and within (0, {_MAX_POLICY_SECONDS}]"
            ) from None
        if not math.isfinite(timeout) or timeout <= 0 or timeout > _MAX_POLICY_SECONDS:
            raise ValueError(
                f"wall_timeout_seconds must be finite and within (0, {_MAX_POLICY_SECONDS}]"
            )

        _validate_policy_integer(
            "max_input_bytes",
            self.max_input_bytes,
            upper=_MAX_INPUT_BYTES,
        )
        _validate_policy_integer(
            "max_memory_bytes",
            self.max_memory_bytes,
            upper=_MAX_MEMORY_BYTES,
        )
        _validate_policy_integer(
            "max_output_file_bytes",
            self.max_output_file_bytes,
            upper=_MAX_OUTPUT_FILE_BYTES,
        )
        _validate_policy_integer(
            "max_parser_log_bytes",
            self.max_parser_log_bytes,
            upper=_MAX_PARSER_LOG_BYTES,
        )
        _validate_policy_integer(
            "max_tmpfs_bytes",
            self.max_tmpfs_bytes,
            upper=_MAX_TMPFS_BYTES,
        )
        for name in ("max_stdout_bytes", "max_stderr_bytes"):
            _validate_policy_integer(name, getattr(self, name), upper=_MAX_CAPTURE_BYTES)
        _validate_policy_integer("cpu_seconds", self.cpu_seconds, upper=_MAX_POLICY_SECONDS)
        _validate_policy_integer("max_open_files", self.max_open_files, upper=_MAX_OPEN_FILES)
        _validate_policy_integer("max_processes", self.max_processes, upper=_MAX_PROCESSES)

    @classmethod
    def local_process(cls) -> SandboxPolicy:
        """Explicit policy for trusted local files without an OS sandbox."""

        return cls(minimum_level=IsolationLevel.PROCESS)


@dataclass(frozen=True, slots=True)
class SnapshotFileIdentity:
    device: int
    inode: int
    mode: int
    size_bytes: int
    mtime_ns: int
    ctime_ns: int
    file_attributes: int

    @classmethod
    def from_stat(cls, metadata: os.stat_result) -> SnapshotFileIdentity:
        return cls(
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mode=stat.S_IFMT(metadata.st_mode),
            size_bytes=metadata.st_size,
            mtime_ns=metadata.st_mtime_ns,
            ctime_ns=metadata.st_ctime_ns,
            file_attributes=int(getattr(metadata, "st_file_attributes", 0)),
        )


@dataclass(frozen=True, slots=True)
class InputSnapshot:
    path: Path
    size_bytes: int
    sha256: str
    source_identity: SnapshotFileIdentity
    snapshot_identity: SnapshotFileIdentity
    duration_seconds: float


@dataclass(frozen=True, slots=True)
class SandboxBackendInfo:
    name: str
    level: IsolationLevel
    available: bool
    capabilities: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class _BubblewrapRuntimeLayout:
    executable: PurePosixPath
    mounts: tuple[tuple[Path, PurePosixPath], ...]


@dataclass(frozen=True, slots=True)
class SandboxRunResult:
    backend: str
    isolation_level: IsolationLevel
    backend_capabilities: tuple[str, ...]
    exit_code: int
    stdout: bytes
    stderr_digest: str
    duration_seconds: float
    stdout_bytes: int
    stderr_bytes: int
    resource_measurement: str
    resource_sample_count: int
    child_peak_rss_bytes: int | None
    child_cpu_seconds: float | None
    child_read_bytes: int | None
    child_write_bytes: int | None


@dataclass(frozen=True, slots=True)
class IsolatedContentInspection:
    request_id: str
    snapshot_sha256: str
    snapshot_size_bytes: int
    backend: str
    isolation_level: IsolationLevel
    backend_capabilities: tuple[str, ...]
    snapshot_duration_seconds: float
    worker_duration_seconds: float
    end_to_end_duration_seconds: float
    stdout_bytes: int
    stderr_bytes: int
    stderr_digest: str
    resource_measurement: str
    resource_sample_count: int
    child_peak_rss_bytes: int | None
    child_cpu_seconds: float | None
    child_read_bytes: int | None
    child_write_bytes: int | None
    inspection: dict[str, object]

    @property
    def os_sandboxed(self) -> bool:
        return self.isolation_level >= IsolationLevel.OS_SANDBOX


def _validate_policy_integer(name: str, value: object, *, upper: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value <= 0 or value > upper:
        raise ValueError(f"{name} must be within [1, {upper}]")


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attribute = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & attribute)


def _first_link_like_parent(path: Path) -> tuple[SandboxErrorCode, str] | None:
    """Find a linked parent component without resolving the input path."""

    candidate = path if path.is_absolute() else Path.cwd() / path
    current = Path(candidate.anchor)
    parts = candidate.parts[1:] if candidate.anchor else candidate.parts
    for part in parts[:-1]:
        if part in {"", "."}:
            continue
        if part == "..":
            current = current.parent
            continue
        current /= part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            return SandboxErrorCode.INPUT_SYMLINK, "symbolic-link parent"
        if _is_reparse_point(metadata):
            return SandboxErrorCode.INPUT_REPARSE_POINT, "reparse-point parent"
    return None


def _require_regular_non_link(
    metadata: os.stat_result,
    *,
    link_code: SandboxErrorCode,
    reparse_code: SandboxErrorCode,
    regular_code: SandboxErrorCode,
    subject: str,
) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        raise SandboxError(link_code, f"{subject} must not be a symbolic link")
    if _is_reparse_point(metadata):
        raise SandboxError(
            reparse_code,
            f"{subject} must not be a filesystem reparse point",
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise SandboxError(regular_code, f"{subject} must be a regular file")


def _safe_lstat(path: Path, *, changed: bool = False) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        code = SandboxErrorCode.INPUT_CHANGED if changed else SandboxErrorCode.INPUT_NOT_REGULAR
        message = "parser input changed during snapshot" if changed else "cannot stat parser input"
        raise SandboxError(code, message) from exc


def _prepare_snapshot_directory(directory: Path) -> None:
    try:
        directory.mkdir(parents=True, exist_ok=True)
        metadata = directory.lstat()
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            raise SandboxError(
                SandboxErrorCode.SNAPSHOT_FAILED,
                "snapshot directory must not be a link or reparse point",
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise SandboxError(
                SandboxErrorCode.SNAPSHOT_FAILED,
                "snapshot directory is not a directory",
            )
        if os.name != "nt":
            directory.chmod(0o700)
    except SandboxError:
        raise
    except OSError as exc:
        raise SandboxError(
            SandboxErrorCode.SNAPSHOT_FAILED,
            "cannot prepare private snapshot directory",
        ) from exc


def _check_snapshot_space(directory: Path, source_size: int) -> None:
    required = source_size + _FREE_SPACE_RESERVE_BYTES
    try:
        free = shutil.disk_usage(directory).free
    except OSError as exc:
        raise SandboxError(
            SandboxErrorCode.SNAPSHOT_FAILED,
            "cannot determine free space for parser snapshot",
        ) from exc
    if free < required:
        raise SandboxError(
            SandboxErrorCode.INSUFFICIENT_FREE_SPACE,
            f"parser snapshot requires at least {required} free bytes",
        )


def snapshot_input(path: str | Path, directory: Path, max_bytes: int) -> InputSnapshot:
    """Copy a stable, bounded regular file into a private staging directory."""

    _validate_policy_integer("max_bytes", max_bytes, upper=_MAX_INPUT_BYTES)
    started = time.perf_counter()
    supplied_source = Path(path)
    try:
        linked_parent = _first_link_like_parent(supplied_source)
    except OSError as exc:
        raise SandboxError(
            SandboxErrorCode.INPUT_NOT_REGULAR,
            "cannot stat parser input parent",
        ) from exc
    if linked_parent is not None:
        raise SandboxError(
            linked_parent[0],
            f"parser input must not have a {linked_parent[1]}",
        )
    source = Path(os.path.abspath(os.fspath(supplied_source)))
    initial_metadata = _safe_lstat(source)
    _require_regular_non_link(
        initial_metadata,
        link_code=SandboxErrorCode.INPUT_SYMLINK,
        reparse_code=SandboxErrorCode.INPUT_REPARSE_POINT,
        regular_code=SandboxErrorCode.INPUT_NOT_REGULAR,
        subject="parser input",
    )
    initial_identity = SnapshotFileIdentity.from_stat(initial_metadata)
    if initial_identity.size_bytes > max_bytes:
        raise SandboxError(
            SandboxErrorCode.INPUT_TOO_LARGE,
            f"parser input exceeds snapshot limit of {max_bytes} bytes",
        )

    _prepare_snapshot_directory(directory)
    _check_snapshot_space(directory, initial_identity.size_bytes)
    destination = directory / "input"
    source_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    source_flags |= getattr(os, "O_NOFOLLOW", 0)
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )

    source_fd: int | None = None
    destination_fd: int | None = None
    try:
        try:
            source_fd = os.open(source, source_flags)
        except OSError as exc:
            raise SandboxError(
                SandboxErrorCode.INPUT_CHANGED,
                "cannot safely open parser input",
            ) from exc
        opened_metadata = os.fstat(source_fd)
        _require_regular_non_link(
            opened_metadata,
            link_code=SandboxErrorCode.INPUT_SYMLINK,
            reparse_code=SandboxErrorCode.INPUT_REPARSE_POINT,
            regular_code=SandboxErrorCode.INPUT_NOT_REGULAR,
            subject="opened parser input",
        )
        opened_identity = SnapshotFileIdentity.from_stat(opened_metadata)
        if opened_identity != initial_identity:
            raise SandboxError(
                SandboxErrorCode.INPUT_CHANGED,
                "parser input identity changed before snapshot copy",
            )

        try:
            destination_fd = os.open(destination, destination_flags, 0o600)
        except OSError as exc:
            raise SandboxError(
                SandboxErrorCode.SNAPSHOT_FAILED,
                "cannot create parser input snapshot",
            ) from exc

        digest = hashlib.sha256()
        copied = 0
        with (
            os.fdopen(source_fd, "rb", closefd=True) as source_handle,
            os.fdopen(destination_fd, "wb", closefd=True) as destination_handle,
        ):
            source_fd = None
            destination_fd = None
            remaining = opened_identity.size_bytes
            while remaining:
                chunk = source_handle.read(min(_COPY_CHUNK_BYTES, remaining))
                if not chunk:
                    raise SandboxError(
                        SandboxErrorCode.INPUT_CHANGED,
                        "parser input became shorter during snapshot copy",
                    )
                copied += len(chunk)
                remaining -= len(chunk)
                destination_handle.write(chunk)
                digest.update(chunk)
            if source_handle.read(1):
                raise SandboxError(
                    SandboxErrorCode.INPUT_CHANGED,
                    "parser input grew during snapshot copy",
                )
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
            final_opened_identity = SnapshotFileIdentity.from_stat(os.fstat(source_handle.fileno()))

        if final_opened_identity != opened_identity or copied != opened_identity.size_bytes:
            raise SandboxError(
                SandboxErrorCode.INPUT_CHANGED,
                "parser input changed while its snapshot was copied",
            )
        final_source_metadata = _safe_lstat(source, changed=True)
        try:
            final_linked_parent = _first_link_like_parent(supplied_source)
        except OSError as exc:
            raise SandboxError(
                SandboxErrorCode.INPUT_CHANGED,
                "cannot re-stat parser input parent after snapshot",
            ) from exc
        if final_linked_parent is not None:
            raise SandboxError(
                SandboxErrorCode.INPUT_CHANGED,
                "parser input parent changed while its snapshot was copied",
            )
        _require_regular_non_link(
            final_source_metadata,
            link_code=SandboxErrorCode.INPUT_CHANGED,
            reparse_code=SandboxErrorCode.INPUT_CHANGED,
            regular_code=SandboxErrorCode.INPUT_CHANGED,
            subject="parser input after snapshot",
        )
        if SnapshotFileIdentity.from_stat(final_source_metadata) != initial_identity:
            raise SandboxError(
                SandboxErrorCode.INPUT_CHANGED,
                "parser input identity changed while its snapshot was copied",
            )

        if os.name != "nt":
            destination.chmod(0o400)
        snapshot_metadata = destination.lstat()
        _require_regular_non_link(
            snapshot_metadata,
            link_code=SandboxErrorCode.INPUT_SNAPSHOT_CHANGED,
            reparse_code=SandboxErrorCode.INPUT_SNAPSHOT_CHANGED,
            regular_code=SandboxErrorCode.INPUT_SNAPSHOT_CHANGED,
            subject="parser input snapshot",
        )
        snapshot_identity = SnapshotFileIdentity.from_stat(snapshot_metadata)
        if snapshot_identity.size_bytes != copied:
            raise SandboxError(
                SandboxErrorCode.INPUT_SNAPSHOT_CHANGED,
                "parser input snapshot size changed after creation",
            )
        return InputSnapshot(
            path=destination,
            size_bytes=copied,
            sha256=digest.hexdigest(),
            source_identity=initial_identity,
            snapshot_identity=snapshot_identity,
            duration_seconds=time.perf_counter() - started,
        )
    except SandboxError:
        _unlink_quietly(destination)
        raise
    except OSError as exc:
        _unlink_quietly(destination)
        raise SandboxError(
            SandboxErrorCode.SNAPSHOT_FAILED,
            "parser input snapshot could not be completed",
        ) from exc
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)


def _unlink_quietly(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.unlink(missing_ok=True)


def _verify_snapshot(snapshot: InputSnapshot) -> None:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_descriptor: int | None = None
    try:
        metadata = snapshot.path.lstat()
        _require_regular_non_link(
            metadata,
            link_code=SandboxErrorCode.INPUT_SNAPSHOT_CHANGED,
            reparse_code=SandboxErrorCode.INPUT_SNAPSHOT_CHANGED,
            regular_code=SandboxErrorCode.INPUT_SNAPSHOT_CHANGED,
            subject="parser input snapshot",
        )
        if SnapshotFileIdentity.from_stat(metadata) != snapshot.snapshot_identity:
            raise SandboxError(
                SandboxErrorCode.INPUT_SNAPSHOT_CHANGED,
                "parser input snapshot identity changed during worker execution",
            )
        file_descriptor = os.open(snapshot.path, flags)
        opened_identity = SnapshotFileIdentity.from_stat(os.fstat(file_descriptor))
        if opened_identity != snapshot.snapshot_identity:
            raise SandboxError(
                SandboxErrorCode.INPUT_SNAPSHOT_CHANGED,
                "opened parser snapshot identity does not match staged input",
            )
        digest = hashlib.sha256()
        observed = 0
        with os.fdopen(file_descriptor, "rb", closefd=True) as handle:
            file_descriptor = None
            remaining = snapshot.size_bytes
            while remaining:
                chunk = handle.read(min(_COPY_CHUNK_BYTES, remaining))
                if not chunk:
                    raise SandboxError(
                        SandboxErrorCode.INPUT_SNAPSHOT_CHANGED,
                        "parser input snapshot became shorter during verification",
                    )
                observed += len(chunk)
                remaining -= len(chunk)
                digest.update(chunk)
            if handle.read(1):
                raise SandboxError(
                    SandboxErrorCode.INPUT_SNAPSHOT_CHANGED,
                    "parser input snapshot grew during worker execution",
                )
            final_opened_identity = SnapshotFileIdentity.from_stat(os.fstat(handle.fileno()))
        final_path_identity = SnapshotFileIdentity.from_stat(snapshot.path.lstat())
    except SandboxError:
        raise
    except OSError as exc:
        raise SandboxError(
            SandboxErrorCode.INPUT_SNAPSHOT_CHANGED,
            "parser input snapshot could not be verified after worker execution",
        ) from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)

    if (
        observed != snapshot.size_bytes
        or digest.hexdigest() != snapshot.sha256
        or final_opened_identity != snapshot.snapshot_identity
        or final_path_identity != snapshot.snapshot_identity
    ):
        raise SandboxError(
            SandboxErrorCode.INPUT_SNAPSHOT_CHANGED,
            "parser input snapshot changed during worker execution",
        )


def _posix_resource_capabilities() -> tuple[bool, tuple[str, ...], str]:
    if os.name == "nt":
        return False, (), "Windows process workers have no POSIX resource limits"
    get_effective_uid = getattr(os, "geteuid", None)
    if callable(get_effective_uid) and get_effective_uid() == 0:
        return (
            False,
            (),
            "a privileged process worker can override POSIX resource limits and is reported "
            "only as process separation",
        )
    try:
        import resource
    except ImportError:
        return False, (), "Python resource limits are unavailable on this host"

    required = {
        "RLIMIT_CPU": "posix_rlimit_cpu",
        "RLIMIT_AS": "posix_rlimit_address_space",
        "RLIMIT_NOFILE": "posix_rlimit_open_files",
        "RLIMIT_NPROC": "posix_rlimit_nproc_uid_scoped",
        "RLIMIT_FSIZE": "posix_rlimit_file_size",
    }
    missing = tuple(name for name in required if not hasattr(resource, name))
    capabilities = tuple(value for name, value in required.items() if hasattr(resource, name))
    if hasattr(resource, "RLIMIT_CORE"):
        capabilities = (*capabilities, "posix_rlimit_core_best_effort")
    if missing:
        return False, capabilities, f"missing POSIX resource limits: {', '.join(missing)}"
    return (
        True,
        capabilities,
        "all required POSIX resource-limit constants are present; RLIMIT_NPROC is "
        "real-UID scoped and RLIMIT_CORE suppression is best effort",
    )


def _windows_job_capabilities() -> tuple[bool, tuple[str, ...], str]:
    if os.name != "nt":
        return False, (), "Windows Job Objects apply only on Windows"
    try:
        from .windows_job import available
    except (ImportError, OSError):
        return False, (), "Windows Job Object APIs are unavailable"
    if not available():
        return False, (), "Windows Job Object APIs are unavailable"
    return (
        True,
        (
            "windows_job_kill_on_close",
            "windows_job_process_tree",
            "windows_job_cpu_time",
            "windows_job_memory",
            "windows_job_process_count",
        ),
        "Windows Job Object resource and descendant limits are available",
    )


class _BoundedPipeReader:
    """Drain one child pipe without retaining more than limit plus one byte."""

    def __init__(self, stream: BinaryIO, limit: int, *, label: str) -> None:
        self._stream = stream
        self._limit = limit
        self._payload = bytearray()
        self._stop = threading.Event()
        self._finished = threading.Event()
        self.data_received = threading.Event()
        self.exceeded = threading.Event()
        self.failed = threading.Event()
        self.error: BaseException | None = None
        self._thread = threading.Thread(
            target=self._read,
            name=f"polymorph-{label}-reader",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def request_stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float) -> bool:
        if self._thread.ident is None:
            with contextlib.suppress(OSError):
                self._stream.close()
            self._finished.set()
            return True
        self._thread.join(timeout=max(0.0, timeout))
        return not self._thread.is_alive()

    @property
    def payload(self) -> bytes:
        if not self._finished.is_set():
            raise RuntimeError("pipe reader payload requested before reader finished")
        return bytes(self._payload)

    def _read(self) -> None:
        try:
            descriptor = self._stream.fileno()
            while not self._stop.is_set():
                available = _pipe_available(descriptor)
                if available is None:
                    break
                if available == 0:
                    self._stop.wait(0.01)
                    continue
                remaining = self._limit + 1 - len(self._payload)
                if remaining <= 0:
                    self.exceeded.set()
                    break
                chunk = os.read(descriptor, min(_COPY_CHUNK_BYTES, available, remaining))
                if not chunk:
                    break
                self._payload.extend(chunk)
                self.data_received.set()
                if len(self._payload) > self._limit:
                    self.exceeded.set()
                    break
        except BaseException as exc:
            if not self._stop.is_set():
                self.error = exc
                self.failed.set()
        finally:
            with contextlib.suppress(OSError):
                self._stream.close()
            self._finished.set()


def _pipe_available(descriptor: int) -> int | None:
    if os.name == "nt":
        return _windows_pipe_available(descriptor)
    try:
        readable, _, _ = select.select([descriptor], [], [], 0.05)
    except (OSError, ValueError) as exc:
        raise OSError("could not poll parser worker pipe") from exc
    return _COPY_CHUNK_BYTES if readable else 0


def _windows_pipe_available(descriptor: int) -> int | None:
    import ctypes
    import msvcrt

    handle = msvcrt.get_osfhandle(descriptor)
    available = ctypes.c_ulong()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    succeeded = kernel32.PeekNamedPipe(
        ctypes.c_void_p(handle),
        None,
        0,
        None,
        ctypes.byref(available),
        None,
    )
    if succeeded:
        return int(available.value)
    error = ctypes.get_last_error()
    if error in {109, 232}:
        return None
    raise OSError(error, "could not poll parser worker pipe")


def _finish_pipe_readers(
    readers: tuple[_BoundedPipeReader, _BoundedPipeReader],
    *,
    allow_drain: bool,
) -> tuple[bytes, bytes]:
    if allow_drain:
        drain_deadline = time.monotonic() + 1.0
        for reader in readers:
            reader.join(max(0.0, drain_deadline - time.monotonic()))
    for reader in readers:
        reader.request_stop()
    stop_deadline = time.monotonic() + 1.0
    stopped = True
    for reader in readers:
        if not reader.join(max(0.0, stop_deadline - time.monotonic())):
            stopped = False
    if not stopped:
        raise SandboxError(
            SandboxErrorCode.WORKER_IO_FAILED,
            "parser worker pipe reader did not stop within its deadline",
        )
    return readers[0].payload, readers[1].payload


class _ObservedMemoryInfo(Protocol):
    rss: int


class _ObservedCpuTimes(Protocol):
    user: float
    system: float


class _ObservedIoCounters(Protocol):
    read_bytes: int
    write_bytes: int


class _ObservedProcess(Protocol):
    def children(self, *, recursive: bool = False) -> list[_ObservedProcess]: ...

    def memory_info(self) -> _ObservedMemoryInfo: ...

    def cpu_times(self) -> _ObservedCpuTimes: ...

    def io_counters(self) -> _ObservedIoCounters: ...


class _PsutilModule(Protocol):
    Process: Callable[[int], _ObservedProcess]


class _ChildResourceObserver:
    """Best-effort sampler used only by the explicit parser-worker benchmark."""

    def __init__(self, process_id: int, *, enabled: bool) -> None:
        self._process: _ObservedProcess | None = None
        self.measurement = "disabled"
        self.sample_count = 0
        self.peak_rss_bytes: int | None = None
        self.cpu_seconds: float | None = None
        self.read_bytes: int | None = None
        self.write_bytes: int | None = None
        if not enabled:
            return
        try:
            psutil = cast(_PsutilModule, importlib.import_module("psutil"))
            self._process = psutil.Process(process_id)
        except (ImportError, OSError, RuntimeError, ValueError):
            self.measurement = "unavailable"
            return
        except Exception:
            self.measurement = "unavailable"
            return
        self.measurement = "sampled_process_tree"

    def sample(self) -> None:
        process = self._process
        if process is None:
            return
        try:
            processes = [process, *process.children(recursive=True)]
        except Exception:
            processes = [process]

        rss_total = 0
        cpu_total = 0.0
        read_total = 0
        write_total = 0
        memory_observed = False
        cpu_observed = False
        io_observed = False
        for observed in processes:
            try:
                rss_total += max(0, int(observed.memory_info().rss))
                memory_observed = True
            except Exception:
                pass
            try:
                cpu = observed.cpu_times()
                cpu_total += max(0.0, float(cpu.user)) + max(0.0, float(cpu.system))
                cpu_observed = True
            except Exception:
                pass
            try:
                counters = observed.io_counters()
                read_total += max(0, int(counters.read_bytes))
                write_total += max(0, int(counters.write_bytes))
                io_observed = True
            except Exception:
                pass

        if not (memory_observed or cpu_observed or io_observed):
            return
        self.sample_count += 1
        if memory_observed and (self.peak_rss_bytes is None or rss_total > self.peak_rss_bytes):
            self.peak_rss_bytes = rss_total
        if cpu_observed and (self.cpu_seconds is None or cpu_total > self.cpu_seconds):
            self.cpu_seconds = cpu_total
        if io_observed:
            if self.read_bytes is None or read_total > self.read_bytes:
                self.read_bytes = read_total
            if self.write_bytes is None or write_total > self.write_bytes:
                self.write_bytes = write_total


def _run_bounded_bubblewrap_query(binary: str, argument: str) -> bytes | None:
    process: subprocess.Popen[bytes] | None = None
    readers: tuple[_BoundedPipeReader, _BoundedPipeReader] | None = None
    try:
        try:
            process = subprocess.Popen(
                [binary, argument],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                close_fds=True,
                env={"LC_ALL": "C"},
                start_new_session=True,
            )
        except (OSError, ValueError):
            return None
        if process.stdout is None or process.stderr is None:
            return None
        readers = (
            _BoundedPipeReader(
                cast(BinaryIO, process.stdout),
                _BWRAP_PROBE_MAX_BYTES,
                label="bwrap-probe-stdout",
            ),
            _BoundedPipeReader(
                cast(BinaryIO, process.stderr),
                _BWRAP_PROBE_MAX_BYTES,
                label="bwrap-probe-stderr",
            ),
        )
        for reader in readers:
            reader.start()

        deadline = time.monotonic() + _BWRAP_PROBE_TIMEOUT_SECONDS
        while process.poll() is None:
            if (
                time.monotonic() >= deadline
                or any(reader.exceeded.is_set() for reader in readers)
                or any(reader.failed.is_set() for reader in readers)
            ):
                _WorkerRunner._terminate(process)
                return None
            time.sleep(0.01)
        try:
            exit_code = process.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            return None
        _WorkerRunner._terminate(process)
        stdout, stderr = _finish_pipe_readers(readers, allow_drain=True)
        if (
            exit_code != 0
            or stderr
            or any(reader.exceeded.is_set() or reader.failed.is_set() for reader in readers)
        ):
            return None
        return stdout
    except (OSError, RuntimeError, SandboxError):
        return None
    finally:
        if process is not None:
            _WorkerRunner._terminate(process)
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                process.wait(timeout=1.0)
        if readers is not None:
            with contextlib.suppress(SandboxError):
                _finish_pipe_readers(readers, allow_drain=False)


def _assess_bubblewrap_compatibility(
    version_payload: bytes,
    help_payload: bytes,
) -> tuple[bool, str]:
    try:
        version_text = version_payload.decode("ascii")
        help_text = help_payload.decode("ascii")
    except UnicodeDecodeError:
        return False, "Bubblewrap returned invalid compatibility metadata"
    match = _BWRAP_VERSION_PATTERN.search(version_text)
    if match is None:
        return False, "Bubblewrap version could not be determined"
    version = tuple(int(component) for component in match.groups())
    display_version = ".".join(str(component) for component in version)
    minimum = ".".join(str(component) for component in _BWRAP_MIN_VERSION)
    if version < _BWRAP_MIN_VERSION:
        return (
            False,
            f"Bubblewrap {display_version} is too old; parser isolation security floor is "
            f">= {minimum}",
        )
    for option in _BWRAP_REQUIRED_OPTIONS:
        if option not in help_text:
            return False, f"Bubblewrap {display_version} does not expose required option {option}"
    return True, f"Bubblewrap {display_version} exposes all required isolation options"


def _probe_bubblewrap_compatibility(binary: str) -> tuple[bool, str]:
    version_payload = _run_bounded_bubblewrap_query(binary, "--version")
    if version_payload is None:
        return False, "Bubblewrap version query failed or exceeded its safety bounds"
    help_payload = _run_bounded_bubblewrap_query(binary, "--help")
    if help_payload is None:
        return False, "Bubblewrap feature query failed or exceeded its safety bounds"
    return _assess_bubblewrap_compatibility(version_payload, help_payload)


class _WorkerRunner:
    def __init__(self, policy: SandboxPolicy, *, observe_resources: bool = False) -> None:
        self.policy = policy
        self.observe_resources = observe_resources

    @property
    def info(self) -> SandboxBackendInfo:
        raise NotImplementedError

    def command(self, snapshot: InputSnapshot, package_directory: Path) -> list[str]:
        raise NotImplementedError

    def run(
        self,
        snapshot: InputSnapshot,
        package_directory: Path,
        request: bytes,
    ) -> SandboxRunResult:
        if len(request) > _MAX_REQUEST_BYTES:
            raise SandboxError(
                SandboxErrorCode.PROTOCOL_ERROR,
                "parser worker request exceeds protocol size limit",
            )
        info = self.info
        if not info.available:
            raise SandboxError(SandboxErrorCode.BACKEND_UNAVAILABLE, info.reason)
        if info.level < self.policy.minimum_level:
            raise SandboxError(
                SandboxErrorCode.CONTAINMENT_TOO_WEAK,
                f"backend {info.name} provides {info.level.name}, policy requires "
                f"{self.policy.minimum_level.name}",
            )

        command = self.command(snapshot, package_directory)
        started = time.perf_counter()
        process: subprocess.Popen[bytes] | None = None
        readers: tuple[_BoundedPipeReader, _BoundedPipeReader] | None = None
        resource_observer: _ChildResourceObserver | None = None
        try:
            with _open_private_request(request) as request_handle:
                creation_flags = 0
                start_new_session = os.name != "nt"
                if os.name == "nt":
                    creation_flags = int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
                try:
                    process = subprocess.Popen(
                        command,
                        stdin=request_handle,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        bufsize=0,
                        close_fds=True,
                        cwd=str(snapshot.path.parent),
                        env=self._environment(),
                        start_new_session=start_new_session,
                        creationflags=creation_flags,
                    )
                except (OSError, ValueError) as exc:
                    raise SandboxError(
                        SandboxErrorCode.WORKER_START_FAILED,
                        f"could not start parser worker backend {info.name}",
                    ) from exc

                resource_observer = _ChildResourceObserver(
                    process.pid,
                    enabled=self.observe_resources,
                )
                resource_observer.sample()

                if process.stdout is None or process.stderr is None:
                    raise SandboxError(
                        SandboxErrorCode.WORKER_IO_FAILED,
                        "parser worker pipes were not created",
                    )
                readers = (
                    _BoundedPipeReader(
                        cast(BinaryIO, process.stdout),
                        self.policy.max_stdout_bytes,
                        label="stdout",
                    ),
                    _BoundedPipeReader(
                        cast(BinaryIO, process.stderr),
                        self.policy.max_stderr_bytes,
                        label="stderr",
                    ),
                )
                try:
                    for reader in readers:
                        reader.start()
                except RuntimeError as exc:
                    raise SandboxError(
                        SandboxErrorCode.WORKER_IO_FAILED,
                        "parser worker pipe readers could not start",
                    ) from exc

                deadline = started + float(self.policy.wall_timeout_seconds)
                limit_hit: SandboxErrorCode | None = None
                reader_failed = False
                stderr_contaminated = False
                while process.poll() is None:
                    resource_observer.sample()
                    if time.perf_counter() >= deadline:
                        limit_hit = SandboxErrorCode.WORKER_TIMEOUT
                        self._terminate(process)
                        break
                    if any(reader.exceeded.is_set() for reader in readers):
                        limit_hit = SandboxErrorCode.WORKER_OUTPUT_LIMIT
                        self._terminate(process)
                        break
                    if any(reader.failed.is_set() for reader in readers):
                        reader_failed = True
                        self._terminate(process)
                        break
                    if readers[1].data_received.is_set():
                        stderr_contaminated = True
                        self._terminate(process)
                        break
                    time.sleep(
                        _RESOURCE_SAMPLE_INTERVAL_SECONDS if self.observe_resources else 0.01
                    )

                resource_observer.sample()
                exit_code = self._wait_after_run(process)
                self._terminate(process)
                stdout, stderr = _finish_pipe_readers(
                    readers,
                    allow_drain=(
                        limit_hit is None and not reader_failed and not stderr_contaminated
                    ),
                )
                stderr_digest = hashlib.sha256(stderr).hexdigest()
                if any(reader.exceeded.is_set() for reader in readers):
                    limit_hit = SandboxErrorCode.WORKER_OUTPUT_LIMIT
                if any(reader.failed.is_set() for reader in readers):
                    reader_failed = True

                if limit_hit is SandboxErrorCode.WORKER_TIMEOUT:
                    raise SandboxError(
                        SandboxErrorCode.WORKER_TIMEOUT,
                        "parser worker exceeded its wall-clock timeout",
                        stderr_digest=stderr_digest,
                    )
                if limit_hit is SandboxErrorCode.WORKER_OUTPUT_LIMIT:
                    raise SandboxError(
                        SandboxErrorCode.WORKER_OUTPUT_LIMIT,
                        "parser worker exceeded its stdout or stderr limit",
                        stderr_digest=stderr_digest,
                    )
                if reader_failed:
                    raise SandboxError(
                        SandboxErrorCode.WORKER_IO_FAILED,
                        "parser worker pipe reader failed",
                        stderr_digest=stderr_digest,
                    )
                if exit_code != 0:
                    raise SandboxError(
                        SandboxErrorCode.WORKER_FAILED,
                        f"parser worker exited with status {exit_code}",
                        stderr_digest=stderr_digest,
                    )
                if stderr:
                    raise SandboxError(
                        SandboxErrorCode.WORKER_FAILED,
                        "parser worker wrote unexpected stderr output",
                        stderr_digest=stderr_digest,
                    )
                return SandboxRunResult(
                    backend=info.name,
                    isolation_level=info.level,
                    backend_capabilities=info.capabilities,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr_digest=stderr_digest,
                    duration_seconds=time.perf_counter() - started,
                    stdout_bytes=len(stdout),
                    stderr_bytes=len(stderr),
                    resource_measurement=resource_observer.measurement,
                    resource_sample_count=resource_observer.sample_count,
                    child_peak_rss_bytes=resource_observer.peak_rss_bytes,
                    child_cpu_seconds=resource_observer.cpu_seconds,
                    child_read_bytes=resource_observer.read_bytes,
                    child_write_bytes=resource_observer.write_bytes,
                )
        finally:
            if process is not None:
                self._terminate_and_reap(process)
            if readers is not None:
                with contextlib.suppress(SandboxError):
                    _finish_pipe_readers(readers, allow_drain=False)

    @staticmethod
    def _environment() -> dict[str, str]:
        environment = {
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
        }
        if os.name == "nt":
            system_root = os.environ.get("SYSTEMROOT")
            if system_root:
                environment["SYSTEMROOT"] = system_root
            command_processor = os.environ.get("COMSPEC")
            if command_processor:
                environment["COMSPEC"] = command_processor
        return environment

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        if os.name == "nt":
            if process.poll() is not None:
                return
            _windows_taskkill_tree(process.pid)
        if os.name != "nt":
            kill_process_group = cast(
                Callable[[int, int], None] | None,
                getattr(os, "killpg", None),
            )
            kill_signal = int(getattr(signal, "SIGKILL", signal.SIGTERM))
            try:
                if kill_process_group is not None:
                    kill_process_group(process.pid, kill_signal)
                    return
            except ProcessLookupError:
                return
            except OSError:
                pass
        if process.poll() is not None:
            return
        with contextlib.suppress(OSError):
            process.kill()

    def _wait_after_run(self, process: subprocess.Popen[bytes]) -> int:
        try:
            return process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            self._terminate(process)
            try:
                return process.wait(timeout=2.0)
            except subprocess.TimeoutExpired as second_exc:
                raise SandboxError(
                    SandboxErrorCode.WORKER_TERMINATION_FAILED,
                    "parser worker did not terminate after forced shutdown",
                ) from second_exc
            except OSError as second_exc:
                raise SandboxError(
                    SandboxErrorCode.WORKER_TERMINATION_FAILED,
                    "parser worker could not be reaped after forced shutdown",
                ) from second_exc
        except OSError as exc:
            raise SandboxError(
                SandboxErrorCode.WORKER_TERMINATION_FAILED,
                "parser worker could not be reaped",
            ) from exc

    def _terminate_and_reap(self, process: subprocess.Popen[bytes]) -> None:
        self._terminate(process)
        try:
            process.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            self._terminate(process)


def _windows_taskkill_tree(process_id: int) -> None:
    """Attempt tree termination without advertising it as a containment guarantee."""

    system_root = os.environ.get("SYSTEMROOT")
    if not system_root:
        return
    taskkill = Path(system_root) / "System32" / "taskkill.exe"
    if not taskkill.is_absolute() or not taskkill.is_file():
        return
    creation_flags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    with contextlib.suppress(OSError, subprocess.TimeoutExpired):
        subprocess.run(
            [str(taskkill), "/PID", str(process_id), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=1.0,
            creationflags=creation_flags,
        )


class ProcessWorkerRunner(_WorkerRunner):
    """Separate local process without filesystem or network isolation."""

    @property
    def info(self) -> SandboxBackendInfo:
        base = (
            "separate_process",
            "parent_wall_timeout",
            "bounded_parent_capture",
        )
        supported, resource_capabilities, reason = _posix_resource_capabilities()
        if supported:
            return SandboxBackendInfo(
                name="process",
                level=IsolationLevel.RESOURCE_LIMITED_PROCESS,
                available=True,
                capabilities=(*base, "posix_process_group_termination", *resource_capabilities),
                reason=reason,
            )
        windows_supported, windows_capabilities, windows_reason = _windows_job_capabilities()
        if windows_supported:
            return SandboxBackendInfo(
                name="process",
                level=IsolationLevel.RESOURCE_LIMITED_PROCESS,
                available=True,
                capabilities=(*base, *windows_capabilities),
                reason=windows_reason,
            )
        windows_capability = ("main_process_termination_only",) if os.name == "nt" else ()
        return SandboxBackendInfo(
            name="process",
            level=IsolationLevel.PROCESS,
            available=True,
            capabilities=(*base, *windows_capability, *resource_capabilities),
            reason=reason,
        )

    def command(self, snapshot: InputSnapshot, package_directory: Path) -> list[str]:
        package_parent = package_directory.parent
        if os.name == "nt":
            bootstrap = (
                "import sys;"
                f"sys.path.insert(0,{str(package_parent)!r});"
                "from polymorph.windows_job import run_parser_worker;"
                "raise SystemExit(run_parser_worker("
                f"cpu_seconds={self.policy.cpu_seconds},"
                f"max_memory_bytes={self.policy.max_memory_bytes},"
                f"max_processes={self.policy.max_processes}))"
            )
        else:
            bootstrap = (
                "import sys;"
                f"sys.path.insert(0,{str(package_parent)!r});"
                "from polymorph.parser_worker import main;"
                "raise SystemExit(main())"
            )
        return [
            sys.executable,
            "-I",
            "-c",
            bootstrap,
            "--input",
            str(snapshot.path),
        ]


class BubblewrapWorkerRunner(_WorkerRunner):
    """Linux namespace sandbox launched through a discovered Bubblewrap binary."""

    def __init__(
        self,
        policy: SandboxPolicy,
        *,
        binary: str | None = None,
        compatibility_probe: Callable[[str], tuple[bool, str]] | None = None,
        observe_resources: bool = False,
    ) -> None:
        super().__init__(policy, observe_resources=observe_resources)
        discovered = binary if binary is not None else shutil.which("bwrap")
        self._binary_unavailable_reason = "Bubblewrap binary was not found or is not executable"
        try:
            candidate = Path(discovered).resolve() if discovered else None
            candidate_metadata = candidate.stat() if candidate is not None else None
        except (OSError, RuntimeError):
            candidate = None
            candidate_metadata = None
        if candidate_metadata is not None and candidate_metadata.st_mode & (
            stat.S_ISUID | stat.S_ISGID
        ):
            self.binary = None
            self._binary_unavailable_reason = (
                "setuid or setgid Bubblewrap binaries are rejected by parser isolation"
            )
        elif candidate is not None and candidate.is_file() and os.access(candidate, os.X_OK):
            self.binary = str(candidate)
        else:
            self.binary = None
        self._compatibility_probe = compatibility_probe or _probe_bubblewrap_compatibility
        self._compatibility: tuple[bool, str] | None = None

    @property
    def info(self) -> SandboxBackendInfo:
        capabilities = (
            "binary_discovered",
            "unprivileged_non_setid_binary",
            "user_mount_pid_network_namespaces_requested",
            "network_namespace_requested",
            "nested_user_namespaces_disabled",
            "linux_capabilities_dropped",
            "read_only_input",
            "read_only_application",
            "private_tmpfs",
            "bounded_tmpfs",
            "read_only_work_directory",
            "read_only_application_root",
            "read_only_sandbox_root",
            "read_only_dev_mount_with_writable_standard_devices",
            "virtual_environment_relocated_to_private_runtime",
            "parent_wall_timeout",
            "bounded_parent_capture",
        )
        if sys.platform != "linux":
            return SandboxBackendInfo(
                name="bubblewrap",
                level=IsolationLevel.OS_SANDBOX,
                available=False,
                capabilities=(),
                reason="Bubblewrap is supported only on Linux",
            )
        if self.binary is None:
            return SandboxBackendInfo(
                name="bubblewrap",
                level=IsolationLevel.OS_SANDBOX,
                available=False,
                capabilities=(),
                reason=self._binary_unavailable_reason,
            )
        if self._compatibility is None:
            self._compatibility = self._compatibility_probe(self.binary)
        compatible, compatibility_reason = self._compatibility
        if not compatible:
            return SandboxBackendInfo(
                name="bubblewrap",
                level=IsolationLevel.OS_SANDBOX,
                available=False,
                capabilities=("binary_discovered",),
                reason=compatibility_reason,
            )
        return SandboxBackendInfo(
            name="bubblewrap",
            level=IsolationLevel.OS_SANDBOX,
            available=True,
            capabilities=capabilities,
            reason=(
                f"{compatibility_reason}; namespace support is verified only by a successful "
                "worker launch"
            ),
        )

    def command(self, snapshot: InputSnapshot, package_directory: Path) -> list[str]:
        if self.binary is None:
            raise SandboxError(
                SandboxErrorCode.BACKEND_UNAVAILABLE,
                self._binary_unavailable_reason,
            )
        python_path = Path(os.path.abspath(sys.executable))
        if not python_path.is_file():
            raise SandboxError(
                SandboxErrorCode.BACKEND_UNAVAILABLE,
                "Python executable is unavailable at its lexical path",
            )
        runtime_layout = _bubblewrap_runtime_layout(python_path)
        venv_destination = PurePosixPath("/runtime/venv")
        for source, destination in runtime_layout.mounts:
            if not source.is_dir():
                raise SandboxError(
                    SandboxErrorCode.BACKEND_UNAVAILABLE,
                    "A required Python runtime directory is unavailable",
                )
            if destination == venv_destination and not (source / "pyvenv.cfg").is_file():
                raise SandboxError(
                    SandboxErrorCode.BACKEND_UNAVAILABLE,
                    "Python virtual environment is missing pyvenv.cfg",
                )
        command = [
            self.binary,
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--disable-userns",
            "--assert-userns-disabled",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--setenv",
            "PYTHONNOUSERSITE",
            "1",
            "--setenv",
            "PYTHONDONTWRITEBYTECODE",
            "1",
            "--setenv",
            "PYTHONIOENCODING",
            "utf-8",
            "--setenv",
            "HOME",
            "/tmp",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--size",
            str(self.policy.max_tmpfs_bytes),
            "--tmpfs",
            "/tmp",
            "--ro-bind",
            str(snapshot.path.parent),
            "/work",
            "--size",
            str(_APP_ROOT_TMPFS_BYTES),
            "--tmpfs",
            "/app",
            "--ro-bind",
            str(package_directory),
            "/app/polymorph",
            "--size",
            str(_APP_ROOT_TMPFS_BYTES),
            "--tmpfs",
            "/runtime",
        ]

        for source, destination in runtime_layout.mounts:
            command.extend(["--ro-bind", str(source), str(destination)])
        loader_cache = Path("/etc/ld.so.cache")
        if loader_cache.is_file():
            command.extend(["--ro-bind", str(loader_cache), str(loader_cache)])
        command.extend(
            [
                "--remount-ro",
                "/app",
                "--remount-ro",
                "/runtime",
                "--remount-ro",
                "/dev",
                "--remount-ro",
                "/",
            ]
        )

        bootstrap = (
            "import sys;"
            "sys.path.insert(0,'/app');"
            "from polymorph.parser_worker import main;"
            "raise SystemExit(main())"
        )
        command.extend(
            [
                "--chdir",
                "/work",
                str(runtime_layout.executable),
                "-I",
                "-c",
                bootstrap,
                "--input",
                "/work/input",
            ]
        )
        return command


def _runtime_roots(_python_path: Path) -> tuple[Path, ...]:
    candidates = (
        Path("/usr"),
        Path("/usr/local"),
        Path("/lib"),
        Path("/lib64"),
    )
    roots: list[Path] = []
    for candidate in candidates:
        root = Path(os.path.abspath(candidate))
        if root.parent == root or not root.is_dir():
            continue
        if any(root == existing or root.is_relative_to(existing) for existing in roots):
            continue
        roots = [existing for existing in roots if not existing.is_relative_to(root)]
        roots.append(root)
    return tuple(sorted(roots, key=lambda item: (len(item.parts), str(item))))


def _bubblewrap_runtime_layout(
    python_path: Path,
    *,
    prefix: Path | None = None,
    base_prefix: Path | None = None,
    system_roots: tuple[Path, ...] | None = None,
) -> _BubblewrapRuntimeLayout:
    lexical_python = Path(os.path.abspath(python_path))
    lexical_prefix = Path(os.path.abspath(prefix if prefix is not None else sys.prefix))
    lexical_base = Path(
        os.path.abspath(base_prefix if base_prefix is not None else sys.base_prefix)
    )
    roots = _runtime_roots(lexical_python) if system_roots is None else system_roots
    if not roots or any(_is_reserved_sandbox_destination(root) for root in roots):
        raise SandboxError(
            SandboxErrorCode.BACKEND_UNAVAILABLE,
            "Python system runtime has an unsafe Bubblewrap mount destination",
        )

    def covered_by_system(path: Path) -> bool:
        return any(path == root or path.is_relative_to(root) for root in roots)

    mounts = tuple((root, PurePosixPath(root.as_posix())) for root in roots)
    if not covered_by_system(lexical_base):
        base_destination = PurePosixPath(lexical_base.as_posix())
        if (
            lexical_base.parent == lexical_base
            or not base_destination.is_absolute()
            or _is_reserved_sandbox_destination(base_destination)
        ):
            raise SandboxError(
                SandboxErrorCode.BACKEND_UNAVAILABLE,
                "Python base runtime cannot be mounted at a safe sandbox destination",
            )
        mounts = (*mounts, (lexical_base, base_destination))

    runtime_roots = (*roots, lexical_base)

    def covered_by_runtime(path: Path) -> bool:
        return any(path == root or path.is_relative_to(root) for root in runtime_roots)

    if lexical_prefix != lexical_base:
        try:
            relative_executable = lexical_python.relative_to(lexical_prefix)
        except ValueError:
            raise SandboxError(
                SandboxErrorCode.BACKEND_UNAVAILABLE,
                "Python executable is outside its virtual-environment prefix",
            ) from None
        if not relative_executable.parts or lexical_prefix.parent == lexical_prefix:
            raise SandboxError(
                SandboxErrorCode.BACKEND_UNAVAILABLE,
                "Python virtual-environment layout is unsafe for relocation",
            )
        destination = PurePosixPath("/runtime/venv")
        return _BubblewrapRuntimeLayout(
            executable=destination / PurePosixPath(relative_executable.as_posix()),
            mounts=(*mounts, (lexical_prefix, destination)),
        )

    if not covered_by_runtime(lexical_python):
        raise SandboxError(
            SandboxErrorCode.BACKEND_UNAVAILABLE,
            "Python executable is outside mounted runtime roots",
        )
    return _BubblewrapRuntimeLayout(
        executable=PurePosixPath(lexical_python.as_posix()),
        mounts=mounts,
    )


def _is_reserved_sandbox_destination(path: Path | PurePosixPath) -> bool:
    candidate = PurePosixPath(path.as_posix())
    reserved = tuple(
        PurePosixPath(item) for item in ("/app", "/dev", "/proc", "/runtime", "/tmp", "/work")
    )
    return any(candidate == item or candidate.is_relative_to(item) for item in reserved)


def _validate_package_directory(package_root: Path | None) -> Path:
    installed_package = Path(__file__).resolve(strict=True).parent
    candidate = (
        installed_package if package_root is None else Path(package_root).resolve(strict=True)
    )
    if (candidate / "polymorph").is_dir():
        candidate = (candidate / "polymorph").resolve(strict=True)
    if candidate != installed_package:
        raise ValueError("package_root must identify this installed polymorph package")
    if candidate.parent == candidate or candidate.anchor == str(candidate):
        raise ValueError("package_root must not be a filesystem root")
    required = (candidate / "__init__.py", candidate / "parser_worker.py")
    if not all(item.is_file() and not item.is_symlink() for item in required):
        raise ValueError("package_root does not contain the parser worker package")
    return candidate


class ParserWorkerClient:
    """Inspect a stable snapshot behind an explicit parser containment boundary."""

    def __init__(
        self,
        policy: SandboxPolicy | None = None,
        *,
        backend: str = "auto",
        package_root: Path | None = None,
        observe_resources: bool = False,
    ) -> None:
        self.policy = policy or SandboxPolicy()
        if backend not in {"auto", "process", "bubblewrap"}:
            raise ValueError(f"unsupported parser worker backend: {backend}")
        if not isinstance(observe_resources, bool):
            raise TypeError("observe_resources must be a boolean")
        self.backend = backend
        self.observe_resources = observe_resources
        self.package_directory = _validate_package_directory(package_root)
        self._bubblewrap_runner = BubblewrapWorkerRunner(
            self.policy,
            observe_resources=observe_resources,
        )
        self._process_runner = ProcessWorkerRunner(
            self.policy,
            observe_resources=observe_resources,
        )
        self._selected_runner: _WorkerRunner | None = None
        self._runner_lock = threading.Lock()

    def inspect_content(
        self,
        path: str | Path,
        *,
        use_magika: bool = False,
    ) -> IsolatedContentInspection:
        if not isinstance(use_magika, bool):
            raise TypeError("use_magika must be a boolean")
        started = time.perf_counter()
        runner = self._runner()
        request_id = secrets.token_hex(16)
        with tempfile.TemporaryDirectory(prefix="polymorph-input-snapshot-") as temp_name:
            snapshot = snapshot_input(
                path,
                Path(temp_name),
                self.policy.max_input_bytes,
            )
            request = _encode_request(request_id, snapshot, use_magika, self.policy)
            result = runner.run(snapshot, self.package_directory, request)
            _verify_snapshot(snapshot)
            inspection = _decode_response(result.stdout, request_id, snapshot)
        return IsolatedContentInspection(
            request_id=request_id,
            snapshot_sha256=snapshot.sha256,
            snapshot_size_bytes=snapshot.size_bytes,
            backend=result.backend,
            isolation_level=result.isolation_level,
            backend_capabilities=result.backend_capabilities,
            snapshot_duration_seconds=snapshot.duration_seconds,
            worker_duration_seconds=result.duration_seconds,
            end_to_end_duration_seconds=time.perf_counter() - started,
            stdout_bytes=result.stdout_bytes,
            stderr_bytes=result.stderr_bytes,
            stderr_digest=result.stderr_digest,
            resource_measurement=result.resource_measurement,
            resource_sample_count=result.resource_sample_count,
            child_peak_rss_bytes=result.child_peak_rss_bytes,
            child_cpu_seconds=result.child_cpu_seconds,
            child_read_bytes=result.child_read_bytes,
            child_write_bytes=result.child_write_bytes,
            inspection=inspection,
        )

    def backend_info(self) -> tuple[SandboxBackendInfo, ...]:
        return (
            self._bubblewrap_runner.info,
            self._process_runner.info,
        )

    def _runner(self) -> _WorkerRunner:
        if self._selected_runner is not None:
            return self._selected_runner
        with self._runner_lock:
            if self._selected_runner is not None:
                return self._selected_runner
            if self.backend == "bubblewrap":
                selected: _WorkerRunner = self._bubblewrap_runner
            elif self.backend == "process":
                selected = self._process_runner
            else:
                sandbox = self._bubblewrap_runner
                process = self._process_runner
                if sandbox.info.available:
                    selected = sandbox
                elif process.info.level >= self.policy.minimum_level:
                    selected = process
                else:
                    available = ", ".join(
                        f"{item.name}={item.level.name if item.available else 'unavailable'}"
                        for item in (sandbox.info, process.info)
                    )
                    raise SandboxError(
                        SandboxErrorCode.CONTAINMENT_TOO_WEAK,
                        f"no backend satisfies {self.policy.minimum_level.name}; {available}",
                    )

            info = selected.info
            if not info.available:
                raise SandboxError(SandboxErrorCode.BACKEND_UNAVAILABLE, info.reason)
            if info.level < self.policy.minimum_level:
                raise SandboxError(
                    SandboxErrorCode.CONTAINMENT_TOO_WEAK,
                    f"backend {info.name} provides {info.level.name}, policy requires "
                    f"{self.policy.minimum_level.name}",
                )
            self._selected_runner = selected
            return selected


def _encode_request(
    request_id: str,
    snapshot: InputSnapshot,
    use_magika: bool,
    policy: SandboxPolicy,
) -> bytes:
    request = {
        "protocol": _PROTOCOL,
        "version": _PROTOCOL_VERSION,
        "request_id": request_id,
        "operation": "inspect_content",
        "input": {"sha256": snapshot.sha256, "size_bytes": snapshot.size_bytes},
        "options": {"use_magika": use_magika},
        "limits": {
            "cpu_seconds": policy.cpu_seconds,
            "max_memory_bytes": policy.max_memory_bytes,
            "max_open_files": policy.max_open_files,
            "max_processes": policy.max_processes,
            "max_output_file_bytes": policy.max_output_file_bytes,
            "max_parser_log_bytes": policy.max_parser_log_bytes,
        },
    }
    try:
        encoded = json.dumps(
            request,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            "parser worker request could not be encoded",
        ) from exc
    if len(encoded) > _MAX_REQUEST_BYTES:
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            "parser worker request exceeds protocol size limit",
        )
    return encoded


class _DuplicateJsonKey(ValueError):
    pass


def _reject_duplicate_pairs(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise _DuplicateJsonKey(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def _reject_nonfinite_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _decode_response(
    payload: bytes,
    expected_request_id: str,
    snapshot: InputSnapshot,
) -> dict[str, object]:
    if len(payload) > _MAX_RESPONSE_BYTES:
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            "parser worker response exceeds protocol size limit",
        )
    try:
        decoded = payload.decode("utf-8")
        value = cast(
            object,
            json.loads(
                decoded,
                object_pairs_hook=_reject_duplicate_pairs,
                parse_constant=_reject_nonfinite_constant,
            ),
        )
        _validate_json_shape(value)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        RecursionError,
        ValueError,
    ):
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            "parser worker produced invalid JSON",
        ) from None
    response = _require_object(value, "response")
    ok = _require_bool(response.get("ok"), "response.ok")
    expected_keys = (
        {"protocol", "version", "request_id", "ok", "input", "inspection"}
        if ok
        else {"protocol", "version", "request_id", "ok", "error_code", "message"}
    )
    _require_exact_keys(response, expected_keys, "response")
    if _require_text(response["protocol"], "response.protocol", _MAX_SHORT_TEXT_BYTES) != _PROTOCOL:
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            "parser worker protocol mismatch",
        )
    version = _require_integer(response["version"], "response.version")
    if version != _PROTOCOL_VERSION:
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            "parser worker protocol version mismatch",
        )
    request_id = _require_text(
        response["request_id"],
        "response.request_id",
        _MAX_SHORT_TEXT_BYTES,
    )
    if request_id != expected_request_id:
        raise SandboxError(
            SandboxErrorCode.REQUEST_MISMATCH,
            "parser worker response request id does not match",
        )

    if not ok:
        error_code = _require_worker_error_code(response["error_code"])
        _require_text(response["message"], "response.message", _MAX_TEXT_BYTES)
        raise SandboxError(
            SandboxErrorCode.WORKER_FAILED,
            f"parser worker rejected input ({error_code})",
            worker_error_code=error_code,
        )

    response_input = _require_object(response["input"], "response.input")
    _require_exact_keys(response_input, {"sha256", "size_bytes"}, "response.input")
    reported_digest = _require_sha256(response_input["sha256"], "response.input.sha256")
    reported_size = _require_integer(response_input["size_bytes"], "response.input.size_bytes")
    if reported_digest != snapshot.sha256 or reported_size != snapshot.size_bytes:
        raise SandboxError(
            SandboxErrorCode.REQUEST_MISMATCH,
            "parser worker response is not bound to the input snapshot",
        )
    return _validate_inspection(response["inspection"], snapshot)


def _validate_json_shape(value: object) -> None:
    nodes = 0

    def visit(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise ValueError("JSON value has too many nodes")
        if depth > _MAX_JSON_DEPTH:
            raise ValueError("JSON value is nested too deeply")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("JSON object key must be text")
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        elif item is None or isinstance(item, (str, bool, int)):
            return
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("JSON contains a non-finite number")
        else:
            raise ValueError("JSON contains an unsupported value")

    visit(value, 0)


def _validate_inspection(value: object, snapshot: InputSnapshot) -> dict[str, object]:
    inspection = _require_object(value, "response.inspection")
    _require_exact_keys(
        inspection,
        {
            "path",
            "size_bytes",
            "kind",
            "confidence",
            "safe",
            "signals",
            "risks",
            "classifier",
        },
        "response.inspection",
    )
    path = _require_text(inspection["path"], "inspection.path", _MAX_SHORT_TEXT_BYTES)
    if path != "<snapshot>":
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            "parser worker inspection exposed an unexpected path",
        )
    size = _require_integer(inspection["size_bytes"], "inspection.size_bytes")
    if size != snapshot.size_bytes:
        raise SandboxError(
            SandboxErrorCode.REQUEST_MISMATCH,
            "parser worker inspection size does not match the snapshot",
        )
    kind = _require_text(inspection["kind"], "inspection.kind", _MAX_SHORT_TEXT_BYTES)
    if kind not in _CONTENT_KINDS:
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            "parser worker inspection contains an unknown content kind",
        )
    confidence = _require_probability(inspection["confidence"], "inspection.confidence")
    safe = _require_bool(inspection["safe"], "inspection.safe")
    signals = _validate_text_list(inspection["signals"], "inspection.signals")
    risks = _validate_risks(inspection["risks"])
    classifier = _validate_classifier(inspection["classifier"])
    if safe != (not any(cast(bool, risk["blocking"]) for risk in risks)):
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            "parser worker inspection safety flag contradicts its risks",
        )
    return {
        "path": path,
        "size_bytes": size,
        "kind": kind,
        "confidence": confidence,
        "safe": safe,
        "signals": signals,
        "risks": risks,
        "classifier": classifier,
    }


def _validate_text_list(value: object, subject: str) -> list[str]:
    if not isinstance(value, list) or len(value) > _MAX_INSPECTION_ITEMS:
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            f"{subject} must be a bounded list",
        )
    return [
        _require_text(item, f"{subject}[{index}]", _MAX_TEXT_BYTES)
        for index, item in enumerate(value)
    ]


def _validate_risks(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > _MAX_INSPECTION_ITEMS:
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            "inspection.risks must be a bounded list",
        )
    normalized: list[dict[str, object]] = []
    for index, item in enumerate(value):
        risk = _require_object(item, f"inspection.risks[{index}]")
        _require_exact_keys(
            risk,
            {"code", "detail", "blocking"},
            f"inspection.risks[{index}]",
        )
        code = _require_text(
            risk["code"],
            f"inspection.risks[{index}].code",
            _MAX_SHORT_TEXT_BYTES,
        )
        if code not in _RISK_CODES:
            raise SandboxError(
                SandboxErrorCode.PROTOCOL_ERROR,
                "parser worker inspection contains an unknown risk code",
            )
        normalized.append(
            {
                "code": code,
                "detail": _require_text(
                    risk["detail"],
                    f"inspection.risks[{index}].detail",
                    _MAX_TEXT_BYTES,
                ),
                "blocking": _require_bool(
                    risk["blocking"],
                    f"inspection.risks[{index}].blocking",
                ),
            }
        )
    return normalized


def _validate_classifier(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    classifier = _require_object(value, "inspection.classifier")
    _require_exact_keys(
        classifier,
        {"provider", "label", "mime_type", "score"},
        "inspection.classifier",
    )
    mime_value = classifier["mime_type"]
    score_value = classifier["score"]
    return {
        "provider": _require_text(
            classifier["provider"],
            "inspection.classifier.provider",
            _MAX_SHORT_TEXT_BYTES,
        ),
        "label": _require_text(
            classifier["label"],
            "inspection.classifier.label",
            _MAX_SHORT_TEXT_BYTES,
        ),
        "mime_type": (
            None
            if mime_value is None
            else _require_text(
                mime_value,
                "inspection.classifier.mime_type",
                _MAX_SHORT_TEXT_BYTES,
            )
        ),
        "score": (
            None
            if score_value is None
            else _require_probability(score_value, "inspection.classifier.score")
        ),
    }


def _require_object(value: object, subject: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            f"{subject} must be a JSON object",
        )
    return cast(dict[str, object], value)


def _require_exact_keys(value: dict[str, object], expected: set[str], subject: str) -> None:
    if set(value) != expected:
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            f"{subject} contains missing or unknown fields",
        )


def _require_bool(value: object, subject: str) -> bool:
    if not isinstance(value, bool):
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            f"{subject} must be a boolean",
        )
    return value


def _require_integer(value: object, subject: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            f"{subject} must be an integer",
        )
    if value < 0 or value > _MAX_SIGNED_INTEGER:
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            f"{subject} is outside the supported integer range",
        )
    return value


def _require_probability(value: object, subject: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            f"{subject} must be a finite number",
        )
    try:
        number = float(value)
    except (OverflowError, ValueError):
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            f"{subject} must be a finite number",
        ) from None
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            f"{subject} must be within [0, 1]",
        )
    return number


def _require_text(value: object, subject: str, max_bytes: int) -> str:
    if not isinstance(value, str) or not value:
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            f"{subject} must be non-empty text",
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            f"{subject} contains invalid Unicode",
        ) from None
    unsafe_categories = {"Cc", "Cf", "Cs", "Zl", "Zp"}
    if len(encoded) > max_bytes or any(
        unicodedata.category(char) in unsafe_categories for char in value
    ):
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            f"{subject} contains oversized or unsafe text",
        )
    return value


def _require_worker_error_code(value: object) -> str:
    error_code = _require_text(value, "response.error_code", _MAX_SHORT_TEXT_BYTES)
    if error_code not in _WORKER_ERROR_CODES:
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            "response.error_code is not a recognized stable worker error",
        )
    return error_code


def _require_sha256(value: object, subject: str) -> str:
    digest = _require_text(value, subject, 64)
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise SandboxError(
            SandboxErrorCode.PROTOCOL_ERROR,
            f"{subject} must be a lowercase SHA-256 digest",
        )
    return digest


def _open_private_request(payload: bytes) -> BinaryIO:
    handle: BinaryIO | None = None
    try:
        handle = cast(
            BinaryIO,
            tempfile.TemporaryFile(  # noqa: SIM115 - ownership transfers to the caller
                mode="w+b",
                prefix="polymorph-worker-request-",
            ),
        )
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
        handle.seek(0)
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != len(payload):
            raise OSError("request staging handle is not a bounded regular file")
        return handle
    except OSError as exc:
        if handle is not None:
            with contextlib.suppress(OSError):
                handle.close()
        raise SandboxError(
            SandboxErrorCode.WORKER_IO_FAILED,
            "could not stage parser worker request",
        ) from exc

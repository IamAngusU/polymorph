from __future__ import annotations

import contextlib
import hashlib
import importlib
import io
import json
import os
import re
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Never, Protocol, TextIO, cast

PROTOCOL = "polymorph.parser-worker"
PROTOCOL_VERSION = 1

_MAX_REQUEST_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 256 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
_UNKNOWN_REQUEST_ID = "0" * 32
_REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_REQUEST_FIELDS = frozenset(
    {"protocol", "version", "request_id", "operation", "input", "options", "limits"}
)
_INPUT_FIELDS = frozenset({"sha256", "size_bytes"})
_OPTION_FIELDS = frozenset({"use_magika"})
_LIMIT_FIELDS = frozenset(
    {
        "cpu_seconds",
        "max_memory_bytes",
        "max_open_files",
        "max_processes",
        "max_output_file_bytes",
        "max_parser_log_bytes",
    }
)
_LIMIT_MAXIMUMS = {
    "cpu_seconds": 60 * 60,
    "max_memory_bytes": 64 * 1024 * 1024 * 1024,
    "max_open_files": 65_536,
    "max_processes": 4_096,
    "max_output_file_bytes": 16 * 1024 * 1024 * 1024,
    "max_parser_log_bytes": 16 * 1024 * 1024,
}


class _WorkerFailure(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.request_id: str | None = None


class _ParserLogLimitExceeded(BaseException):
    """Escape parser code that catches ordinary library exceptions."""


@dataclass(frozen=True, slots=True)
class ParserWorkerLimits:
    cpu_seconds: int
    max_memory_bytes: int
    max_open_files: int
    max_processes: int
    max_output_file_bytes: int
    max_parser_log_bytes: int


@dataclass(frozen=True, slots=True)
class ParserWorkerInput:
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class ParserWorkerRequest:
    request_id: str
    operation: str
    input: ParserWorkerInput
    use_magika: bool
    limits: ParserWorkerLimits


@dataclass(frozen=True, slots=True)
class _SnapshotMeasurement:
    sha256: str
    size_bytes: int
    identity: tuple[int, int, int, int]


class _ResourceModule(Protocol):
    RLIM_INFINITY: int

    def getrlimit(self, resource: int) -> tuple[int, int]: ...

    def setrlimit(self, resource: int, limits: tuple[int, int]) -> None: ...


class _FileIdentityLike(Protocol):
    @property
    def device(self) -> int: ...

    @property
    def inode(self) -> int: ...

    @property
    def size_bytes(self) -> int: ...

    @property
    def mtime_ns(self) -> int: ...


class _CountingDiscardSink(io.TextIOBase):
    """Discard parser output without allowing an in-memory log to grow."""

    def __init__(self, maximum_bytes: int) -> None:
        super().__init__()
        self.maximum_bytes = maximum_bytes
        self.bytes_seen = 0

    def writable(self) -> bool:
        return True

    def isatty(self) -> bool:
        return False

    def write(self, value: str, /) -> int:
        if not isinstance(value, str):
            raise TypeError("parser log writes must be text")
        encoded_size = len(value.encode("utf-8", errors="replace"))
        if self.bytes_seen + encoded_size > self.maximum_bytes:
            raise _ParserLogLimitExceeded
        self.bytes_seen += encoded_size
        return len(value)

    def flush(self) -> None:
        return None


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _WorkerFailure(
                "invalid_request_json",
                "The parser worker request is not valid canonical JSON.",
            )
        result[key] = value
    return result


def _reject_nonfinite_constant(_value: str) -> Never:
    raise _WorkerFailure(
        "invalid_request_json",
        "The parser worker request is not valid canonical JSON.",
    )


def _object(value: object, fields: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise _WorkerFailure(
            "invalid_request",
            "The parser worker request has an invalid field set.",
        )
    output: dict[str, object] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise _WorkerFailure(
                "invalid_request",
                "The parser worker request has an invalid field set.",
            )
        output[key] = item
    return output


def _positive_limit(payload: Mapping[str, object], name: str) -> int:
    value = payload.get(name)
    maximum = _LIMIT_MAXIMUMS[name]
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise _WorkerFailure(
            "invalid_request",
            "The parser worker request contains an invalid resource limit.",
        )
    return value


def _request_id_hint(payload: object) -> str:
    if not isinstance(payload, dict):
        return _UNKNOWN_REQUEST_ID
    value = payload.get("request_id")
    return value if isinstance(value, str) and _REQUEST_ID.fullmatch(value) else _UNKNOWN_REQUEST_ID


def _parse_request_payload(payload: object) -> ParserWorkerRequest:
    root = _object(payload, _REQUEST_FIELDS)
    protocol = root["protocol"]
    if protocol != PROTOCOL:
        raise _WorkerFailure(
            "unsupported_protocol",
            "The parser worker protocol is unsupported.",
        )
    version = root["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != PROTOCOL_VERSION:
        raise _WorkerFailure(
            "unsupported_version",
            "The parser worker protocol version is unsupported.",
        )
    request_id = root["request_id"]
    if not isinstance(request_id, str) or not _REQUEST_ID.fullmatch(request_id):
        raise _WorkerFailure(
            "invalid_request",
            "The parser worker request id is invalid.",
        )
    operation = root["operation"]
    if operation != "inspect_content":
        raise _WorkerFailure(
            "unsupported_operation",
            "The parser worker operation is unsupported.",
        )

    input_payload = _object(root["input"], _INPUT_FIELDS)
    expected_sha256 = input_payload["sha256"]
    if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256):
        raise _WorkerFailure(
            "invalid_request",
            "The parser worker input digest is invalid.",
        )
    expected_size = input_payload["size_bytes"]
    if (
        isinstance(expected_size, bool)
        or not isinstance(expected_size, int)
        or not 0 <= expected_size <= (1 << 63) - 1
    ):
        raise _WorkerFailure(
            "invalid_request",
            "The parser worker input size is invalid.",
        )

    options = _object(root["options"], _OPTION_FIELDS)
    use_magika = options["use_magika"]
    if not isinstance(use_magika, bool):
        raise _WorkerFailure(
            "invalid_request",
            "The parser worker options are invalid.",
        )

    limits_payload = _object(root["limits"], _LIMIT_FIELDS)
    limits = ParserWorkerLimits(
        cpu_seconds=_positive_limit(limits_payload, "cpu_seconds"),
        max_memory_bytes=_positive_limit(limits_payload, "max_memory_bytes"),
        max_open_files=_positive_limit(limits_payload, "max_open_files"),
        max_processes=_positive_limit(limits_payload, "max_processes"),
        max_output_file_bytes=_positive_limit(limits_payload, "max_output_file_bytes"),
        max_parser_log_bytes=_positive_limit(limits_payload, "max_parser_log_bytes"),
    )
    return ParserWorkerRequest(
        request_id=request_id,
        operation=operation,
        input=ParserWorkerInput(expected_sha256, expected_size),
        use_magika=use_magika,
        limits=limits,
    )


def _read_request(stream: BinaryIO) -> tuple[ParserWorkerRequest, str]:
    try:
        metadata = os.fstat(stream.fileno())
    except (OSError, ValueError) as exc:
        raise _WorkerFailure(
            "request_not_regular",
            "The parser worker request must be provided as a regular file.",
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise _WorkerFailure(
            "request_not_regular",
            "The parser worker request must be provided as a regular file.",
        )
    if metadata.st_size > _MAX_REQUEST_BYTES:
        raise _WorkerFailure(
            "request_too_large",
            "The parser worker request exceeds the size limit.",
        )
    raw = stream.read(_MAX_REQUEST_BYTES + 1)
    if len(raw) > _MAX_REQUEST_BYTES:
        raise _WorkerFailure(
            "request_too_large",
            "The parser worker request exceeds the size limit.",
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _WorkerFailure(
            "invalid_request_encoding",
            "The parser worker request must be UTF-8 JSON.",
        ) from exc
    try:
        parsed = cast(
            object,
            json.loads(
                text,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite_constant,
            ),
        )
    except _WorkerFailure:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise _WorkerFailure(
            "invalid_request_json",
            "The parser worker request is not valid canonical JSON.",
        ) from exc
    request_id = _request_id_hint(parsed)
    try:
        request = _parse_request_payload(parsed)
    except _WorkerFailure as failure:
        failure.request_id = request_id
        raise
    return request, request_id


def _parse_arguments(argv: Sequence[str]) -> Path:
    if len(argv) != 2 or argv[0] != "--input" or not argv[1]:
        raise _WorkerFailure(
            "invalid_arguments",
            "The parser worker requires one snapshot input.",
        )
    return Path(argv[1])


def _apply_posix_limits(limits: ParserWorkerLimits) -> None:
    if os.name == "nt":
        return
    if os.name != "posix":
        raise _WorkerFailure(
            "resource_limits_unavailable",
            "Required process resource limits are unavailable on this platform.",
        )
    try:
        resource = cast(_ResourceModule, importlib.import_module("resource"))
    except ImportError as exc:
        raise _WorkerFailure(
            "resource_limits_unavailable",
            "Required process resource limits are unavailable on this platform.",
        ) from exc

    core_resource = getattr(resource, "RLIMIT_CORE", None)
    if isinstance(core_resource, int):
        # Core-dump suppression is defense in depth. Every caller-requested limit below
        # remains mandatory and determines whether the worker may continue.
        with contextlib.suppress(OSError, ValueError):
            resource.setrlimit(core_resource, (0, 0))

    requested = (
        ("RLIMIT_CPU", limits.cpu_seconds),
        ("RLIMIT_AS", limits.max_memory_bytes),
        ("RLIMIT_NOFILE", limits.max_open_files),
        ("RLIMIT_NPROC", limits.max_processes),
        ("RLIMIT_FSIZE", limits.max_output_file_bytes),
    )
    for name, value in requested:
        resource_id = getattr(resource, name, None)
        if not isinstance(resource_id, int):
            raise _WorkerFailure(
                "resource_limits_unavailable",
                "Required process resource limits are unavailable on this platform.",
            )
        try:
            _soft, hard = resource.getrlimit(resource_id)
            effective = value if hard == resource.RLIM_INFINITY else min(value, hard)
            if effective < 1:
                raise _WorkerFailure(
                    "resource_limits_unavailable",
                    "Required process resource limits are unavailable on this platform.",
                )
            resource.setrlimit(resource_id, (effective, effective))
        except _WorkerFailure:
            raise
        except (OSError, ValueError) as exc:
            raise _WorkerFailure(
                "resource_limit_failed",
                "A required process resource limit could not be applied.",
            ) from exc


def _has_reparse_attribute(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)


def _measure_snapshot(path: Path, expected_size: int) -> _SnapshotMeasurement:
    try:
        path_metadata = path.lstat()
    except OSError as exc:
        raise _WorkerFailure(
            "input_unavailable",
            "The parser worker input is unavailable.",
        ) from exc
    if stat.S_ISLNK(path_metadata.st_mode) or _has_reparse_attribute(path_metadata):
        raise _WorkerFailure(
            "input_link_rejected",
            "The parser worker input must not be a link or reparse point.",
        )
    if not stat.S_ISREG(path_metadata.st_mode):
        raise _WorkerFailure(
            "input_not_regular",
            "The parser worker input must be a regular file.",
        )
    if path_metadata.st_size != expected_size:
        raise _WorkerFailure(
            "input_size_mismatch",
            "The parser worker input size does not match the request.",
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode):
            raise _WorkerFailure(
                "input_not_regular",
                "The parser worker input must be a regular file.",
            )
        if _identity(opened_metadata) != _identity(path_metadata):
            raise _WorkerFailure(
                "input_changed",
                "The parser worker input changed during verification.",
            )
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            remaining = expected_size
            while remaining:
                chunk = handle.read(min(_HASH_CHUNK_BYTES, remaining))
                if not chunk:
                    raise _WorkerFailure(
                        "input_changed",
                        "The parser worker input changed during verification.",
                    )
                digest.update(chunk)
                remaining -= len(chunk)
            if handle.read(1):
                raise _WorkerFailure(
                    "input_changed",
                    "The parser worker input changed during verification.",
                )
            final_opened_metadata = os.fstat(handle.fileno())
        final_path_metadata = path.lstat()
    except _WorkerFailure:
        raise
    except OSError as exc:
        raise _WorkerFailure(
            "input_unavailable",
            "The parser worker input is unavailable.",
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if (
        _identity(final_opened_metadata) != _identity(opened_metadata)
        or _identity(final_path_metadata) != _identity(path_metadata)
        or stat.S_ISLNK(final_path_metadata.st_mode)
        or _has_reparse_attribute(final_path_metadata)
    ):
        raise _WorkerFailure(
            "input_changed",
            "The parser worker input changed during verification.",
        )
    return _SnapshotMeasurement(
        sha256=digest.hexdigest(),
        size_bytes=opened_metadata.st_size,
        identity=_identity(opened_metadata),
    )


def _inspect_snapshot(path: Path, request: ParserWorkerRequest) -> dict[str, object]:
    before = _measure_snapshot(path, request.input.size_bytes)
    if before.sha256 != request.input.sha256:
        raise _WorkerFailure(
            "input_digest_mismatch",
            "The parser worker input digest does not match the request.",
        )

    log_sink = _CountingDiscardSink(request.limits.max_parser_log_bytes)
    try:
        with contextlib.redirect_stdout(log_sink), contextlib.redirect_stderr(log_sink):
            from .content import ContentInspector, MagikaClassifier

            classifier = MagikaClassifier() if request.use_magika else None
            report = ContentInspector(classifier=classifier).inspect(path)
    except _ParserLogLimitExceeded as exc:
        raise _WorkerFailure(
            "parser_log_limit_exceeded",
            "Parser output exceeded the configured limit.",
        ) from exc
    except _WorkerFailure:
        raise
    except BaseException as exc:
        raise _WorkerFailure(
            "inspection_failed",
            "The parser worker could not inspect the input.",
        ) from exc

    after = _measure_snapshot(path, request.input.size_bytes)
    if (
        after.sha256 != request.input.sha256
        or after.sha256 != before.sha256
        or after.size_bytes != before.size_bytes
        or after.identity != before.identity
        or report.size_bytes != before.size_bytes
        or _identity_from_report(report.identity) != before.identity
    ):
        raise _WorkerFailure(
            "input_changed",
            "The parser worker input changed during inspection.",
        )

    inspection = report.as_dict()
    inspection["path"] = "<snapshot>"
    inspection.pop("identity", None)
    return {
        "protocol": PROTOCOL,
        "version": PROTOCOL_VERSION,
        "request_id": request.request_id,
        "ok": True,
        "input": {
            "sha256": after.sha256,
            "size_bytes": after.size_bytes,
        },
        "inspection": inspection,
    }


def _identity_from_report(identity: _FileIdentityLike) -> tuple[int, int, int, int]:
    return (
        identity.device,
        identity.inode,
        identity.size_bytes,
        identity.mtime_ns,
    )


def _error_response(request_id: str, failure: _WorkerFailure) -> dict[str, object]:
    return {
        "protocol": PROTOCOL,
        "version": PROTOCOL_VERSION,
        "request_id": request_id,
        "ok": False,
        "error_code": failure.code,
        "message": failure.message,
    }


def _encode_response(response: Mapping[str, object]) -> str:
    try:
        encoded = json.dumps(
            response,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise _WorkerFailure(
            "invalid_inspection_result",
            "The parser worker produced an invalid inspection result.",
        ) from exc
    if len(encoded) + 1 > _MAX_RESPONSE_BYTES:
        raise _WorkerFailure(
            "response_too_large",
            "The parser worker response exceeds the size limit.",
        )
    return encoded.decode("utf-8") + "\n"


def _write_response(stream: TextIO, response: Mapping[str, object]) -> None:
    stream.write(_encode_response(response))
    stream.flush()


def main(argv: Sequence[str] | None = None) -> int:
    response_stream = sys.stdout
    request_id = _UNKNOWN_REQUEST_ID
    try:
        input_stream = cast(BinaryIO, sys.stdin.buffer)
        request, request_id = _read_request(input_stream)
        path = _parse_arguments(tuple(sys.argv[1:] if argv is None else argv))
        _apply_posix_limits(request.limits)
        response = _inspect_snapshot(path, request)
    except _WorkerFailure as failure:
        if failure.request_id is not None:
            request_id = failure.request_id
        response = _error_response(request_id, failure)
    except BaseException:
        response = _error_response(
            request_id,
            _WorkerFailure(
                "worker_failed",
                "The parser worker failed safely.",
            ),
        )

    try:
        _write_response(response_stream, response)
    except _WorkerFailure as failure:
        try:
            _write_response(response_stream, _error_response(request_id, failure))
        except BaseException:
            return 70
    except BaseException:
        return 70
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

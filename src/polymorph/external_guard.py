"""Bounded client for the optional NSFW Guard process bridge."""

from __future__ import annotations

import hashlib
import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Iterator, Sequence
from pathlib import Path
from types import TracebackType
from typing import IO

BRIDGE_PROTOCOL = "safety-bridge/v1"
DEFAULT_RESPONSE_LIMIT_BYTES = 1_048_576
DEFAULT_TIMEOUT_SECONDS = 120.0

JsonObject = dict[str, object]
_ReaderItem = str | BaseException | None


class ExternalGuardError(ValueError):
    """The optional guard is absent, malformed, or outside its declared contract."""


def discover_guard_command(executable: str | Path | None = None) -> tuple[str, ...]:
    """Resolve one executable without a shell or implicit package import."""
    requested = str(executable) if executable is not None else os.getenv("POLYMORPH_NSFW_GUARD")
    if requested:
        candidate = Path(requested).expanduser()
        if candidate.is_file():
            return (str(candidate.resolve()),)
        resolved = shutil.which(requested)
        if resolved is not None:
            return (str(Path(resolved).resolve()),)
        raise ExternalGuardError(f"NSFW Guard executable was not found: {requested}")

    resolved = shutil.which("nsfw-guard")
    if resolved is None:
        raise ExternalGuardError(
            "NSFW Guard is optional and was not found on PATH. Install nsfw-guard or set "
            "POLYMORPH_NSFW_GUARD to its executable path."
        )
    return (str(Path(resolved).resolve()),)


def scan_images(
    paths: Sequence[str | Path],
    *,
    command: Sequence[str] | None = None,
    executable: str | Path | None = None,
    policy: str = "balanced-v1",
    provider: str = "cpu",
    threads: int = 0,
    cuda_arena_limit_mib: int | None = None,
    model_path: str | Path | None = None,
    no_download: bool = False,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    response_limit_bytes: int = DEFAULT_RESPONSE_LIMIT_BYTES,
) -> Iterator[JsonObject]:
    """Yield validated bridge responses while one guard process stays warm."""
    normalized = tuple(_require_image_path(item) for item in paths)
    if not normalized:
        raise ExternalGuardError("At least one image path is required.")
    if command is not None and executable is not None:
        raise ExternalGuardError("Use command or executable, not both.")
    if threads < 0:
        raise ExternalGuardError("threads must be zero or greater.")
    if timeout_seconds <= 0:
        raise ExternalGuardError("timeout_seconds must be greater than zero.")
    if response_limit_bytes < 1024:
        raise ExternalGuardError("response_limit_bytes must be at least 1024.")
    if provider == "cuda" and cuda_arena_limit_mib is None:
        raise ExternalGuardError("CUDA requires an explicit cuda_arena_limit_mib.")

    resolved_command = tuple(command) if command is not None else discover_guard_command(executable)
    if not resolved_command or any(not part for part in resolved_command):
        raise ExternalGuardError("The NSFW Guard command must contain non-empty arguments.")
    roots = tuple(dict.fromkeys(path.parent for path in normalized))

    with _BridgeProcess(
        resolved_command,
        roots=roots,
        policy=policy,
        provider=provider,
        threads=threads,
        cuda_arena_limit_mib=cuda_arena_limit_mib,
        model_path=model_path,
        no_download=no_download,
        timeout_seconds=timeout_seconds,
        response_limit_bytes=response_limit_bytes,
    ) as bridge:
        for index, path in enumerate(normalized, start=1):
            request_id = f"polymorph-{index:08d}"
            request: JsonObject = {
                "protocol": BRIDGE_PROTOCOL,
                "operation": "scan",
                "id": request_id,
                "artifact": {
                    "kind": "file",
                    "path": str(path),
                    "sha256": _file_sha256(path),
                },
            }
            yield bridge.exchange(request, request_id=request_id)


class _BridgeProcess:
    def __init__(
        self,
        command: Sequence[str],
        *,
        roots: Sequence[Path],
        policy: str,
        provider: str,
        threads: int,
        cuda_arena_limit_mib: int | None,
        model_path: str | Path | None,
        no_download: bool,
        timeout_seconds: float,
        response_limit_bytes: int,
    ) -> None:
        arguments = [*command, "bridge", "--policy", policy, "--provider", provider]
        for root in roots:
            arguments.extend(("--allow-root", str(root)))
        if threads:
            arguments.extend(("--threads", str(threads)))
        if cuda_arena_limit_mib is not None:
            arguments.extend(("--cuda-arena-limit-mib", str(cuda_arena_limit_mib)))
        if model_path is not None:
            arguments.extend(("--model-path", str(Path(model_path).expanduser().resolve())))
        if no_download:
            arguments.append("--no-download")
        self._arguments = arguments
        self._timeout_seconds = timeout_seconds
        self._response_limit_bytes = response_limit_bytes
        self._stderr: IO[str] | None = None
        self._process: subprocess.Popen[str] | None = None
        self._responses: queue.Queue[_ReaderItem] = queue.Queue(maxsize=1)
        self._reader: threading.Thread | None = None

    def __enter__(self) -> _BridgeProcess:
        self._stderr = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
        self._process = subprocess.Popen(  # noqa: S603 - explicit local tool, never a shell
            self._arguments,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._stderr,
            text=True,
            encoding="utf-8",
            errors="strict",
            bufsize=1,
        )
        self._reader = threading.Thread(target=self._read_responses, daemon=True)
        self._reader.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc, traceback
        self.close(check=exc_type is None)

    def exchange(self, request: JsonObject, *, request_id: str) -> JsonObject:
        process = self._require_process()
        if process.stdin is None:
            raise ExternalGuardError("NSFW Guard stdin is unavailable.")
        line = json.dumps(request, ensure_ascii=True, separators=(",", ":"))
        try:
            process.stdin.write(line + "\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise ExternalGuardError(self._failure_message("closed its input")) from exc

        try:
            item = self._responses.get(timeout=self._timeout_seconds)
        except queue.Empty as exc:
            process.kill()
            raise ExternalGuardError(
                f"NSFW Guard exceeded the {self._timeout_seconds:g}s response timeout; no retry "
                "was attempted."
            ) from exc
        if item is None:
            raise ExternalGuardError(self._failure_message("closed its output"))
        if isinstance(item, BaseException):
            raise ExternalGuardError("NSFW Guard emitted invalid UTF-8 output.") from item
        if len(item.encode("utf-8")) > self._response_limit_bytes or not item.endswith("\n"):
            process.kill()
            raise ExternalGuardError("NSFW Guard response exceeded its bounded line contract.")
        try:
            response: object = json.loads(item)
        except json.JSONDecodeError as exc:
            raise ExternalGuardError("NSFW Guard returned malformed JSON.") from exc
        if not isinstance(response, dict):
            raise ExternalGuardError("NSFW Guard response must be a JSON object.")
        if response.get("protocol") != BRIDGE_PROTOCOL:
            raise ExternalGuardError("NSFW Guard returned an unsupported protocol version.")
        if response.get("id") != request_id:
            raise ExternalGuardError("NSFW Guard response id did not match the request.")
        if not isinstance(response.get("ok"), bool):
            raise ExternalGuardError("NSFW Guard response omitted its outcome flag.")
        return {str(key): value for key, value in response.items()}

    def close(self, *, check: bool) -> None:
        process = self._process
        if process is None:
            return
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        try:
            return_code = process.wait(timeout=min(self._timeout_seconds, 10.0))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            if check:
                raise ExternalGuardError(
                    "NSFW Guard did not stop after its input closed."
                ) from None
            return
        finally:
            if self._reader is not None:
                self._reader.join(timeout=1)
            if process.stdout is not None:
                process.stdout.close()
        if check and return_code != 0:
            raise ExternalGuardError(self._failure_message(f"exited with status {return_code}"))
        if self._stderr is not None:
            self._stderr.close()

    def _read_responses(self) -> None:
        process = self._require_process()
        if process.stdout is None:
            self._responses.put(None)
            return
        try:
            while True:
                line = process.stdout.readline(self._response_limit_bytes + 1)
                if not line:
                    self._responses.put(None)
                    return
                self._responses.put(line)
        except BaseException as exc:
            self._responses.put(exc)

    def _require_process(self) -> subprocess.Popen[str]:
        if self._process is None:
            raise ExternalGuardError("NSFW Guard process has not started.")
        return self._process

    def _failure_message(self, action: str) -> str:
        detail = ""
        if self._stderr is not None:
            self._stderr.flush()
            self._stderr.seek(0)
            detail = self._stderr.read(8192).strip()
        suffix = f" Details: {detail}" if detail else ""
        return f"NSFW Guard {action}.{suffix}"


def _require_image_path(value: str | Path) -> Path:
    try:
        path = Path(value).expanduser().resolve(strict=True)
    except OSError as exc:
        raise ExternalGuardError(f"Image path is unavailable: {value}") from exc
    if not path.is_file():
        raise ExternalGuardError(f"Image path is not a file: {path}")
    return path


def _file_sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()

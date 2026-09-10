from __future__ import annotations

import hashlib
import json
import math
import os
import socket
import stat
import sys
import time
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import BinaryIO

import pytest

import polymorph.isolation as isolation_module
from polymorph.isolation import (
    _RISK_CODES,
    BubblewrapWorkerRunner,
    InputSnapshot,
    IsolationLevel,
    ParserWorkerClient,
    SandboxBackendInfo,
    SandboxError,
    SandboxErrorCode,
    SandboxPolicy,
    _assess_bubblewrap_compatibility,
    _bubblewrap_runtime_layout,
    _decode_response,
    _is_reserved_sandbox_destination,
    _runtime_roots,
    _verify_snapshot,
    _windows_taskkill_tree,
    _WorkerRunner,
    snapshot_input,
)


class _ScriptRunner(_WorkerRunner):
    def __init__(self, policy: SandboxPolicy, script: str) -> None:
        super().__init__(policy)
        self.script = script

    @property
    def info(self) -> SandboxBackendInfo:
        return SandboxBackendInfo(
            name="test-script",
            level=IsolationLevel.PROCESS,
            available=True,
            capabilities=("separate_process",),
            reason="test runner",
        )

    def command(self, snapshot: InputSnapshot, package_directory: Path) -> list[str]:
        del snapshot, package_directory
        return [sys.executable, "-I", "-c", self.script]


def _snapshot(tmp_path: Path) -> InputSnapshot:
    source = tmp_path / "input.csv"
    source.write_bytes(b"a,b\n1,2\n")
    return snapshot_input(source, tmp_path / "snapshot", 1024)


def test_snapshot_rejects_input_below_linked_parent(tmp_path: Path) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    (real_directory / "input.csv").write_bytes(b"a,b\n1,2\n")
    linked_directory = tmp_path / "linked"
    try:
        linked_directory.symlink_to(real_directory, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    with pytest.raises(SandboxError) as caught:
        snapshot_input(linked_directory / "input.csv", tmp_path / "snapshot", 1024)

    assert caught.value.code in {
        SandboxErrorCode.INPUT_SYMLINK,
        SandboxErrorCode.INPUT_REPARSE_POINT,
    }
    assert "parent" in str(caught.value)


def test_snapshot_rejects_linked_parent_before_dotdot(tmp_path: Path) -> None:
    lexical_directory = tmp_path / "lexical"
    lexical_directory.mkdir()
    target_parent = tmp_path / "target"
    target_child = target_parent / "child"
    target_child.mkdir(parents=True)
    (target_parent / "input.csv").write_bytes(b"a,b\n1,2\n")
    linked_directory = lexical_directory / "jump"
    try:
        linked_directory.symlink_to(target_child, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks unavailable: {exc}")

    with pytest.raises(SandboxError) as caught:
        snapshot_input(
            linked_directory / ".." / "input.csv",
            tmp_path / "snapshot",
            1024,
        )

    assert caught.value.code in {
        SandboxErrorCode.INPUT_SYMLINK,
        SandboxErrorCode.INPUT_REPARSE_POINT,
    }


def _package_directory() -> Path:
    return Path(isolation_module.__file__).resolve().parent


def test_local_process_policy_is_explicit_and_rejects_nonfinite_timeouts() -> None:
    assert SandboxPolicy.local_process().minimum_level is IsolationLevel.PROCESS
    for timeout in (math.nan, math.inf, -math.inf):
        with pytest.raises(ValueError):
            SandboxPolicy(wall_timeout_seconds=timeout)
    with pytest.raises(ValueError) as caught:
        SandboxPolicy(wall_timeout_seconds=10**400)
    assert caught.value.__cause__ is None


def test_policy_rejects_invalid_tmpfs_bounds() -> None:
    for value, error in ((False, TypeError), (0, ValueError), (64 * 1024**3 + 1, ValueError)):
        with pytest.raises(error):
            SandboxPolicy(max_tmpfs_bytes=value)  # type: ignore[arg-type]


def test_process_worker_uses_bounded_pipe_memory_for_native_stdout_burst(
    tmp_path: Path,
) -> None:
    policy = replace(
        SandboxPolicy.local_process(),
        wall_timeout_seconds=3.0,
        max_stdout_bytes=64,
        max_stderr_bytes=1024,
    )
    script = (
        "import os\ntry:\n    os.write(1, b'x' * (8 * 1024 * 1024))\nexcept OSError:\n    pass\n"
    )

    with pytest.raises(SandboxError) as caught:
        _ScriptRunner(policy, script).run(_snapshot(tmp_path), _package_directory(), b"{}")

    assert caught.value.code is SandboxErrorCode.WORKER_OUTPUT_LIMIT


def test_success_exit_with_native_stderr_is_protocol_contamination(tmp_path: Path) -> None:
    payload = b"native-stderr"
    script = f"import os; os.write(2,{payload!r})"

    with pytest.raises(SandboxError) as caught:
        _ScriptRunner(SandboxPolicy.local_process(), script).run(
            _snapshot(tmp_path),
            _package_directory(),
            b"{}",
        )

    assert caught.value.code is SandboxErrorCode.WORKER_FAILED
    assert caught.value.stderr_digest == hashlib.sha256(payload).hexdigest()


def test_descendant_held_pipes_do_not_hold_parent_open(tmp_path: Path) -> None:
    child = "import time; time.sleep(3)"
    script = f"import subprocess, sys; subprocess.Popen([sys.executable, '-I', '-c', {child!r}])"
    started = time.perf_counter()

    result = _ScriptRunner(SandboxPolicy.local_process(), script).run(
        _snapshot(tmp_path),
        _package_directory(),
        b"{}",
    )

    assert result.exit_code == 0
    assert time.perf_counter() - started < 2.5


def test_parent_rehash_rejects_snapshot_growth(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)
    snapshot.path.chmod(stat.S_IWRITE | stat.S_IREAD)
    with snapshot.path.open("ab") as handle:
        handle.write(b"extra")
        handle.flush()
        os.fsync(handle.fileno())

    with pytest.raises(SandboxError) as caught:
        _verify_snapshot(snapshot)

    assert caught.value.code is SandboxErrorCode.INPUT_SNAPSHOT_CHANGED


def test_snapshot_copy_reads_only_initial_size_plus_growth_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"x")
    real_fdopen = isolation_module.os.fdopen

    class GrowingReader:
        def __init__(self, handle: BinaryIO) -> None:
            self.handle = handle
            self.injected = False

        def __enter__(self) -> GrowingReader:
            return self

        def __exit__(self, *_args: object) -> None:
            self.handle.close()

        def read(self, size: int) -> bytes:
            payload = self.handle.read(size)
            if payload == b"" and not self.injected:
                self.injected = True
                return b"y"
            return payload

        def fileno(self) -> int:
            return self.handle.fileno()

    def fdopen(descriptor: int, mode: str, *args: object, **kwargs: object) -> object:
        handle = real_fdopen(descriptor, mode, *args, **kwargs)
        return GrowingReader(handle) if mode == "rb" else handle

    monkeypatch.setattr(isolation_module.os, "fdopen", fdopen)

    with pytest.raises(SandboxError) as caught:
        snapshot_input(source, tmp_path / "staged", 1024)

    assert caught.value.code is SandboxErrorCode.INPUT_CHANGED


def test_process_environment_does_not_fix_hash_seed() -> None:
    environment = _ScriptRunner(SandboxPolicy.local_process(), "pass")._environment()

    assert "PYTHONHASHSEED" not in environment


@pytest.mark.skipif(os.name != "nt", reason="Windows taskkill contract")
def test_windows_taskkill_tree_is_bounded_and_noninteractive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []
    system_root = tmp_path / "Windows"
    taskkill = system_root / "System32" / "taskkill.exe"
    taskkill.parent.mkdir(parents=True)
    taskkill.write_bytes(b"taskkill")

    def run(command: list[str], **kwargs: object) -> object:
        calls.append((command, kwargs))
        return object()

    monkeypatch.setattr(isolation_module.subprocess, "run", run)
    monkeypatch.setenv("SYSTEMROOT", str(system_root))

    _windows_taskkill_tree(1234)

    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[1:] == ["/PID", "1234", "/T", "/F"]
    assert kwargs["timeout"] == 1.0
    assert kwargs["check"] is False
    assert kwargs["stdin"] is isolation_module.subprocess.DEVNULL
    assert kwargs["stdout"] is isolation_module.subprocess.DEVNULL
    assert kwargs["stderr"] is isolation_module.subprocess.DEVNULL


@pytest.mark.skipif(os.name != "nt", reason="Windows termination contract")
def test_windows_successful_process_does_not_invoke_taskkill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    class ExitedProcess:
        pid = 1234

        @staticmethod
        def poll() -> int:
            return 0

        @staticmethod
        def kill() -> None:
            raise AssertionError("an exited worker must not be killed")

    monkeypatch.setattr(isolation_module, "_windows_taskkill_tree", calls.append)

    _WorkerRunner._terminate(ExitedProcess())  # type: ignore[arg-type]

    assert calls == []


def test_bubblewrap_command_relocates_venv_and_hardens_mounts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lexical_python = tmp_path / "venv" / "bin" / "python"
    lexical_python.parent.mkdir(parents=True)
    lexical_python.write_bytes(b"python")
    lexical_python.chmod(0o755)
    venv_root = lexical_python.parent.parent
    (venv_root / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    bubblewrap_binary = tmp_path / "bwrap"
    bubblewrap_binary.write_bytes(b"bubblewrap")
    bubblewrap_binary.chmod(0o755)
    seen: list[Path] = []

    def runtime_layout(path: Path) -> object:
        seen.append(path)
        return isolation_module._BubblewrapRuntimeLayout(
            executable=PurePosixPath("/runtime/venv/bin/python"),
            mounts=((venv_root, PurePosixPath("/runtime/venv")),),
        )

    monkeypatch.setattr(isolation_module.sys, "executable", str(lexical_python))
    monkeypatch.setattr(isolation_module, "_bubblewrap_runtime_layout", runtime_layout)
    policy = replace(SandboxPolicy(), max_tmpfs_bytes=123456)
    command = BubblewrapWorkerRunner(
        policy,
        binary=str(bubblewrap_binary),
    ).command(_snapshot(tmp_path), _package_directory())

    assert seen == [lexical_python]
    assert "/runtime/venv/bin/python" in command
    assert ["--ro-bind", str(venv_root), "/runtime/venv"] == command[
        command.index(str(venv_root)) - 1 : command.index(str(venv_root)) + 2
    ]
    assert "PYTHONHASHSEED" not in command
    assert "--disable-userns" in command
    assert "--assert-userns-disabled" in command
    cap_drop = command.index("--cap-drop")
    assert command[cap_drop + 1] == "ALL"
    tmp_mount = next(
        index
        for index, item in enumerate(command)
        if item == "--tmpfs" and command[index + 1] == "/tmp"
    )
    assert command[tmp_mount - 2 : tmp_mount + 2] == [
        "--size",
        str(policy.max_tmpfs_bytes),
        "--tmpfs",
        "/tmp",
    ]
    work_bind = command.index("/work")
    assert command[work_bind - 2 : work_bind + 1] == [
        "--ro-bind",
        str(tmp_path / "snapshot"),
        "/work",
    ]
    remounts = [command[index + 1] for index, item in enumerate(command) if item == "--remount-ro"]
    assert remounts == ["/app", "/runtime", "/dev", "/"]
    root_remount = max(index for index, item in enumerate(command) if item == "--remount-ro")
    last_bind = max(index for index, item in enumerate(command) if item == "--ro-bind")
    assert root_remount > last_bind
    assert root_remount < command.index("--chdir")
    assert "--dir" not in command


def test_bubblewrap_compatibility_rejects_old_or_incomplete_versions() -> None:
    required_help = " ".join(isolation_module._BWRAP_REQUIRED_OPTIONS).encode()

    compatible, reason = _assess_bubblewrap_compatibility(b"bubblewrap 0.11.0\n", required_help)
    assert not compatible
    assert "security floor is >= 0.12.0" in reason

    compatible, reason = _assess_bubblewrap_compatibility(
        b"bubblewrap 0.12.0\n",
        required_help.replace(b"--assert-userns-disabled", b""),
    )
    assert not compatible
    assert "--assert-userns-disabled" in reason

    compatible, _ = _assess_bubblewrap_compatibility(b"bubblewrap 0.12.0\n", required_help)
    assert compatible


def test_bubblewrap_backend_reports_old_binary_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "bwrap"
    binary.write_bytes(b"bubblewrap")
    binary.chmod(0o755)
    monkeypatch.setattr(isolation_module.sys, "platform", "linux")
    runner = BubblewrapWorkerRunner(
        SandboxPolicy(),
        binary=str(binary),
        compatibility_probe=lambda _binary: (
            False,
            "Bubblewrap 0.6.1 is too old; parser isolation security floor is >= 0.12.0",
        ),
    )

    first = runner.info
    second = runner.info

    assert not first.available
    assert first.reason == second.reason
    assert first.capabilities == ("binary_discovered",)


@pytest.mark.skipif(os.name == "nt", reason="POSIX set-id mode bits")
def test_bubblewrap_backend_rejects_setid_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "bwrap"
    binary.write_bytes(b"bubblewrap")
    binary.chmod(0o755 | stat.S_ISUID)
    monkeypatch.setattr(isolation_module.sys, "platform", "linux")
    runner = BubblewrapWorkerRunner(SandboxPolicy(), binary=str(binary))

    assert not runner.info.available
    assert "setuid or setgid" in runner.info.reason


def test_reserved_bubblewrap_destinations_cover_mutable_and_kernel_mounts() -> None:
    for path in ("/app/x", "/dev/x", "/proc/x", "/runtime/x", "/tmp/x", "/work/x"):
        assert _is_reserved_sandbox_destination(PurePosixPath(path))
    assert not _is_reserved_sandbox_destination(PurePosixPath("/usr"))


@pytest.mark.skipif(sys.platform != "linux", reason="POSIX virtualenv mapping contract")
def test_bubblewrap_runtime_layout_relocates_synthetic_app_venv() -> None:
    prefix = Path("/app/.venv")
    layout = _bubblewrap_runtime_layout(
        prefix / "bin/python",
        prefix=prefix,
        base_prefix=Path("/usr"),
        system_roots=(Path("/usr"), Path("/lib"), Path("/lib64")),
    )

    assert layout.executable == PurePosixPath("/runtime/venv/bin/python")
    assert (prefix, PurePosixPath("/runtime/venv")) in layout.mounts


def test_parser_client_caches_bubblewrap_probe_and_selected_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = tmp_path / "bwrap"
    binary.write_bytes(b"bubblewrap")
    binary.chmod(0o755)
    calls = 0

    def probe(_binary: str) -> tuple[bool, str]:
        nonlocal calls
        calls += 1
        return True, "Bubblewrap 0.12.0 exposes all required isolation options"

    monkeypatch.setattr(isolation_module.sys, "platform", "linux")
    monkeypatch.setattr(isolation_module.shutil, "which", lambda _name: str(binary))
    monkeypatch.setattr(isolation_module, "_probe_bubblewrap_compatibility", probe)
    client = ParserWorkerClient(SandboxPolicy(), backend="bubblewrap")

    first = client._runner()
    second = client._runner()
    client.backend_info()

    assert first is second
    assert calls == 1


@pytest.mark.skipif(sys.platform != "linux", reason="Linux lexical runtime mount contract")
def test_linux_runtime_roots_keep_lexical_lib_mounts() -> None:
    roots = _runtime_roots(Path(os.path.abspath(sys.executable)))

    if Path("/lib").is_dir():
        assert Path("/lib") in roots
    if Path("/lib64").is_dir():
        assert Path("/lib64") in roots

    layout = _bubblewrap_runtime_layout(Path(os.path.abspath(sys.executable)))
    prefix = Path(os.path.abspath(sys.prefix))
    base_prefix = Path(os.path.abspath(sys.base_prefix))
    if prefix != base_prefix:
        relative_executable = Path(os.path.abspath(sys.executable)).relative_to(prefix)
        assert layout.executable == PurePosixPath("/runtime/venv") / PurePosixPath(
            relative_executable.as_posix()
        )
        assert (prefix, PurePosixPath("/runtime/venv")) in layout.mounts


@pytest.mark.skipif(sys.platform != "linux", reason="Bubblewrap boundary requires Linux")
def test_real_bubblewrap_enforces_parser_boundary(tmp_path: Path) -> None:
    host_only_path = Path("/etc/passwd")
    assert host_only_path.is_file()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener_port = listener.getsockname()[1]
    policy = replace(
        SandboxPolicy(),
        wall_timeout_seconds=5.0,
        max_tmpfs_bytes=1024 * 1024,
        max_stdout_bytes=16 * 1024,
        max_stderr_bytes=16 * 1024,
    )
    script = f"""
import ctypes
import json
import os
import socket
import subprocess
import sys

def write_denied(path):
    try:
        with open(path, "wb", buffering=0) as handle:
            handle.write(b"x")
    except OSError:
        return True
    return False

network_blocked = False
connection = socket.socket()
connection.settimeout(0.25)
try:
    connection.connect(("127.0.0.1", {listener_port}))
except OSError:
    network_blocked = True
finally:
    connection.close()

libc = ctypes.CDLL(None, use_errno=True)
nested_userns_blocked = libc.unshare(0x10000000) == -1

tmp_bounded = False
try:
    with open("/tmp/quota-probe", "wb", buffering=0) as handle:
        for _ in range(64):
            handle.write(b"x" * 65536)
except OSError:
    tmp_bounded = True

result = {{
    "app_write_denied": write_denied("/app/escape"),
    "dev_write_denied": write_denied("/dev/escape"),
    "host_path_hidden": not os.path.exists({str(host_only_path)!r}),
    "nested_userns_blocked": nested_userns_blocked,
    "network_blocked": network_blocked,
    "root_write_denied": write_denied("/escape"),
    "tmp_bounded": tmp_bounded,
    "work_write_denied": write_denied("/work/escape"),
}}
os.write(1, json.dumps(result, sort_keys=True).encode("ascii"))
subprocess.Popen(
    [sys.executable, "-I", "-c", "import time; time.sleep(20)"],
    stdin=subprocess.DEVNULL,
)
"""

    class BoundaryRunner(BubblewrapWorkerRunner):
        def command(self, snapshot: InputSnapshot, package_directory: Path) -> list[str]:
            command = super().command(snapshot, package_directory)
            marker = command.index("--chdir")
            sandbox_python = command[marker + 2]
            return [
                *command[: marker + 2],
                sandbox_python,
                "-I",
                "-c",
                script,
            ]

    runner = BoundaryRunner(policy)
    backend = runner.info
    if not backend.available:
        listener.close()
        pytest.skip(backend.reason)
    snapshot = _snapshot(tmp_path)
    started = time.perf_counter()

    try:
        result = runner.run(snapshot, _package_directory(), b"{}")
    finally:
        listener.close()

    assert time.perf_counter() - started < 3.0
    checks = json.loads(result.stdout)
    assert checks == {
        "app_write_denied": True,
        "dev_write_denied": True,
        "host_path_hidden": True,
        "nested_userns_blocked": True,
        "network_blocked": True,
        "root_write_denied": True,
        "tmp_bounded": True,
        "work_write_denied": True,
    }
    assert "read_only_dev_mount_with_writable_standard_devices" in runner.info.capabilities


def test_response_validator_knows_new_bounded_parser_risks() -> None:
    assert "archive_metadata_too_large" in _RISK_CODES
    assert "archive_scan_budget_exceeded" in _RISK_CODES
    assert "json_nesting_too_deep" in _RISK_CODES
    assert "json_too_many_items" in _RISK_CODES
    assert "xml_nesting_too_deep" in _RISK_CODES
    assert "xml_too_many_elements" in _RISK_CODES
    assert "xml_too_many_attributes" in _RISK_CODES


def test_invalid_worker_json_has_no_decoder_exception_cause(tmp_path: Path) -> None:
    snapshot = _snapshot(tmp_path)

    with pytest.raises(SandboxError) as caught:
        _decode_response(b'{"payload":', "11" * 16, snapshot)

    assert caught.value.code is SandboxErrorCode.PROTOCOL_ERROR
    assert caught.value.__cause__ is None


def test_worker_response_lone_surrogate_has_no_payload_exception_cause(tmp_path: Path) -> None:
    request_id = "11" * 16
    payload = json.dumps(
        {
            "protocol": "\ud800",
            "version": 1,
            "request_id": request_id,
            "ok": False,
            "error_code": "invalid",
            "message": "invalid",
        }
    ).encode()

    with pytest.raises(SandboxError) as caught:
        _decode_response(payload, request_id, _snapshot(tmp_path))

    assert caught.value.code is SandboxErrorCode.PROTOCOL_ERROR
    assert caught.value.__cause__ is None


def test_worker_response_rejects_log_spoofing_unicode(tmp_path: Path) -> None:
    request_id = "11" * 16
    payload = json.dumps(
        {
            "protocol": "polymorph.parser-worker",
            "version": 1,
            "request_id": request_id,
            "ok": False,
            "error_code": "inspection_failed",
            "message": "safe-looking\u202ereversed",
        }
    ).encode()

    with pytest.raises(SandboxError) as caught:
        _decode_response(payload, request_id, _snapshot(tmp_path))

    assert caught.value.code is SandboxErrorCode.PROTOCOL_ERROR
    assert caught.value.__cause__ is None


def test_worker_response_rejects_unknown_high_cardinality_error_code(tmp_path: Path) -> None:
    request_id = "11" * 16
    payload = json.dumps(
        {
            "protocol": "polymorph.parser-worker",
            "version": 1,
            "request_id": request_id,
            "ok": False,
            "error_code": "attacker_" + "x" * 200,
            "message": "rejected",
        }
    ).encode()

    with pytest.raises(SandboxError) as caught:
        _decode_response(payload, request_id, _snapshot(tmp_path))

    assert caught.value.code is SandboxErrorCode.PROTOCOL_ERROR
    assert caught.value.worker_error_code is None


def test_worker_response_huge_probability_is_stable_protocol_error(tmp_path: Path) -> None:
    request_id = "11" * 16
    snapshot = _snapshot(tmp_path)
    payload = json.dumps(
        {
            "protocol": "polymorph.parser-worker",
            "version": 1,
            "request_id": request_id,
            "ok": True,
            "input": {"sha256": snapshot.sha256, "size_bytes": snapshot.size_bytes},
            "inspection": {
                "path": "<snapshot>",
                "size_bytes": snapshot.size_bytes,
                "kind": "text",
                "confidence": 10**400,
                "safe": True,
                "signals": [],
                "risks": [],
                "classifier": {
                    "provider": "none",
                    "label": None,
                    "mime_type": None,
                    "score": None,
                },
            },
        }
    ).encode()

    with pytest.raises(SandboxError) as caught:
        _decode_response(payload, request_id, snapshot)

    assert caught.value.code is SandboxErrorCode.PROTOCOL_ERROR
    assert caught.value.__cause__ is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX resource capability contract")
def test_posix_resource_capabilities_are_honest_about_scope_and_core() -> None:
    import resource

    supported, capabilities, reason = isolation_module._posix_resource_capabilities()

    if os.geteuid() == 0:
        assert supported is False
        assert capabilities == ()
        assert "privileged" in reason
        return
    if supported:
        assert "posix_rlimit_nproc_uid_scoped" in capabilities
        assert "posix_rlimit_process_count" not in capabilities
        assert "real-UID scoped" in reason
    assert "posix_rlimit_core" not in capabilities
    if hasattr(resource, "RLIMIT_CORE"):
        assert "posix_rlimit_core_best_effort" in capabilities


@pytest.mark.skipif(os.name == "nt", reason="POSIX privilege capability contract")
def test_privileged_process_runner_does_not_claim_enforceable_rlimits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(isolation_module.os, "geteuid", lambda: 0)

    supported, capabilities, reason = isolation_module._posix_resource_capabilities()

    assert supported is False
    assert capabilities == ()
    assert "privileged" in reason


def test_real_local_worker_inspects_content_over_bounded_pipes(tmp_path: Path) -> None:
    source = tmp_path / "renamed.xlsx"
    source.write_bytes(b"customer,amount\nA,1\n")

    result = ParserWorkerClient(
        SandboxPolicy.local_process(),
        backend="process",
    ).inspect_content(source)

    assert result.inspection["kind"] == "delimited_text"
    assert result.stdout_bytes <= SandboxPolicy.local_process().max_stdout_bytes
    assert result.stderr_bytes == 0
    assert result.end_to_end_duration_seconds >= result.snapshot_duration_seconds
    assert result.end_to_end_duration_seconds >= result.worker_duration_seconds

from __future__ import annotations

import errno

import pytest

import polymorph.filesystem as filesystem
from polymorph.filesystem import (
    PathLockError,
    PathLockTimeout,
    atomic_write_text,
    exclusive_path_lock,
)


def test_exclusive_path_lock_times_out_without_touching_destination(tmp_path) -> None:
    path = tmp_path / "destination.json"

    with (
        exclusive_path_lock(path),
        pytest.raises(PathLockTimeout, match="timed out"),
        exclusive_path_lock(
            path,
            timeout_seconds=0.01,
            poll_interval_seconds=0.001,
        ),
    ):
        raise AssertionError("contended lock was acquired")

    assert not path.exists()
    assert len(list(tmp_path.glob(".polymorph-write-*.lock"))) == 1


@pytest.mark.parametrize("timeout", (-1.0, float("inf"), float("nan")))
def test_exclusive_path_lock_rejects_unsafe_timeouts(tmp_path, timeout) -> None:
    with (
        pytest.raises(ValueError, match="finite non-negative"),
        exclusive_path_lock(tmp_path / "destination.json", timeout_seconds=timeout),
    ):
        raise AssertionError("invalid timeout was accepted")


def test_exclusive_path_lock_releases_after_body_failure(tmp_path) -> None:
    path = tmp_path / "destination.json"

    with pytest.raises(RuntimeError, match="simulated"), exclusive_path_lock(path):
        raise RuntimeError("simulated writer failure")

    with exclusive_path_lock(path, timeout_seconds=0):
        pass

    lock_files = list(tmp_path.glob(".polymorph-write-*.lock"))
    assert len(lock_files) == 1
    assert lock_files[0].read_bytes() == b"\0"


def test_atomic_write_retries_a_transient_windows_replace_failure(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target.json"
    target.write_text("old", encoding="utf-8")
    real_replace = filesystem.os.replace
    attempts = 0

    def transient_replace(source, destination) -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise PermissionError(errno.EACCES, "simulated sharing violation")
        real_replace(source, destination)

    monkeypatch.setattr(filesystem.os, "replace", transient_replace)
    monkeypatch.setattr(filesystem, "_is_retryable_windows_replace_error", lambda _error: True)
    monkeypatch.setattr(filesystem.time, "sleep", lambda _seconds: None)

    atomic_write_text(target, "new")

    assert attempts == 3
    assert target.read_text(encoding="utf-8") == "new"


def test_replace_retry_policy_is_limited_to_windows_sharing_errors() -> None:
    permission_error = PermissionError(errno.EACCES, "busy")
    other_error = OSError(errno.EIO, "broken")

    assert filesystem._is_retryable_windows_replace_error(permission_error, platform_name="nt")
    assert not filesystem._is_retryable_windows_replace_error(
        permission_error, platform_name="posix"
    )
    assert not filesystem._is_retryable_windows_replace_error(other_error, platform_name="nt")


def test_atomic_create_stays_successful_if_temporary_cleanup_fails_after_publish(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "created.json"
    real_unlink = filesystem.os.unlink
    cleanup_attempts = 0

    def fail_temporary_cleanup(path) -> None:
        nonlocal cleanup_attempts
        cleanup_attempts += 1
        raise PermissionError(errno.EACCES, "simulated post-publish cleanup failure")

    monkeypatch.setattr(filesystem.os, "unlink", fail_temporary_cleanup)
    atomic_write_text(target, "committed", overwrite=False)
    monkeypatch.setattr(filesystem.os, "unlink", real_unlink)

    assert cleanup_attempts == 1
    assert target.read_text(encoding="utf-8") == "committed"
    for leftover in tmp_path.glob(f".{target.name}.*"):
        leftover.unlink()


def test_lock_initialization_stays_usable_if_temporary_cleanup_fails(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "destination.json"
    real_unlink = filesystem.os.unlink

    monkeypatch.setattr(
        filesystem.os,
        "unlink",
        lambda _path: (_ for _ in ()).throw(PermissionError(errno.EACCES, "busy")),
    )
    with exclusive_path_lock(target):
        pass
    monkeypatch.setattr(filesystem.os, "unlink", real_unlink)

    lock_files = list(tmp_path.glob(".polymorph-write-*.lock"))
    assert len(lock_files) == 1
    assert lock_files[0].read_bytes() == b"\0"
    for leftover in tmp_path.iterdir():
        if leftover != lock_files[0]:
            leftover.unlink()


@pytest.mark.parametrize("content", (b"", b"too large"))
def test_existing_corrupt_lock_file_fails_closed(tmp_path, content: bytes) -> None:
    target = tmp_path / "destination.json"
    resolved, key = filesystem._canonical_path(target)
    lock_path = filesystem._lock_file_for(resolved, key)
    lock_path.write_bytes(content)

    with pytest.raises(PathLockError, match="invalid size"), exclusive_path_lock(target):
        pass

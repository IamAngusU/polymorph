from __future__ import annotations

import pytest

from polymorph.filesystem import PathLockTimeout, exclusive_path_lock


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

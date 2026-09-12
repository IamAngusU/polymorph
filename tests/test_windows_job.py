from __future__ import annotations

import os
from pathlib import Path

import pytest

from polymorph.isolation import IsolationLevel, ProcessWorkerRunner, SandboxPolicy


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_windows_process_runner_uses_resource_job_before_parser(tmp_path: Path) -> None:
    runner = ProcessWorkerRunner(SandboxPolicy.local_process())
    info = runner.info
    command = runner.command(
        type("Snapshot", (), {"path": tmp_path / "input"})(),
        Path(__file__).parents[1] / "src" / "polymorph",
    )

    assert info.level is IsolationLevel.RESOURCE_LIMITED_PROCESS
    assert "windows_job_kill_on_close" in info.capabilities
    assert "run_parser_worker" in command[3]

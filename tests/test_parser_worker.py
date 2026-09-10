from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from polymorph.parser_worker import (
    PROTOCOL,
    PROTOCOL_VERSION,
    _CountingDiscardSink,
    _ParserLogLimitExceeded,
)


def _request(source: Path, **changes: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "protocol": PROTOCOL,
        "version": PROTOCOL_VERSION,
        "request_id": "11" * 16,
        "operation": "inspect_content",
        "input": {
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "size_bytes": source.stat().st_size,
        },
        "options": {"use_magika": False},
        "limits": {
            "cpu_seconds": 10,
            "max_memory_bytes": 512 * 1024 * 1024,
            "max_open_files": 64,
            "max_processes": 1,
            "max_output_file_bytes": 512 * 1024,
            "max_parser_log_bytes": 64 * 1024,
        },
    }
    payload.update(changes)
    return payload


def _worker_command(source: Path) -> list[str]:
    source_root = Path(__file__).resolve().parents[1] / "src"
    bootstrap = (
        "import sys;"
        f"sys.path.insert(0,{str(source_root)!r});"
        "from polymorph.parser_worker import main;"
        "raise SystemExit(main())"
    )
    return [sys.executable, "-I", "-c", bootstrap, "--input", str(source)]


def _run_worker(source: Path, request: bytes, tmp_path: Path) -> subprocess.CompletedProcess[bytes]:
    request_path = tmp_path / "request.json"
    request_path.write_bytes(request)
    with request_path.open("rb") as request_handle:
        return subprocess.run(
            _worker_command(source),
            stdin=request_handle,
            capture_output=True,
            check=False,
            timeout=10,
        )


def test_worker_inspects_renamed_csv_without_exposing_source_path(tmp_path: Path) -> None:
    source = tmp_path / "customer-secret-name.xlsx"
    source.write_text("customer,amount\nA,1\nB,2\n", encoding="utf-8")
    request = json.dumps(_request(source), allow_nan=False).encode()

    completed = _run_worker(source, request, tmp_path)

    assert completed.returncode == 0
    assert completed.stderr == b""
    response = json.loads(completed.stdout)
    assert response["ok"] is True
    assert response["request_id"] == "11" * 16
    assert response["input"] == _request(source)["input"]
    assert response["inspection"]["path"] == "<snapshot>"
    assert response["inspection"]["kind"] == "delimited_text"
    assert "identity" not in response["inspection"]
    assert str(source).encode() not in completed.stdout
    assert b"Traceback" not in completed.stderr


@pytest.mark.parametrize(
    ("mutation", "error_code"),
    [
        ({"extra": True}, "invalid_request"),
        ({"operation": "execute_code"}, "unsupported_operation"),
        ({"version": True}, "unsupported_version"),
        ({"request_id": "not-an-id"}, "invalid_request"),
        ({"options": {"use_magika": 1}}, "invalid_request"),
    ],
)
def test_worker_rejects_invalid_request_contract(
    tmp_path: Path,
    mutation: dict[str, object],
    error_code: str,
) -> None:
    source = tmp_path / "input.csv"
    source.write_text("a,b\n1,2\n", encoding="utf-8")
    encoded = json.dumps(_request(source, **mutation), allow_nan=False).encode()

    response = json.loads(_run_worker(source, encoded, tmp_path).stdout)

    assert response["ok"] is False
    assert response["error_code"] == error_code


def test_worker_rejects_duplicate_json_keys_without_traceback(tmp_path: Path) -> None:
    source = tmp_path / "input.csv"
    source.write_text("a,b\n1,2\n", encoding="utf-8")
    payload = json.dumps(_request(source), separators=(",", ":"))
    duplicate = payload.replace(
        '"operation":"inspect_content"',
        '"operation":"inspect_content","operation":"inspect_content"',
    ).encode()

    completed = _run_worker(source, duplicate, tmp_path)
    response = json.loads(completed.stdout)

    assert response["ok"] is False
    assert response["error_code"] == "invalid_request_json"
    assert b"Traceback" not in completed.stderr


def test_worker_requires_regular_file_stdin(tmp_path: Path) -> None:
    source = tmp_path / "input.csv"
    source.write_text("a,b\n1,2\n", encoding="utf-8")
    encoded = json.dumps(_request(source), allow_nan=False).encode()

    completed = subprocess.run(
        _worker_command(source),
        input=encoded,
        capture_output=True,
        check=False,
        timeout=10,
    )
    response = json.loads(completed.stdout)

    assert response["ok"] is False
    assert response["error_code"] == "request_not_regular"


def test_worker_rejects_snapshot_digest_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "input.csv"
    source.write_text("a,b\n1,2\n", encoding="utf-8")
    request = _request(source)
    request["input"] = {"sha256": "00" * 32, "size_bytes": source.stat().st_size}

    response = json.loads(
        _run_worker(source, json.dumps(request, allow_nan=False).encode(), tmp_path).stdout
    )

    assert response["ok"] is False
    assert response["error_code"] == "input_digest_mismatch"


def test_worker_rejects_nonfinite_json_constant(tmp_path: Path) -> None:
    source = tmp_path / "input.csv"
    source.write_text("a,b\n1,2\n", encoding="utf-8")
    encoded = json.dumps(_request(source)).replace('"cpu_seconds": 10', '"cpu_seconds": NaN')

    response = json.loads(_run_worker(source, encoded.encode(), tmp_path).stdout)

    assert response["ok"] is False
    assert response["error_code"] == "invalid_request_json"


def test_parser_log_sink_discards_bounded_text_and_refuses_flood() -> None:
    sink = _CountingDiscardSink(4)

    assert sink.write("test") == 4
    assert sink.bytes_seen == 4
    with pytest.raises(_ParserLogLimitExceeded):
        sink.write("!")


def test_importing_worker_does_not_import_parser_dependencies() -> None:
    source_root = Path(__file__).resolve().parents[1] / "src"
    script = (
        "import sys;"
        f"sys.path.insert(0,{str(source_root)!r});"
        "import polymorph.parser_worker;"
        "raise SystemExit(1 if 'polymorph.content' in sys.modules else 0)"
    )

    completed = subprocess.run(
        [sys.executable, "-I", "-c", script],
        capture_output=True,
        check=False,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr.decode(errors="replace")

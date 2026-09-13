from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from polymorph.cli import build_parser
from polymorph.external_guard import (
    BRIDGE_PROTOCOL,
    ExternalGuardError,
    discover_guard_command,
    scan_images,
)

_MOCK_BRIDGE = """
import json
import pathlib
import sys

capture = pathlib.Path(sys.argv[1])
requests = []
for line in sys.stdin:
    request = json.loads(line)
    requests.append(request)
    response = {
        "protocol": request["protocol"],
        "id": request["id"],
        "ok": True,
        "result": {"verdict": "ALLOW"},
    }
    print(json.dumps(response, separators=(",", ":")), flush=True)
capture.write_text(
    json.dumps({"argv": sys.argv[2:], "requests": requests}), encoding="utf-8"
)
"""


def test_guard_streams_over_one_process_and_binds_file_hash(tmp_path: Path) -> None:
    script = tmp_path / "mock_guard.py"
    capture = tmp_path / "capture.json"
    first = tmp_path / "first.png"
    second = tmp_path / "second.webp"
    script.write_text(_MOCK_BRIDGE, encoding="utf-8")
    first.write_bytes(b"first")
    second.write_bytes(b"second")

    responses = list(
        scan_images(
            [first, second],
            command=(sys.executable, str(script), str(capture)),
            no_download=True,
            timeout_seconds=5,
        )
    )

    evidence = json.loads(capture.read_text(encoding="utf-8"))
    assert [item["result"]["verdict"] for item in responses] == ["ALLOW", "ALLOW"]
    assert evidence["argv"].count("bridge") == 1
    assert evidence["argv"].count("--allow-root") == 1
    assert len(evidence["requests"]) == 2
    assert evidence["requests"][0]["protocol"] == BRIDGE_PROTOCOL
    assert evidence["requests"][0]["operation"] == "scan"
    assert evidence["requests"][0]["artifact"]["sha256"] == (
        "a7937b64b8caa58f03721bb6bacf5c78cb235febe0e70b1b84cd99541461a08e"
    )


def test_guard_rejects_a_mismatched_response_id(tmp_path: Path) -> None:
    script = tmp_path / "wrong_id.py"
    image = tmp_path / "image.png"
    image.write_bytes(b"image")
    script.write_text(
        "import json,sys\n"
        "for line in sys.stdin:\n"
        " request=json.loads(line)\n"
        " print(json.dumps({'protocol':request['protocol'],'id':'wrong','ok':True}),flush=True)\n",
        encoding="utf-8",
    )

    with pytest.raises(ExternalGuardError, match="response id"):
        list(scan_images([image], command=(sys.executable, str(script)), timeout_seconds=5))


def test_guard_discovery_and_cli_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    executable = tmp_path / "nsfw-guard.exe"
    executable.write_bytes(b"")
    monkeypatch.setenv("POLYMORPH_NSFW_GUARD", str(executable))

    assert discover_guard_command() == (str(executable.resolve()),)
    args = build_parser().parse_args(
        ["guard", "image.png", "--provider", "cuda", "--cuda-arena-limit-mib", "512"]
    )
    assert args.command == "guard"
    assert args.provider == "cuda"
    assert args.cuda_arena_limit_mib == 512

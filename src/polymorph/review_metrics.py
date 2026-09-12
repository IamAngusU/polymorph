from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_HISTORY_BYTES = 64 * 1024 * 1024


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _store(value: str | None) -> Path:
    if value:
        return Path(value).expanduser().resolve()
    configured = os.environ.get("POLYMORPH_HOME")
    return Path(configured).expanduser().resolve() if configured else Path.home() / ".polymorph"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True))


def _start(args: argparse.Namespace) -> int:
    if args.fields < 1 or args.suggestions < 0 or args.suggestions > args.fields:
        raise SystemExit("fields must be positive and suggestions must be between zero and fields")
    session_id = uuid.uuid4().hex
    payload = {
        "schema": "polymorph.review-session",
        "version": 1,
        "session_id": session_id,
        "started_at": _now(),
        "started_epoch": time.time(),
        "fields": args.fields,
        "suggestions": args.suggestions,
        "corpus": args.corpus,
        "operator_label": args.operator_label,
        "status": "active",
        "privacy": "metadata_only_no_field_names_or_values",
    }
    path = _store(args.store) / "reviews" / "active" / f"{session_id}.json"
    _write_json(path, payload)
    _emit({key: value for key, value in payload.items() if key != "started_epoch"})
    return 0


def _finish(args: argparse.Namespace) -> int:
    store = _store(args.store)
    path = store / "reviews" / "active" / f"{args.session_id}.json"
    if not path.is_file():
        raise SystemExit("unknown or already completed review session")
    payload = json.loads(path.read_text(encoding="utf-8"))
    counts = (args.accepted, args.corrected, args.abstained)
    if any(value < 0 for value in counts) or sum(counts) != payload["fields"]:
        raise SystemExit("accepted + corrected + abstained must equal the session field count")
    duration = max(0.0, time.time() - float(payload["started_epoch"]))
    completed = {
        key: value for key, value in payload.items() if key not in {"started_epoch", "status"}
    }
    completed.update(
        {
            "status": "completed",
            "completed_at": _now(),
            "duration_seconds": round(duration, 3),
            "accepted": args.accepted,
            "corrected": args.corrected,
            "abstained": args.abstained,
            "suggestion_acceptance_rate": (
                round(args.accepted / payload["suggestions"], 6) if payload["suggestions"] else None
            ),
            "fields_per_minute": (
                round(payload["fields"] / (duration / 60), 3) if duration > 0 else None
            ),
            "timing_caveat": "wall time may include operator idle time",
        }
    )
    completed_path = store / "reviews" / "completed" / f"{args.session_id}.json"
    _write_json(completed_path, completed)
    history = store / "metrics" / "review-history.jsonl"
    history.parent.mkdir(parents=True, exist_ok=True)
    if history.exists() and history.stat().st_size > MAX_HISTORY_BYTES:
        raise SystemExit("review history exceeds the local safety limit")
    with history.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(completed, ensure_ascii=True, sort_keys=True) + "\n")
    path.unlink()
    _emit(completed)
    return 0


def _summary(args: argparse.Namespace) -> int:
    history = _store(args.store) / "metrics" / "review-history.jsonl"
    sessions: list[dict[str, Any]] = []
    if history.is_file():
        if history.stat().st_size > MAX_HISTORY_BYTES:
            raise SystemExit("review history exceeds the local safety limit")
        for line in history.read_text(encoding="utf-8").splitlines():
            if line.strip():
                sessions.append(json.loads(line))
    fields = sum(int(item["fields"]) for item in sessions)
    duration = sum(float(item["duration_seconds"]) for item in sessions)
    accepted = sum(int(item["accepted"]) for item in sessions)
    corrected = sum(int(item["corrected"]) for item in sessions)
    abstained = sum(int(item["abstained"]) for item in sessions)
    _emit(
        {
            "schema": "polymorph.review-summary",
            "version": 1,
            "sessions": len(sessions),
            "fields": fields,
            "duration_seconds": round(duration, 3),
            "accepted": accepted,
            "corrected": corrected,
            "abstained": abstained,
            "fields_per_minute": round(fields / (duration / 60), 3) if duration > 0 else None,
            "privacy": "metadata_only_no_field_names_or_values",
        }
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Measure real metadata-only mapping review work.")
    parser.add_argument("--store", help="local Polymorph state directory")
    sub = parser.add_subparsers(dest="command", required=True)
    start = sub.add_parser("start")
    start.add_argument("--fields", type=int, required=True)
    start.add_argument("--suggestions", type=int, required=True)
    start.add_argument("--corpus", default="private")
    start.add_argument("--operator-label", default="anonymous")
    start.set_defaults(func=_start)
    finish = sub.add_parser("finish")
    finish.add_argument("session_id")
    finish.add_argument("--accepted", type=int, required=True)
    finish.add_argument("--corrected", type=int, required=True)
    finish.add_argument("--abstained", type=int, required=True)
    finish.set_defaults(func=_finish)
    summary = sub.add_parser("summary")
    summary.set_defaults(func=_summary)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

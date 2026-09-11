"""Read-only learned recommendations beside unchanged authoritative decisions."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab_probe  # noqa: E402

PROTOCOL = "angusu.bridge.learning-probe/1"


def _source_from_file(item: dict[str, Any], root: Path) -> Any:
    path = lab_probe._input_path(root, item.get("relative_path"), lab_probe.MAX_FILE_BYTES)
    fmt = item.get("format")
    if fmt in ("csv", "tsv"):
        from polymorph.connectors.csv_file import CsvConnector

        connector: Any = CsvConnector(path)
    elif fmt in ("json", "json5"):
        from polymorph.connectors.json_file import JsonFileConnector

        connector = JsonFileConnector(path)
    elif fmt == "xlsx":
        from polymorph.connectors.excel import ExcelConnector

        connector = ExcelConnector(path)
    else:
        raise lab_probe.InvalidRequest("unsupported source format")
    return connector.inspect_schema()


def handle(payload: Any, root: Path, ranker: Any) -> dict[str, Any]:
    from polymorph.matching.hybrid import HybridMatcher
    from polymorph.serialization import schema_to_dict

    obj = lab_probe._object(payload, {"protocol", "request_id", "operation", "items"})
    if obj.get("protocol") != PROTOCOL or obj.get("operation") not in ("map", "parse_map"):
        raise lab_probe.InvalidRequest("unsupported learning probe contract")
    request_id = lab_probe._text(obj.get("request_id"), 128)
    items = obj.get("items")
    if not isinstance(items, list) or not 1 <= len(items) <= lab_probe.MAX_ITEMS:
        raise lab_probe.InvalidRequest("invalid item count")
    output = []
    identities: set[str] = set()
    for raw_item in items:
        keys = {"id", "target_schema"}
        keys |= {"source_schema"} if obj["operation"] == "map" else {"relative_path", "format"}
        item = lab_probe._object(raw_item, keys)
        identity = lab_probe._text(item.get("id"), 128)
        if identity in identities:
            raise lab_probe.InvalidRequest("duplicate case identity")
        identities.add(identity)
        wall = time.perf_counter_ns()
        target = lab_probe._schema(item.get("target_schema"))
        source = (
            lab_probe._schema(item.get("source_schema"))
            if obj["operation"] == "map"
            else _source_from_file(item, root)
        )
        # Never pass the ranker into the authority path. Model changes affect only
        # the second, explicitly non-executable recommendation result.
        decisions = HybridMatcher().propose(source, target)
        source_dict = schema_to_dict(source)
        target_dict = schema_to_dict(target)
        recommendations = [
            {
                "source_field_id": field["id"],
                "ranking": ranker.rank_fields(field, target_dict["fields"]),
                "requires_review": True,
            }
            for field in source_dict["fields"]
        ]
        output.append(
            {
                "id": identity,
                "source_schema": source_dict,
                "decisions": [
                    {
                        "source_field_id": d.source_field_id,
                        "target_field_id": d.target_field_id,
                        "status": d.status.value,
                    }
                    for d in decisions
                ],
                "recommendations": recommendations,
                "operation_wall_ms": (time.perf_counter_ns() - wall) / 1e6,
            }
        )
    return {
        "protocol": PROTOCOL,
        "request_id": request_id,
        "operation": obj["operation"],
        "items": output,
        "model_sha256": ranker.artifact_sha256,
        "training_performed": False,
        "oracle_received": False,
        "writes_performed": False,
        "authority": "unchanged_deterministic_policy",
        "recommendations": "advisory_only",
        "os_sandboxed": False,
        "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", type=Path, required=True)
    parser.add_argument("--model", type=Path)
    parser.add_argument("--model-sha256")
    parser.add_argument("--knowledge-home", type=Path)
    parser.add_argument("--trusted-key", type=Path)
    args = parser.parse_args()
    if bool(args.knowledge_home) != bool(args.trusted_key):
        parser.error("--knowledge-home and --trusted-key are required together")
    if args.knowledge_home and (args.model or args.model_sha256):
        parser.error("choose an explicit candidate or the active general package, not both")
    if bool(args.model) != bool(args.model_sha256):
        parser.error("--model and --model-sha256 must be supplied together")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    from polymorph.matching.lexical import LearnedRanker

    try:
        ranker = (
            LearnedRanker.load(args.model, expected_sha256=args.model_sha256)
            if args.model
            else LearnedRanker.baseline()
        )
        if args.knowledge_home:
            from polymorph.knowledge import KnowledgeStore, read_bytes

            key = bytes.fromhex(read_bytes(args.trusted_key, 256).decode("ascii").strip())
            ranker = KnowledgeStore(args.knowledge_home, key).active_ranker()
            if ranker is None:
                raise ValueError("no active general knowledge package")
        request = lab_probe._request(sys.stdin.buffer.read(lab_probe.MAX_REQUEST_BYTES + 1))
        with contextlib.redirect_stdout(sys.stderr):
            result = handle(request, args.input_root, ranker)
        raw = lab_probe._canonical(result)
        if len(raw) > lab_probe.MAX_REQUEST_BYTES:
            raise lab_probe.ObservationError("learning response too large")
        sys.stdout.buffer.write(raw + b"\n")
        return 0
    except Exception as exc:
        sys.stdout.buffer.write(
            lab_probe._canonical(
                {"protocol": PROTOCOL, "status": "target_error", "error_type": type(exc).__name__}
            ) + b"\n"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

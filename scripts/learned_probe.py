"""Opt-in, label-free shadow check of a pinned learned advisor. No destination writes."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import sys
from pathlib import Path
from typing import Any

PROTOCOL = "angusu.bridge.lab-probe/1"
MAX_REQUEST_BYTES = 16 * 1024 * 1024


def _wire() -> Any:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import lab_probe

    return lab_probe


ROOT = Path(__file__).resolve().parents[1]


def handle(payload: Any, advisor: Any, model_sha256: str) -> dict[str, Any]:
    from polymorph.matching.hybrid import HybridMatcher

    wire = _wire()

    obj = wire._object(payload, {"protocol", "request_id", "operation", "items"})
    if obj.get("protocol") != PROTOCOL or obj.get("operation") != "map":
        raise wire.InvalidRequest("shadow advisor accepts map operations only")
    request_id = wire._text(obj.get("request_id"), 128)
    items = obj.get("items")
    if not isinstance(items, list) or len(items) > 128:
        raise wire.InvalidRequest("invalid mapping items")
    output = []
    identities = set()
    base, candidate = HybridMatcher(), HybridMatcher(reranker=advisor)
    for item in items:
        item = wire._object(item, {"id", "source_schema", "target_schema"})
        identity = wire._text(item.get("id"), 128)
        if identity in identities:
            raise wire.InvalidRequest("duplicate case identity")
        identities.add(identity)
        source = wire._schema(item.get("source_schema"))
        target = wire._schema(item.get("target_schema"))

        def observe(matcher: Any) -> list[dict[str, Any]]:
            return [{"source_field_id": d.source_field_id, "target_field_id": d.target_field_id,
                     "status": d.status.value, "score": d.score, "margin": d.margin}
                    for d in matcher.propose(source, target)]

        output.append({"id": identity, "status": "ok", "result": observe(candidate),
                       "baseline_result": observe(base)})
    observed_facts = wire.facts()
    observed_facts.update(model_profile="explicit_pinned_sparse_advisor", model_sha256=model_sha256)
    return {"protocol": PROTOCOL, "request_id": request_id, "operation": "map", "items": output,
            "facts": observed_facts, "oracle_received": False, "training_performed": False,
            "scope": "read_only_advisory_shadow", "os_sandboxed": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model", type=Path, required=True)
    p.add_argument("--expected-sha256", required=True)
    args = p.parse_args()
    wire = _wire()
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from polymorph.matching.learned import AdvisoryRanker

        advisor = AdvisoryRanker.load(args.model, expected_sha256=args.expected_sha256)
        request = wire._request(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1))
        with contextlib.redirect_stdout(sys.stderr):
            response = handle(request, advisor, args.expected_sha256)
        # An artifact changed after loading is not a valid recorded candidate evaluation.
        with args.model.open("rb") as stream:
            after_hash = hashlib.sha256(stream.read(16 * 1024 * 1024 + 1)).hexdigest()
        if after_hash != args.expected_sha256:
            raise wire.InvalidRequest("advisor changed during the observation")
        raw = wire._canonical(response)
        if len(raw) > MAX_REQUEST_BYTES:
            raise wire.InvalidRequest("shadow response exceeds budget")
        sys.stdout.buffer.write(raw + b"\n")
        return 0
    except Exception as exc:
        sys.stdout.buffer.write(wire._canonical({"protocol": PROTOCOL, "status": "probe_error", "error_type": type(exc).__name__}) + b"\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

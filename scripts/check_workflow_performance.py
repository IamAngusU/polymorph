from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

from polymorph.connectors.database import DATABASE_ATOMIC_BATCH_MAX_RECORDS

MAX_REPORT_BYTES = 2 * 1024 * 1024


def _without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"workflow report contains duplicate key: {key}")
        result[key] = value
    return result


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"workflow report {label} must be an object")
    return value


def _finite_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"workflow report {label} must be a number")
    converted = float(value)
    if not math.isfinite(converted) or converted < 0:
        raise ValueError(f"workflow report {label} must be finite and non-negative")
    return converted


def _expected_atomic_batch_events(records: int, outer_batch_size: int) -> int:
    def events_for_chunk(size: int) -> int:
        complete, remainder = divmod(size, DATABASE_ATOMIC_BATCH_MAX_RECORDS)
        return complete + int(remainder > 1)

    complete, remainder = divmod(records, outer_batch_size)
    return complete * events_for_chunk(outer_batch_size) + events_for_chunk(remainder)


def load_report(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError("workflow report does not exist")
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("workflow report exceeds the size limit")
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_without_duplicate_keys,
        )
    except (OSError, RecursionError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("workflow report is not valid UTF-8 JSON") from exc
    return _object(payload, "root")


def evaluate_report(
    payload: dict[str, Any],
    *,
    min_throughput: float,
    max_wall_seconds: float,
    max_peak_rss_mib: float,
    expected_records: int | None = None,
    expected_batch_size: int | None = None,
) -> dict[str, object]:
    """Return a deterministic correctness and coarse performance gate result."""

    if payload.get("benchmark") != "workflow" or payload.get("version") != 1:
        raise ValueError("workflow report identity or version is unsupported")
    workflow = _object(payload.get("workflow"), "workflow")
    configuration = _object(workflow.get("configuration"), "configuration")
    progress = _object(workflow.get("progress"), "progress")
    final_state = _object(workflow.get("final_state"), "final_state")
    observability = _object(workflow.get("observability"), "observability")
    resources = _object(payload.get("resources"), "resources")
    measurement = _object(payload.get("measurement"), "measurement")

    records_raw = configuration.get("records")
    if isinstance(records_raw, bool) or not isinstance(records_raw, int) or records_raw <= 0:
        raise ValueError("workflow report record count must be a positive integer")
    records = records_raw
    batch_size_raw = configuration.get("batch_size")
    if (
        isinstance(batch_size_raw, bool)
        or not isinstance(batch_size_raw, int)
        or batch_size_raw <= 0
    ):
        raise ValueError("workflow report batch size must be a positive integer")
    batch_size = batch_size_raw
    expected_batches = (records + batch_size - 1) // batch_size
    throughput = _finite_number(resources.get("throughput_per_second"), "throughput")
    wall_ms = _finite_number(resources.get("wall_ms"), "wall time")
    peak_rss_bytes = _finite_number(resources.get("peak_rss_bytes"), "peak RSS")
    peak_rss_mib = peak_rss_bytes / (1024 * 1024)

    failures: list[str] = []
    if workflow.get("success") is not True or workflow.get("failure") is not None:
        failures.append("workflow_not_successful")
    if expected_records is not None and records != expected_records:
        failures.append("configuration_record_count_mismatch")
    if expected_batch_size is not None and batch_size != expected_batch_size:
        failures.append("configuration_batch_size_mismatch")
    if configuration.get("signed_audit") is not True:
        failures.append("configuration_signed_audit_disabled")
    if (
        measurement.get("mode") != "standard"
        or measurement.get("python_allocation_tracing") is not False
    ):
        failures.append("measurement_mode_not_comparable")
    if (
        resources.get("measurement_mode") != "standard"
        or resources.get("python_allocation_tracing") is not False
    ):
        failures.append("resource_measurement_mode_not_comparable")
    if resources.get("result_count") != records:
        failures.append("resource_result_count_mismatch")
    for field in (
        "records_read",
        "records_staged",
        "records_relayed",
        "records_leased",
        "records_delivered",
        "records_acknowledged",
    ):
        if progress.get(field) != records:
            failures.append(f"progress_{field}_mismatch")
    if progress.get("batches_completed") != expected_batches:
        failures.append("progress_batch_count_mismatch")
    for field in ("destination_rows", "ledger_committed"):
        if final_state.get(field) != records:
            failures.append(f"final_{field}_mismatch")
    for field in ("outbox_depth", "relay_depth", "quarantine_depth", "mismatch_count"):
        if final_state.get(field) != 0:
            failures.append(f"final_{field}_not_zero")
    for field in (
        "content_verified",
        "known_plaintext_canaries_absent",
        "audit_signatures_verified",
    ):
        if final_state.get(field) is not True:
            failures.append(f"final_{field}_false")
    if final_state.get("audit_events") != records:
        failures.append("final_audit_event_count_mismatch")
    for field in (
        "stream_valid",
        "run_closed",
        "workflow_lifecycle_valid",
        "event_ids_unique",
        "event_contract_valid",
        "workflow_counts_valid",
    ):
        if observability.get(field) is not True:
            failures.append(f"observability_{field}_false")

    event_types = _object(observability.get("event_types"), "observability event types")
    if event_types.get("delivery") != records:
        failures.append("observability_delivery_event_count_mismatch")
    expected_batch_events = _expected_atomic_batch_events(records, batch_size)
    if event_types.get("delivery_batch", 0) != expected_batch_events:
        failures.append("observability_delivery_batch_event_count_mismatch")

    raw_stages = workflow.get("stages")
    if not isinstance(raw_stages, list):
        raise ValueError("workflow report stages must be an array")
    stages: dict[str, dict[str, Any]] = {}
    for raw_stage in raw_stages:
        stage = _object(raw_stage, "stage")
        name = stage.get("name")
        if not isinstance(name, str) or not name or name in stages:
            raise ValueError("workflow report stage names must be unique non-empty strings")
        stages[name] = stage
        if stage.get("status") != "passed" or stage.get("reason_code") is not None:
            failures.append(f"stage_{name}_not_passed")
    for name in (
        "source_seal_and_outbox_stage",
        "outbox_reload_and_relay_enqueue",
        "relay_lease",
        "destination_delivery",
        "acknowledgements",
    ):
        required_stage = stages.get(name)
        if required_stage is None:
            failures.append(f"stage_{name}_missing")
            continue
        if required_stage.get("calls") != expected_batches:
            failures.append(f"stage_{name}_call_count_mismatch")
        if required_stage.get("items_processed") != records:
            failures.append(f"stage_{name}_item_count_mismatch")

    durability = _object(final_state.get("sqlite_durability"), "SQLite durability")
    destination_durability = _object(durability.get("destination"), "destination SQLite durability")
    if destination_durability.get("synchronous") != 2:
        failures.append("destination_sqlite_not_full_sync")
    if durability.get("blind_state_synchronous_levels") != [2]:
        failures.append("blind_state_sqlite_not_full_sync")

    if throughput < min_throughput:
        failures.append("throughput_below_floor")
    if throughput <= 0:
        failures.append("throughput_not_positive")
    if wall_ms > max_wall_seconds * 1000:
        failures.append("wall_time_above_ceiling")
    if wall_ms <= 0:
        failures.append("wall_time_not_positive")
    if peak_rss_mib > max_peak_rss_mib:
        failures.append("peak_rss_above_ceiling")
    if peak_rss_mib <= 0:
        failures.append("peak_rss_not_positive")

    return {
        "schema_version": 1,
        "passed": not failures,
        "failures": failures,
        "records": records,
        "batch_size": batch_size,
        "batches": expected_batches,
        "observed": {
            "throughput_per_second": throughput,
            "wall_seconds": wall_ms / 1000,
            "peak_rss_mib": peak_rss_mib,
        },
        "thresholds": {
            "min_throughput_per_second": min_throughput,
            "max_wall_seconds": max_wall_seconds,
            "max_peak_rss_mib": max_peak_rss_mib,
        },
    }


def _positive_number(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be finite and greater than zero")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Gate a retained Polymorph workflow report on integrity and coarse performance."
    )
    parser.add_argument("report", type=Path)
    parser.add_argument("--min-throughput", type=_positive_number, required=True)
    parser.add_argument("--max-wall-seconds", type=_positive_number, required=True)
    parser.add_argument("--max-peak-rss-mib", type=_positive_number, required=True)
    parser.add_argument("--expected-records", type=int)
    parser.add_argument("--expected-batch-size", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        result = evaluate_report(
            load_report(args.report),
            min_throughput=args.min_throughput,
            max_wall_seconds=args.max_wall_seconds,
            max_peak_rss_mib=args.max_peak_rss_mib,
            expected_records=args.expected_records,
            expected_batch_size=args.expected_batch_size,
        )
    except ValueError as exc:
        parser.error(str(exc))
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0 if result["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

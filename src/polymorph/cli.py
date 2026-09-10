from __future__ import annotations

import argparse
import getpass
import importlib.util
import json
import os
import platform
import shutil
import sqlite3
import statistics
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import unquote

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from . import __version__
from .audit import AuditLog
from .benchmark import (
    BenchmarkResult,
    MappingBenchmarkCase,
    benchmark_call,
    benchmark_mapping_cases,
)
from .connectors.base import SourceConnector
from .connectors.csv_file import CsvConnector
from .connectors.database import DatabaseConnector
from .connectors.excel import ExcelConnector
from .connectors.json_file import JsonFileConnector
from .content import ContentInspector, ContentKind, FileInspection, MagikaClassifier
from .diagnostics import explain_reason
from .errors import PolymorphError
from .isolation import (
    IsolatedContentInspection,
    IsolationLevel,
    ParserWorkerClient,
    SandboxError,
    SandboxPolicy,
)
from .keys import EncryptedRecipientKeyFile
from .matching.hybrid import HybridMatcher
from .matching.semantic import (
    MULTILINGUAL_CPU,
    RERANKER_MULTILINGUAL_CPU,
    install_profile,
    load_profile_encoder,
    load_profile_reranker,
    verify_installed_profile,
)
from .models.mapping import MappingDecision
from .models.schema import SchemaDescriptor
from .observability import EventStream
from .paths import model_home, recipe_store_path
from .planning import build_plan
from .preflight import PreflightReport, PreflightRunner
from .recipes import (
    DEFAULT_RECIPE_REJECTION_THRESHOLD,
    RecipeHealth,
    RecipeRunOutcome,
    RecipeStore,
)
from .repair import RepairSeverity, propose_plan_repair
from .serialization import (
    load_plan,
    load_schema,
    plan_to_dict,
    save_plan,
    save_schema,
    schema_from_dict,
    schema_to_dict,
)
from .spool import SealedSpool
from .sqlite_safety import selected_journal_mode, sqlite_wal_is_safe
from .validation import PlanValidator
from .workflow_benchmark import run_workflow_benchmark


def _resolved_file_path(value: str | Path) -> Path:
    try:
        return Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise PolymorphError("could not resolve a CLI file path safely") from exc


def _paths_alias(left: Path, right: Path) -> bool:
    if left == right:
        return True
    try:
        return left.exists() and right.exists() and left.samefile(right)
    except OSError:
        return False


def _protect_write_path(
    output: str | Path | None,
    *protected: str | Path | None,
    label: str = "output",
) -> None:
    if output is None:
        return
    destination = _resolved_file_path(output)
    for candidate in protected:
        if candidate is None:
            continue
        if _paths_alias(destination, _resolved_file_path(candidate)):
            raise PolymorphError(f"{label} path must not overwrite an input or state file")


def _sqlite_database_path(url: str | None) -> str | None:
    if not url:
        return None
    try:
        parsed = make_url(url)
    except ArgumentError:
        return None
    if parsed.get_backend_name() != "sqlite" or not parsed.database:
        return None
    mode = parsed.query.get("mode")
    if parsed.database == ":memory:" or mode == "memory":
        return None
    database = parsed.database
    if str(parsed.query.get("uri", "")).casefold() in {"1", "true", "yes"} and database.startswith(
        "file:"
    ):
        database = unquote(database.removeprefix("file:"))
        if (
            len(database) >= 3
            and database[0] == "/"
            and database[1].isalpha()
            and database[2] == ":"
        ):
            database = database[1:]
    return database


def _emit(payload: object, *, output: str | None = None) -> None:
    text = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True)
    if output:
        path = Path(output).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def _diagnostic_payload(reason_code: str) -> dict[str, str]:
    return explain_reason(reason_code).as_dict()


def _recipe_health_payload(health: RecipeHealth) -> dict[str, object]:
    payload = health.as_dict()
    if health.last_reason_code is not None:
        payload["last_diagnostic"] = _diagnostic_payload(health.last_reason_code)
    return payload


def _recipe_observation(report: PreflightReport) -> tuple[RecipeRunOutcome, str]:
    if report.promotable:
        return RecipeRunOutcome.SUCCESS, "preflight_promotable"
    if not report.valid:
        for finding in report.plan_validation.findings:
            if finding.severity.value == "blocking":
                return RecipeRunOutcome.REJECTED, finding.code
        for preflight_finding in report.findings:
            if preflight_finding.severity.value == "blocking":
                outcome = (
                    RecipeRunOutcome.QUARANTINED
                    if preflight_finding.code
                    in {"foreign_key_lookup_failed", "source_iteration_failed"}
                    else RecipeRunOutcome.REJECTED
                )
                return outcome, preflight_finding.code
        return RecipeRunOutcome.REJECTED, "preflight_not_promotable"
    for finding in report.plan_validation.findings:
        if finding.severity.value == "review":
            return RecipeRunOutcome.QUARANTINED, finding.code
    for preflight_finding in report.findings:
        if preflight_finding.severity.value == "review":
            return RecipeRunOutcome.QUARANTINED, preflight_finding.code
    if not report.complete_scan:
        return RecipeRunOutcome.QUARANTINED, "sampled_scan"
    return RecipeRunOutcome.QUARANTINED, "preflight_not_promotable"


def _emit_schema(schema: SchemaDescriptor, args: argparse.Namespace) -> None:
    if getattr(args, "output", None):
        save_schema(args.output, schema)
    else:
        _emit(schema_to_dict(schema))


def _inspect_excel(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, args.path)
    connector = ExcelConnector(args.path, sheet=args.sheet, header_row=args.header_row)
    _emit_schema(connector.inspect_schema(), args)


def _inspect_csv(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, args.path)
    connector = CsvConnector(args.path, delimiter=args.delimiter, encoding=args.encoding)
    _emit_schema(connector.inspect_schema(), args)


def _inspect_json(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, args.path)
    _emit_schema(JsonFileConnector(args.path).inspect_schema(), args)


def _inspect_db(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, _sqlite_database_path(args.url))
    with DatabaseConnector(args.url, args.table, schema=args.schema) as connector:
        _emit_schema(connector.inspect_schema(), args)


def _matcher(model_dir: str | None, reranker_dir: str | None = None) -> HybridMatcher:
    semantic = None
    reranker = None
    if model_dir:
        semantic = load_profile_encoder(
            MULTILINGUAL_CPU,
            Path(model_dir).expanduser().resolve(),
        )
    if reranker_dir:
        reranker = load_profile_reranker(
            RERANKER_MULTILINGUAL_CPU,
            Path(reranker_dir).expanduser().resolve(),
        )
    return HybridMatcher(semantic=semantic, reranker=reranker)


def _matcher_for_args(args: argparse.Namespace) -> HybridMatcher:
    model_dir = getattr(args, "model_dir", None)
    reranker_dir = getattr(args, "reranker_dir", None)
    if getattr(args, "models", False):
        model_dir = model_dir or str(model_home(MULTILINGUAL_CPU.name))
        reranker_dir = reranker_dir or str(model_home(RERANKER_MULTILINGUAL_CPU.name))
    return _matcher(model_dir, reranker_dir)


def _decision_dict(item: MappingDecision) -> dict[str, object]:
    return {
        "source": item.source_field_id,
        "target": item.target_field_id,
        "status": item.status.value,
        "score": round(item.score, 4),
        "margin": round(item.margin, 4),
        "reasons": list(item.reasons),
    }


def _map(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, args.source, args.target)
    source = load_schema(args.source)
    target = load_schema(args.target)
    decisions = _matcher_for_args(args).propose(source, target)
    _emit([_decision_dict(item) for item in decisions], output=args.output)


def _plan_create(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, args.source, args.target)
    source = load_schema(args.source)
    target = load_schema(args.target)
    decisions = _matcher_for_args(args).propose(source, target)
    plan = build_plan(source, target, decisions, allow_review=args.allow_review)
    if not plan.rules:
        raise SystemExit("no mapping rules passed the requested approval threshold")
    report = PlanValidator().validate(plan, source, target)
    if not report.valid:
        raise SystemExit("generated plan failed validation")
    if report.requires_review and not args.allow_review:
        raise SystemExit(
            "generated plan requires review; rerun with --allow-review after inspection"
        )
    save_plan(args.output, plan)
    _emit(
        {
            "plan": str(Path(args.output).expanduser().resolve()),
            "plan_id": plan.id,
            "version": plan.version,
            "digest": plan.digest(),
            "rules": len(plan.rules),
            "decisions": [_decision_dict(item) for item in decisions],
            "findings": [
                {
                    "severity": item.severity.value,
                    "code": item.code,
                    "message": item.message,
                    "source": item.source_field_id,
                    "target": item.target_field_id,
                }
                for item in report.findings
            ],
        }
    )


def _plan_validate(args: argparse.Namespace) -> None:
    plan = load_plan(args.plan)
    source = load_schema(args.source)
    target = load_schema(args.target)
    report = PlanValidator().validate(plan, source, target)
    _emit(
        {
            "valid": report.valid,
            "requires_review": report.requires_review,
            "plan_id": plan.id,
            "version": plan.version,
            "digest": plan.digest(),
            "findings": [
                {
                    "severity": item.severity.value,
                    "code": item.code,
                    "message": item.message,
                    "source": item.source_field_id,
                    "target": item.target_field_id,
                }
                for item in report.findings
            ],
        }
    )
    if not report.valid:
        raise SystemExit(2)
    if report.requires_review:
        raise SystemExit(3)


def _plan_show(args: argparse.Namespace) -> None:
    plan = load_plan(args.plan)
    _emit(plan_to_dict(plan))


def _plan_repair(args: argparse.Namespace) -> None:
    _protect_write_path(
        args.output,
        args.plan,
        args.old_source,
        args.new_source,
        args.old_target,
        args.new_target,
    )
    plan = load_plan(args.plan)
    proposal = propose_plan_repair(
        plan,
        load_schema(args.old_source),
        load_schema(args.new_source),
        load_schema(args.old_target),
        load_schema(args.new_target),
        _matcher_for_args(args),
    )
    payload: dict[str, object] = {
        "blocked": proposal.blocked,
        "auto_applicable": proposal.auto_applicable,
        "findings": [
            {
                "severity": item.severity.value,
                "side": item.side,
                "field": item.field_id,
                "replacement": item.replacement_field_id,
                "message": item.message,
            }
            for item in proposal.findings
        ],
    }
    if proposal.plan is not None:
        payload["candidate_digest"] = proposal.plan.digest()
        payload["candidate_version"] = proposal.plan.version
        review = any(item.severity is RepairSeverity.REVIEW for item in proposal.findings)
        if not review or args.allow_review:
            save_plan(args.output, proposal.plan)
            payload["saved"] = str(Path(args.output).expanduser().resolve())
    _emit(payload)
    if proposal.blocked:
        raise SystemExit(2)
    if (
        proposal.plan is not None
        and any(item.severity is RepairSeverity.REVIEW for item in proposal.findings)
        and not args.allow_review
    ):
        raise SystemExit(3)


def _model_install(args: argparse.Namespace) -> None:
    profiles = {
        MULTILINGUAL_CPU.name: MULTILINGUAL_CPU,
        RERANKER_MULTILINGUAL_CPU.name: RERANKER_MULTILINGUAL_CPU,
    }
    profile = profiles[args.profile]
    destination = Path(args.destination or model_home(profile.name)).expanduser().resolve()
    model_path = install_profile(profile, destination)
    _emit(
        {
            "profile": profile.name,
            "repo_id": profile.repo_id,
            "revision": profile.revision,
            "model": str(model_path),
        }
    )


def _audit_verify(args: argparse.Namespace) -> None:
    path = Path(args.path).expanduser().resolve()
    if not path.is_file():
        raise PolymorphError(f"audit store does not exist: {path}")
    public_key = bytes.fromhex(args.public_key_hex) if args.public_key_hex else None
    count = AuditLog(path, create=False).verify(trusted_public_key=public_key)
    _emit(
        {
            "valid": True,
            "events": count,
            "verification": "hash_chain_and_signatures" if public_key else "hash_chain_only",
        }
    )


def _audit_summary(args: argparse.Namespace) -> None:
    path = Path(args.path).expanduser().resolve()
    if not path.is_file():
        raise PolymorphError(f"audit store does not exist: {path}")
    public_key = bytes.fromhex(args.public_key_hex) if args.public_key_hex else None
    summary = AuditLog(path, create=False).summary(trusted_public_key=public_key)
    payload = summary.as_dict()
    payload["verification"] = "hash_chain_and_signatures" if public_key else "hash_chain_only"
    payload["reason_diagnostics"] = [
        {"count": count, **_diagnostic_payload(code)} for code, count in summary.reasons.items()
    ]
    _emit(payload)


def _audit_export(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, args.path)
    path = Path(args.path).expanduser().resolve()
    if not path.is_file():
        raise PolymorphError(f"audit store does not exist: {path}")
    text = AuditLog(path, create=False).export_jsonl()
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    _emit({"events_file": str(output)})


def _event_stream_path(value: str) -> Path:
    # Preserve the lexical path so EventStream can reject symlinks instead of following one.
    path = Path(os.path.abspath(Path(value).expanduser()))
    if not path.is_file():
        raise PolymorphError(f"operational event stream does not exist: {path}")
    return path


def _events_summary(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, args.path)
    stream = EventStream(_event_stream_path(args.path))
    summary = stream.summary(run_id=args.run_id)
    payload = summary.as_dict()
    payload["valid"] = True
    payload["verification"] = "structural"
    payload["reason_diagnostics"] = [
        {"count": count, **_diagnostic_payload(code)} for code, count in summary.reasons.items()
    ]
    _emit(payload, output=args.output)


def _events_check(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, args.path)
    stream = EventStream(_event_stream_path(args.path))
    summary = stream.summary(run_id=args.run_id)
    healthy_statuses = {"delivered", "duplicate", "passed", "started"}
    status_counts = {
        status: count
        for status, count in summary.statuses.items()
        if status not in healthy_statuses
    }
    unclosed_run_count = int(summary.events > 0 and summary.workflow_lifecycle_valid is not True)
    health_reasons: list[str] = []
    if not summary.events:
        health_reasons.append("operational_run_not_found")
    if status_counts or summary.reasons:
        health_reasons.append("operational_failure_status_present")
    if unclosed_run_count:
        health_reasons.append("operational_run_not_closed")
    if not summary.event_contract_valid:
        health_reasons.append("operational_event_contract_invalid")
    if summary.workflow_lifecycle_valid is True and summary.workflow_counts_valid is not True:
        health_reasons.append("operational_workflow_count_mismatch")
    healthy = not health_reasons
    _emit(
        {
            "healthy": healthy,
            "valid": True,
            "verification": "structural",
            "run_id": args.run_id,
            "events": summary.events,
            "first_event_type": summary.first_event_type,
            "last_event_type": summary.last_event_type,
            "workflow_lifecycle_valid": summary.workflow_lifecycle_valid,
            "event_ids_unique": summary.event_ids_unique,
            "duplicate_event_ids": summary.duplicate_event_ids,
            "event_contract_valid": summary.event_contract_valid,
            "workflow_counts_valid": summary.workflow_counts_valid,
            "unhealthy_statuses": status_counts,
            "unclosed_run_count": unclosed_run_count,
            "health_reasons": health_reasons,
            "health_diagnostics": [_diagnostic_payload(code) for code in health_reasons],
            "reason_counts": summary.reasons,
            "reason_diagnostics": [
                {"count": count, **_diagnostic_payload(code)}
                for code, count in summary.reasons.items()
            ],
        },
        output=args.output,
    )
    if not healthy:
        raise SystemExit(10)


def _quarantine_list(args: argparse.Namespace) -> None:
    entries = SealedSpool(args.path).list_entries(limit=args.limit)
    _emit(
        [
            {
                "record_digest": item.record_digest,
                "tenant": item.tenant,
                "destination_connector": item.destination_connector,
                "transfer_id": item.transfer_id,
                "record_id": item.record_id,
                "plan_digest": item.plan_digest,
                "reason_code": item.reason_code,
                "diagnostic": _diagnostic_payload(item.reason_code),
                "quarantined_at": item.quarantined_at,
            }
            for item in entries
        ]
    )


def _explain(args: argparse.Namespace) -> None:
    _emit(_diagnostic_payload(args.reason_code))


def _key_generate(args: argparse.Namespace) -> None:
    first = getpass.getpass("Key passphrase: ")
    second = getpass.getpass("Repeat passphrase: ")
    if first != second:
        raise SystemExit("passphrases do not match")
    public = EncryptedRecipientKeyFile.create(args.output, first)
    _emit(
        {
            "key_file": str(Path(args.output).expanduser().resolve()),
            "public_key_hex": public.hex(),
        }
    )


def _key_public(args: argparse.Namespace) -> None:
    public = EncryptedRecipientKeyFile.public_key(args.path)
    _emit({"public_key_hex": public.hex()})


def _key_validate(args: argparse.Namespace) -> None:
    passphrase = getpass.getpass("Key passphrase: ")
    public = EncryptedRecipientKeyFile.validate(args.path, passphrase)
    _emit({"valid": True, "public_key_hex": public.hex()})


def _inspector(use_magika: bool) -> ContentInspector:
    classifier = MagikaClassifier() if use_magika else None
    return ContentInspector(classifier=classifier)


def _connector_for_inspection(path: str, report: FileInspection) -> SourceConnector | None:
    if report.kind is ContentKind.XLSX:
        return ExcelConnector(path, expected_source_identity=report.identity)
    if report.kind in {ContentKind.JSON, ContentKind.JSON5}:
        return JsonFileConnector(path, expected_source_identity=report.identity)
    if report.kind is ContentKind.DELIMITED_TEXT:
        return CsvConnector(path, expected_source_identity=report.identity)
    if report.kind is ContentKind.TEXT and any(
        signal.startswith("JSON-like") for signal in report.signals
    ):
        return JsonFileConnector(path, expected_source_identity=report.identity)
    return None


def _auto_source(
    path: str,
    *,
    use_magika: bool = False,
) -> tuple[FileInspection, SourceConnector | None]:
    report = _inspector(use_magika).inspect(path)
    if not report.safe:
        codes = ", ".join(item.code.value for item in report.blocking_risks)
        raise PolymorphError(f"input was rejected by the content trust gate: {codes}")
    return report, _connector_for_inspection(path, report)


def _inspect_auto(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, args.path)
    report, connector = _auto_source(args.path, use_magika=args.magika)
    payload: dict[str, object] = {"content": report.as_dict(), "schema": None}
    if connector is not None:
        payload["schema"] = schema_to_dict(connector.inspect_schema())
    _emit(payload, output=args.output)


_CONTAINMENT_LEVELS = {
    "process": IsolationLevel.PROCESS,
    "resource-limited": IsolationLevel.RESOURCE_LIMITED_PROCESS,
    "os-sandbox": IsolationLevel.OS_SANDBOX,
}


def _parser_worker_policy(args: argparse.Namespace) -> SandboxPolicy:
    max_input_mib = args.max_input_mib
    if isinstance(max_input_mib, bool) or not isinstance(max_input_mib, int):
        raise ValueError("--max-input-mib must be an integer")
    if not 1 <= max_input_mib <= 1024 * 1024:
        raise ValueError("--max-input-mib must be between 1 and 1048576")
    return SandboxPolicy(
        minimum_level=_CONTAINMENT_LEVELS[args.require_containment],
        wall_timeout_seconds=args.timeout,
        max_input_bytes=max_input_mib * 1024 * 1024,
    )


def _isolated_content_payload(result: IsolatedContentInspection) -> dict[str, object]:
    return {
        "content": result.inspection,
        "worker": {
            "scope": "content_inspection_only",
            "structured_parsers_isolated": False,
            "success": True,
            "request_id": result.request_id,
            "backend": result.backend,
            "isolation_level": result.isolation_level.name.lower(),
            "os_sandboxed": result.os_sandboxed,
            "capabilities": list(result.backend_capabilities),
            "snapshot": {
                "sha256": result.snapshot_sha256,
                "size_bytes": result.snapshot_size_bytes,
            },
            "timing_ms": {
                "snapshot": result.snapshot_duration_seconds * 1000,
                "worker": result.worker_duration_seconds * 1000,
                "end_to_end": result.end_to_end_duration_seconds * 1000,
            },
            "protocol_output_bytes": {
                "stdout": result.stdout_bytes,
                "stderr": result.stderr_bytes,
            },
        },
    }


def _parser_worker_failure_payload(error: SandboxError) -> dict[str, object]:
    return {
        "reason_code": error.code.value,
        "message": str(error),
        "worker_error_code": error.worker_error_code,
        "stderr_sha256": error.stderr_digest,
        "diagnostic": _diagnostic_payload(error.code.value),
    }


def _inspect_isolated_content(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, args.path)
    client = ParserWorkerClient(_parser_worker_policy(args), backend=args.backend)
    try:
        result = client.inspect_content(args.path, use_magika=args.magika)
    except SandboxError as exc:
        if args.output:
            _emit(
                {
                    "content": None,
                    "worker": {
                        "scope": "content_inspection_only",
                        "structured_parsers_isolated": False,
                        "success": False,
                        "failure": _parser_worker_failure_payload(exc),
                    },
                },
                output=args.output,
            )
        raise
    _emit(_isolated_content_payload(result), output=args.output)


def _resolver_from_args(args: argparse.Namespace) -> DatabaseConnector | None:
    resolver_db_url = getattr(args, "resolver_db_url", None)
    if not resolver_db_url:
        return None
    resolver_db_table = getattr(args, "resolver_db_table", None)
    if not resolver_db_table:
        raise PolymorphError("--resolver-db-table is required with --resolver-db-url")
    return DatabaseConnector(
        resolver_db_url,
        resolver_db_table,
        schema=getattr(args, "resolver_db_schema", None),
    )


def _preflight_file(args: argparse.Namespace) -> None:
    resolver_path = _sqlite_database_path(args.resolver_db_url)
    _protect_write_path(
        args.output,
        args.source,
        args.target_schema,
        args.plan,
        resolver_path,
        args.recipe_store if args.remember else None,
    )
    if args.remember:
        _protect_write_path(
            args.recipe_store,
            args.source,
            args.target_schema,
            args.plan,
            resolver_path,
            label="recipe store",
        )
    content, connector = _auto_source(args.source, use_magika=args.magika)
    if connector is None:
        raise PolymorphError(
            f"no structured source connector is available for detected content {content.kind.value}"
        )
    source = connector.inspect_schema()
    target = load_schema(args.target_schema)
    plan = load_plan(args.plan)
    resolver = _resolver_from_args(args)
    try:
        report = PreflightRunner().run(
            connector.iter_records(),
            source,
            target,
            plan,
            max_records=args.max_records,
            foreign_key_resolver=resolver,
        )
    finally:
        if resolver is not None:
            resolver.close()
    payload = {"content": content.as_dict(), "preflight": report.as_dict()}
    if args.remember:
        if not report.promotable:
            payload["recipe"] = {
                "remembered": False,
                "reason": "preflight_not_promotable",
                "diagnostic": _diagnostic_payload("preflight_not_promotable"),
            }
        else:
            store = RecipeStore(args.recipe_store)
            recipe = store.remember(plan, source, target, approved_by=args.approved_by)
            store.record_run(
                recipe,
                plan,
                RecipeRunOutcome.SUCCESS,
                reason_code="preflight_promotable",
            )
            payload["recipe"] = {
                "remembered": True,
                "id": recipe.id,
                "version": recipe.version,
                "store": str(Path(args.recipe_store).expanduser().resolve()),
                "health": _recipe_health_payload(store.health(recipe)),
            }
    _emit(payload, output=args.output)
    if not report.valid:
        raise SystemExit(2)
    if report.requires_review or not report.promotable:
        raise SystemExit(3)


def _prepare(args: argparse.Namespace) -> None:
    """One-command, no-write readiness workflow for a file-to-schema route."""

    if args.recipe_rejection_threshold < 1:
        raise ValueError("recipe rejection threshold must be at least one")
    resolver_path = _sqlite_database_path(args.resolver_db_url)
    _protect_write_path(
        args.recipe_store,
        args.source,
        args.target_schema,
        resolver_path,
        args.output,
        args.output_plan,
        label="recipe store",
    )
    _protect_write_path(
        args.output_plan,
        args.source,
        args.target_schema,
        resolver_path,
        args.recipe_store,
        args.output,
        label="plan output",
    )
    _protect_write_path(
        args.output,
        args.source,
        args.target_schema,
        resolver_path,
        args.recipe_store,
        args.output_plan,
    )
    content, connector = _auto_source(args.source, use_magika=args.magika)
    if connector is None:
        raise PolymorphError(
            f"no structured source connector is available for detected content {content.kind.value}"
        )
    source = connector.inspect_schema()
    target = load_schema(args.target_schema)
    store = RecipeStore(args.recipe_store)
    candidate = store.find(source, target)
    recipe = None
    candidate_health: RecipeHealth | None = None
    active_health: RecipeHealth | None = None
    adaptation_code: str | None = None
    adaptation_event_recorded = False
    preflight_event_recorded = False
    decisions = None
    route_source = "fresh_mapping"
    if candidate is not None:
        candidate_health = store.health(
            candidate,
            rejection_threshold=args.recipe_rejection_threshold,
        )
        if not candidate_health.auto_reuse_allowed:
            adaptation_code = "recipe_auto_reuse_suspended"
        else:
            try:
                plan = candidate.rebind(source, target)
            except PolymorphError:
                store.record_run(
                    candidate,
                    candidate.plan,
                    RecipeRunOutcome.REJECTED,
                    reason_code="recipe_rebind_failed",
                )
                adaptation_event_recorded = True
                candidate_health = store.health(
                    candidate,
                    rejection_threshold=args.recipe_rejection_threshold,
                )
                adaptation_code = "recipe_rebind_failed"
            else:
                recipe = candidate
                route_source = "recipe"
    if recipe is None:
        decisions = _matcher_for_args(args).propose(source, target)
        plan = build_plan(source, target, decisions, allow_review=False)

    if not plan.rules:
        if recipe is not None:
            store.record_run(
                recipe,
                plan,
                RecipeRunOutcome.REJECTED,
                reason_code="no_auto_approved_mapping_rules",
            )
            preflight_event_recorded = True
            active_health = store.health(
                recipe,
                rejection_threshold=args.recipe_rejection_threshold,
            )
        payload = {
            "ready": False,
            "content": content.as_dict(),
            "route_source": route_source,
            "reason": "no_auto_approved_mapping_rules",
            "diagnostic": _diagnostic_payload("no_auto_approved_mapping_rules"),
            "decisions": [_decision_dict(item) for item in decisions or []],
            "recipe_monitoring": {
                "candidate_id": candidate.id if candidate is not None else None,
                "used": recipe is not None,
                "adaptation": (
                    _diagnostic_payload(adaptation_code) if adaptation_code is not None else None
                ),
                "events_recorded": {
                    "adaptation": adaptation_event_recorded,
                    "preflight": preflight_event_recorded,
                },
                "candidate_health": (
                    _recipe_health_payload(candidate_health)
                    if candidate_health is not None
                    else None
                ),
                "active_health": (
                    _recipe_health_payload(active_health) if active_health is not None else None
                ),
            },
        }
        _emit(payload, output=args.output)
        raise SystemExit(3)

    resolver = _resolver_from_args(args)
    try:
        report = PreflightRunner().run(
            connector.iter_records(),
            source,
            target,
            plan,
            max_records=args.max_records,
            foreign_key_resolver=resolver,
        )
    finally:
        if resolver is not None:
            resolver.close()
    ready = report.promotable
    observation_outcome, observation_reason = _recipe_observation(report)
    remembered = False
    remembered_recipe_id = recipe.id if recipe is not None else None
    if recipe is not None:
        store.record_run(
            recipe,
            plan,
            observation_outcome,
            reason_code=observation_reason,
        )
        preflight_event_recorded = True
        active_health = store.health(
            recipe,
            rejection_threshold=args.recipe_rejection_threshold,
        )
        candidate_health = active_health
    if ready and recipe is None and args.remember:
        remembered_recipe = store.remember(plan, source, target, approved_by=args.approved_by)
        store.record_run(
            remembered_recipe,
            plan,
            RecipeRunOutcome.SUCCESS,
            reason_code="preflight_promotable",
        )
        preflight_event_recorded = True
        remembered = True
        remembered_recipe_id = remembered_recipe.id
        active_health = store.health(
            remembered_recipe,
            rejection_threshold=args.recipe_rejection_threshold,
        )

    saved_plan = None
    if ready and args.output_plan:
        save_plan(args.output_plan, plan)
        saved_plan = str(Path(args.output_plan).expanduser().resolve())

    payload = {
        "ready": ready,
        "content": content.as_dict(),
        "route_source": route_source,
        "recipe_id": remembered_recipe_id,
        "recipe_remembered": remembered,
        "plan": {
            "id": plan.id,
            "version": plan.version,
            "digest": plan.digest(),
            "rules": len(plan.rules),
            "saved": saved_plan,
        },
        "decisions": [_decision_dict(item) for item in decisions or []],
        "preflight": report.as_dict(),
        "recipe_monitoring": {
            "candidate_id": candidate.id if candidate is not None else None,
            "used": recipe is not None,
            "events_recorded": {
                "adaptation": adaptation_event_recorded,
                "preflight": preflight_event_recorded,
            },
            "preflight_outcome": observation_outcome.value,
            "preflight_reason": observation_reason,
            "preflight_diagnostic": _diagnostic_payload(observation_reason),
            "adaptation": (
                _diagnostic_payload(adaptation_code) if adaptation_code is not None else None
            ),
            "candidate_health": (
                _recipe_health_payload(candidate_health) if candidate_health is not None else None
            ),
            "active_health": (
                _recipe_health_payload(active_health) if active_health is not None else None
            ),
        },
    }
    _emit(payload, output=args.output)
    if not report.valid:
        raise SystemExit(2)
    if not ready:
        raise SystemExit(3)


def _recipe_remember(args: argparse.Namespace) -> None:
    _protect_write_path(
        args.store,
        args.plan,
        args.source_schema,
        args.target_schema,
        label="recipe store",
    )
    source = load_schema(args.source_schema)
    target = load_schema(args.target_schema)
    recipe = RecipeStore(args.store).remember(
        load_plan(args.plan), source, target, approved_by=args.approved_by
    )
    _emit(
        {
            "id": recipe.id,
            "version": recipe.version,
            "source_structural_fingerprint": recipe.source_structural_fingerprint,
            "target_structural_fingerprint": recipe.target_structural_fingerprint,
            "store": str(Path(args.store).expanduser().resolve()),
        }
    )


def _recipe_list(args: argparse.Namespace) -> None:
    store = RecipeStore(args.store)
    recipes = store.list(limit=args.limit)
    _emit(
        [
            {
                "id": recipe.id,
                "version": recipe.version,
                "plan_digest": recipe.plan.digest(),
                "source_structural_fingerprint": recipe.source_structural_fingerprint,
                "target_structural_fingerprint": recipe.target_structural_fingerprint,
                "approved_by": recipe.approved_by,
                "created_at": recipe.created_at.isoformat(),
                "health": _recipe_health_payload(store.health(recipe)),
            }
            for recipe in recipes
        ]
    )


def _recipe_health(args: argparse.Namespace) -> None:
    if args.rejection_threshold < 1:
        raise ValueError("recipe rejection threshold must be at least one")
    store = RecipeStore(args.store)
    if args.recipe_id is not None:
        recipe = store.get(args.recipe_id)
        if recipe is None:
            _emit({"found": False, "recipe_id": args.recipe_id})
            raise SystemExit(4)
        recipes = [recipe]
    else:
        recipes = store.list(limit=args.limit)
    _emit(
        {
            "rejection_threshold": args.rejection_threshold,
            "recipes": [
                {
                    "id": recipe.id,
                    "version": recipe.version,
                    "plan_digest": recipe.plan.digest(),
                    "health": _recipe_health_payload(
                        store.health(
                            recipe,
                            rejection_threshold=args.rejection_threshold,
                        )
                    ),
                }
                for recipe in recipes
            ],
        }
    )


def _recipe_find(args: argparse.Namespace) -> None:
    _protect_write_path(
        args.store,
        args.source_schema,
        args.target_schema,
        args.output_plan,
        label="recipe store",
    )
    _protect_write_path(
        args.output_plan,
        args.source_schema,
        args.target_schema,
        args.store,
        label="plan output",
    )
    source = load_schema(args.source_schema)
    target = load_schema(args.target_schema)
    store = RecipeStore(args.store)
    recipe = store.find(source, target)
    if recipe is None:
        _emit({"found": False})
        raise SystemExit(4)
    health = store.health(recipe, rejection_threshold=args.rejection_threshold)
    plan = recipe.rebind(source, target)
    if args.output_plan:
        save_plan(args.output_plan, plan)
    _emit(
        {
            "found": True,
            "recipe_id": recipe.id,
            "recipe_version": recipe.version,
            "automatic_reuse_allowed": health.auto_reuse_allowed,
            "health": _recipe_health_payload(health),
            "rebound_plan_id": plan.id,
            "rebound_plan_digest": plan.digest(),
            "output_plan": str(Path(args.output_plan).expanduser().resolve())
            if args.output_plan
            else None,
        }
    )


def _excel_xml_hardening_status() -> dict[str, object]:
    try:
        import openpyxl
    except ImportError:
        return {"available": False, "enabled": False}
    return {
        "available": importlib.util.find_spec("defusedxml") is not None,
        "enabled": bool(getattr(openpyxl, "DEFUSEDXML", False)),
    }


def _parser_worker_status() -> dict[str, object]:
    policy = SandboxPolicy()
    backends = ParserWorkerClient(policy).backend_info()
    return {
        "implemented": True,
        "scope": "content_inspection_only",
        "structured_parsers_isolated": False,
        "default_minimum_level": policy.minimum_level.name.lower(),
        "backends": [
            {
                "name": backend.name,
                "level": backend.level.name.lower(),
                "available": backend.available,
                "capabilities": list(backend.capabilities),
                "reason": backend.reason,
            }
            for backend in backends
        ],
    }


def _doctor(args: argparse.Namespace) -> None:
    optional = {
        "magika": importlib.util.find_spec("magika") is not None,
        "clevercsv": importlib.util.find_spec("clevercsv") is not None,
        "onnxruntime": importlib.util.find_spec("onnxruntime") is not None,
        "sentencepiece": importlib.util.find_spec("sentencepiece") is not None,
        "keyring": importlib.util.find_spec("keyring") is not None,
    }
    models: dict[str, object] = {}
    for profile in (MULTILINGUAL_CPU, RERANKER_MULTILINGUAL_CPU):
        location = model_home(profile.name)
        if not location.exists():
            models[profile.name] = {"installed": False, "path": str(location)}
            continue
        try:
            model_path = verify_installed_profile(profile, location)
        except PolymorphError as exc:
            models[profile.name] = {
                "installed": True,
                "valid": False,
                "path": str(location),
                "error": str(exc),
            }
        else:
            models[profile.name] = {
                "installed": True,
                "valid": True,
                "path": str(model_path),
            }
    _emit(
        {
            "version": __version__,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "content_trust_gate": True,
            "excel_xml_hardening": _excel_xml_hardening_status(),
            "preflight_contract_sandbox": True,
            "operational_visibility": {
                "destination_receipt_audit": "optional",
                "audit_event_types": ["delivery", "replay", "force_replay"],
                "recipe_outcomes_recorded_by_prepare": True,
                "recipe_rejection_threshold": DEFAULT_RECIPE_REJECTION_THRESHOLD,
                "adaptive_recipe_guard": True,
                "local_operational_event_stream": True,
                "operational_run_and_correlation_ids": True,
                "operational_health_gate": True,
                "complete_event_stream": False,
                "alerting_service": False,
            },
            "sqlite": {
                "version": sqlite3.sqlite_version,
                "journal_mode": selected_journal_mode(),
                "wal_reset_fix_present": sqlite_wal_is_safe(),
            },
            "parser_os_sandbox": {
                "bubblewrap": shutil.which("bwrap") is not None,
                "firejail": shutil.which("firejail") is not None,
                "note": "binary presence only; see parser_worker for active capabilities",
            },
            "parser_worker": _parser_worker_status(),
            "optional": optional,
            "models": models,
            "recipe_store": str(recipe_store_path()),
        }
    )


def _benchmark_inspect(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, args.path)
    report, content_metrics = benchmark_call(
        "content_inspection",
        lambda: _inspector(args.magika).inspect(args.path),
        trace_python_allocations=args.tracemalloc,
    )
    metric_payloads = [_benchmark_resource_payload(content_metrics)]
    payload: dict[str, object] = {
        "content": report.as_dict(),
        "measurement": _benchmark_measurement_payload(args.tracemalloc),
        "metrics": metric_payloads,
    }
    if report.safe:
        connector = _connector_for_inspection(args.path, report)
        if connector is not None:
            schema, schema_metrics = benchmark_call(
                "schema_inspection",
                connector.inspect_schema,
                trace_python_allocations=args.tracemalloc,
            )
            payload["schema"] = schema_to_dict(schema)
            metric_payloads.append(_benchmark_resource_payload(schema_metrics))
            if args.records > 0:

                def read_records() -> list[Mapping[str, object]]:
                    rows = []
                    for index, record in enumerate(connector.iter_records()):
                        if index >= args.records:
                            break
                        rows.append(record)
                    return rows

                _, records_metrics = benchmark_call(
                    "record_read",
                    read_records,
                    result_count=len,
                    trace_python_allocations=args.tracemalloc,
                )
                metric_payloads.append(_benchmark_resource_payload(records_metrics))
    _emit(payload, output=args.output)


def _measurement_percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] * (upper - rank) + ordered[upper] * (rank - lower)


def _timing_summary(values: list[float]) -> dict[str, float]:
    return {
        "min": min(values, default=0.0),
        "p50": statistics.median(values) if values else 0.0,
        "p95": _measurement_percentile(values, 0.95),
        "max": max(values, default=0.0),
    }


def _benchmark_parser_worker(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, args.path)
    if isinstance(args.runs, bool) or not 1 <= args.runs <= 100:
        raise ValueError("--runs must be between 1 and 100")
    policy = _parser_worker_policy(args)
    client = ParserWorkerClient(policy, backend=args.backend, observe_resources=True)
    results = []
    elapsed_ms: list[float] = []
    for run_index in range(1, args.runs + 1):
        started = time.perf_counter()
        try:
            results.append(client.inspect_content(args.path, use_magika=args.magika))
        except SandboxError as exc:
            failed_elapsed_ms = (time.perf_counter() - started) * 1000
            _emit(
                {
                    "scope": "content_inspection_only",
                    "structured_parsers_isolated": False,
                    "success": False,
                    "requested_runs": args.runs,
                    "completed_runs": len(results),
                    "failed_run": run_index,
                    "backend_requested": args.backend,
                    "minimum_containment": policy.minimum_level.name.lower(),
                    "failure": _parser_worker_failure_payload(exc),
                    "timing_ms": {
                        "completed_end_to_end": _timing_summary(elapsed_ms),
                        "failed_end_to_end": failed_elapsed_ms,
                    },
                },
                output=args.output,
            )
            raise
        elapsed_ms.append(results[-1].end_to_end_duration_seconds * 1000)

    first = results[0]
    canonical_inspection = json.dumps(
        first.inspection,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if any(
        result.snapshot_sha256 != first.snapshot_sha256
        or result.snapshot_size_bytes != first.snapshot_size_bytes
        or json.dumps(
            result.inspection,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        != canonical_inspection
        for result in results[1:]
    ):
        raise PolymorphError("parser-worker benchmark produced inconsistent snapshots or results")

    snapshot_ms = [result.snapshot_duration_seconds * 1000 for result in results]
    worker_ms = [result.worker_duration_seconds * 1000 for result in results]
    measured_rss = [
        result.child_peak_rss_bytes for result in results if result.child_peak_rss_bytes is not None
    ]
    measured_cpu = [
        result.child_cpu_seconds for result in results if result.child_cpu_seconds is not None
    ]
    measured_reads = [
        result.child_read_bytes for result in results if result.child_read_bytes is not None
    ]
    measured_writes = [
        result.child_write_bytes for result in results if result.child_write_bytes is not None
    ]
    median_elapsed = statistics.median(elapsed_ms)
    input_mib = first.snapshot_size_bytes / (1024 * 1024)
    throughput = input_mib / (median_elapsed / 1000) if median_elapsed > 0 else 0.0
    _emit(
        {
            "scope": "content_inspection_only",
            "structured_parsers_isolated": False,
            "success": True,
            "runs": args.runs,
            "consistent": True,
            "backend": first.backend,
            "isolation_level": first.isolation_level.name.lower(),
            "os_sandboxed": first.os_sandboxed,
            "capabilities": list(first.backend_capabilities),
            "snapshot": {
                "sha256": first.snapshot_sha256,
                "size_bytes": first.snapshot_size_bytes,
            },
            "content_kind": first.inspection["kind"],
            "timing_ms": {
                "snapshot": _timing_summary(snapshot_ms),
                "worker": _timing_summary(worker_ms),
                "end_to_end": _timing_summary(elapsed_ms),
                "cold_end_to_end": elapsed_ms[0],
                "warm_end_to_end": (
                    _timing_summary(elapsed_ms[1:]) if len(elapsed_ms) > 1 else None
                ),
            },
            "throughput_mib_per_second_at_p50": throughput,
            "protocol_output_bytes": {
                "stdout_max": max(result.stdout_bytes for result in results),
                "stderr_max": max(result.stderr_bytes for result in results),
            },
            "limits": {
                "wall_timeout_seconds": policy.wall_timeout_seconds,
                "cpu_seconds": policy.cpu_seconds,
                "max_memory_bytes": policy.max_memory_bytes,
                "max_input_bytes": policy.max_input_bytes,
                "max_stdout_bytes": policy.max_stdout_bytes,
                "max_stderr_bytes": policy.max_stderr_bytes,
                "max_open_files": policy.max_open_files,
                "max_processes": policy.max_processes,
                "max_output_file_bytes": policy.max_output_file_bytes,
                "max_parser_log_bytes": policy.max_parser_log_bytes,
                "max_tmpfs_bytes": policy.max_tmpfs_bytes,
            },
            "child_peak_rss_bytes": max(measured_rss, default=None),
            "child_cpu_seconds_max": max(measured_cpu, default=None),
            "child_read_bytes_max": max(measured_reads, default=None),
            "child_write_bytes_max": max(measured_writes, default=None),
            "resource_observation": {
                "mode": (
                    "sampled_process_tree"
                    if any(result.resource_sample_count for result in results)
                    else "unavailable"
                ),
                "observer_effect": True,
                "poll_interval_ms": 5.0,
                "successful_sample_count": sum(result.resource_sample_count for result in results),
                "runs_with_samples": sum(result.resource_sample_count > 0 for result in results),
            },
            "measurement_note": (
                "Every sample includes a fresh snapshot and worker. The cold sample also "
                "includes backend selection and its cached compatibility probe. Child and "
                "descendant RSS, CPU and I/O are sampled only in benchmark mode when psutil "
                "is available; fast process exits can make these conservative observations."
            ),
            "samples": [
                {
                    "temperature": "cold" if index == 0 else "warm_backend_probe_cache",
                    "end_to_end_ms": elapsed,
                    "snapshot_ms": result.snapshot_duration_seconds * 1000,
                    "worker_ms": result.worker_duration_seconds * 1000,
                    "stdout_bytes": result.stdout_bytes,
                    "stderr_bytes": result.stderr_bytes,
                    "resource_measurement": result.resource_measurement,
                    "resource_sample_count": result.resource_sample_count,
                    "child_peak_rss_bytes": result.child_peak_rss_bytes,
                    "child_cpu_seconds": result.child_cpu_seconds,
                    "child_read_bytes": result.child_read_bytes,
                    "child_write_bytes": result.child_write_bytes,
                }
                for index, (elapsed, result) in enumerate(zip(elapsed_ms, results, strict=True))
            ],
        },
        output=args.output,
    )


def _benchmark_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise PolymorphError("mapping benchmark manifest contains a duplicate JSON key")
        payload[key] = value
    return payload


def _reject_benchmark_json_constant(value: str) -> object:
    raise PolymorphError(f"mapping benchmark manifest contains non-finite JSON: {value}")


def _reject_unknown_keys(
    payload: Mapping[str, object], allowed: frozenset[str], label: str
) -> None:
    unknown = set(payload) - allowed
    if unknown:
        raise PolymorphError(f"{label} contains unknown fields: {', '.join(sorted(unknown))}")


def _validate_benchmark_schema_shape(payload: Mapping[str, object], label: str) -> None:
    _reject_unknown_keys(payload, frozenset({"id", "fields", "relations", "metadata"}), label)
    fields = payload.get("fields")
    if isinstance(fields, list):
        allowed_field_keys = frozenset(
            {
                "id",
                "name",
                "data_type",
                "nullable",
                "destination_generated",
                "sensitivity",
                "role",
                "description",
                "aliases",
                "container",
            }
        )
        for field_index, field in enumerate(fields, start=1):
            if isinstance(field, dict):
                _reject_unknown_keys(field, allowed_field_keys, f"{label} field {field_index}")
    relations = payload.get("relations", [])
    if isinstance(relations, list):
        allowed_relation_keys = frozenset(
            {
                "source_field_id",
                "target_container",
                "target_field",
                "name",
                "target_schema",
                "lookup_keys",
            }
        )
        for relation_index, relation in enumerate(relations, start=1):
            if isinstance(relation, dict):
                _reject_unknown_keys(
                    relation,
                    allowed_relation_keys,
                    f"{label} relation {relation_index}",
                )
                lookup_keys = relation.get("lookup_keys", [])
                if isinstance(lookup_keys, list):
                    for key_index, key in enumerate(lookup_keys, start=1):
                        if isinstance(key, dict):
                            _reject_unknown_keys(
                                key,
                                frozenset({"name", "data_type"}),
                                (f"{label} relation {relation_index} lookup key {key_index}"),
                            )


def _benchmark_mapping(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, args.manifest)
    if args.require_auto_precision is not None and not 0.0 <= args.require_auto_precision <= 1.0:
        raise ValueError("required auto precision must be between zero and one")
    if (
        args.require_automation_coverage is not None
        and not 0.0 <= args.require_automation_coverage <= 1.0
    ):
        raise ValueError("required automation coverage must be between zero and one")
    if (
        args.require_suggestion_accuracy is not None
        and not 0.0 <= args.require_suggestion_accuracy <= 1.0
    ):
        raise ValueError("required suggestion accuracy must be between zero and one")
    if args.max_unsafe_auto < 0:
        raise ValueError("maximum unsafe automatic decisions must not be negative")
    manifest_path = Path(args.manifest).expanduser().resolve()
    try:
        payload = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_benchmark_json_object,
            parse_constant=_reject_benchmark_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolymorphError("mapping benchmark manifest is not valid UTF-8 JSON") from exc
    if (
        not isinstance(payload, dict)
        or isinstance(payload.get("version"), bool)
        or payload.get("version") != 1
    ):
        raise PolymorphError("mapping benchmark manifest must be an object with version 1")
    _reject_unknown_keys(
        payload,
        frozenset({"version", "description", "provenance", "cases"}),
        "mapping benchmark manifest",
    )
    description = payload.get("description")
    if description is not None and (
        not isinstance(description, str) or not description.strip() or len(description) > 4096
    ):
        raise PolymorphError("mapping benchmark manifest description is invalid")
    provenance = payload.get("provenance")
    if provenance is not None:
        if not isinstance(provenance, dict):
            raise PolymorphError("mapping benchmark manifest provenance must be an object")
        _reject_unknown_keys(
            provenance,
            frozenset(
                {
                    "kind",
                    "contains_customer_data",
                    "suitable_for_accuracy_marketing",
                }
            ),
            "mapping benchmark provenance",
        )
        kind = provenance.get("kind")
        if kind is not None and (not isinstance(kind, str) or not kind.strip() or len(kind) > 512):
            raise PolymorphError("mapping benchmark provenance kind is invalid")
        for flag in ("contains_customer_data", "suitable_for_accuracy_marketing"):
            if flag in provenance and not isinstance(provenance[flag], bool):
                raise PolymorphError(f"mapping benchmark provenance {flag} must be boolean")
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise PolymorphError("mapping benchmark manifest must contain at least one case")

    cases: list[MappingBenchmarkCase] = []
    case_ids: set[str] = set()
    for index, raw in enumerate(raw_cases, start=1):
        if not isinstance(raw, dict):
            raise PolymorphError(f"benchmark case {index} must be an object")
        _reject_unknown_keys(
            raw,
            frozenset({"id", "source_schema", "target_schema", "expected", "review_only"}),
            f"benchmark case {index}",
        )
        source_payload = raw.get("source_schema")
        target_payload = raw.get("target_schema")
        expected_payload = raw.get("expected")
        if not isinstance(source_payload, dict) or not isinstance(target_payload, dict):
            raise PolymorphError(
                f"benchmark case {index} must contain inline source/target schemas"
            )
        _validate_benchmark_schema_shape(source_payload, f"benchmark case {index} source schema")
        _validate_benchmark_schema_shape(target_payload, f"benchmark case {index} target schema")
        if not isinstance(expected_payload, dict) or not expected_payload:
            raise PolymorphError(f"benchmark case {index} must contain expected mappings")
        expected: dict[str, str | None] = {}
        for source_id, target_id in expected_payload.items():
            if target_id is not None and not isinstance(target_id, str):
                raise PolymorphError(f"benchmark case {index} has an invalid expected target")
            expected[str(source_id)] = target_id
        case_id_value = raw.get("id")
        if (
            not isinstance(case_id_value, str)
            or not case_id_value.strip()
            or "\x00" in case_id_value
            or len(case_id_value) > 256
        ):
            raise PolymorphError(f"benchmark case {index} has an invalid id")
        case_id = case_id_value
        if case_id in case_ids:
            raise PolymorphError("mapping benchmark case ids must be unique")
        case_ids.add(case_id)
        source_schema = schema_from_dict(source_payload)
        target_schema = schema_from_dict(target_payload)
        source_ids = {field.id for field in source_schema.fields}
        if set(expected) != source_ids:
            raise PolymorphError(
                f"benchmark case {index} must label every source field exactly once"
            )
        target_ids = {field.id for field in target_schema.fields}
        if any(
            target_id is not None and target_id not in target_ids for target_id in expected.values()
        ):
            raise PolymorphError(f"benchmark case {index} references an unknown target field")
        review_only_payload = raw.get("review_only", [])
        if (
            not isinstance(review_only_payload, list)
            or any(not isinstance(item, str) for item in review_only_payload)
            or len(set(review_only_payload)) != len(review_only_payload)
        ):
            raise PolymorphError(f"benchmark case {index} has invalid review-only labels")
        review_only = frozenset(review_only_payload)
        if not review_only <= source_ids:
            raise PolymorphError(f"benchmark case {index} reviews an unknown source field")
        if any(expected[source_id] is None for source_id in review_only):
            raise PolymorphError(
                f"benchmark case {index} review-only fields must have an expected target"
            )
        cases.append(
            MappingBenchmarkCase(
                id=case_id,
                source_schema=source_schema,
                target_schema=target_schema,
                expected=expected,
                review_only=review_only,
            )
        )

    matcher = _matcher_for_args(args)
    report, metrics = benchmark_call(
        "mapping_corpus",
        lambda: benchmark_mapping_cases(cases, matcher),
        result_count=lambda result: result.fields_scored,
        trace_python_allocations=args.tracemalloc,
    )
    result = {
        "mapping": report.as_dict(),
        "measurement": _benchmark_measurement_payload(args.tracemalloc),
        "resources": _benchmark_resource_payload(metrics),
    }
    _emit(result, output=args.output)

    if args.require_auto_precision is not None:
        precision = report.auto_precision
        if precision is None or precision < args.require_auto_precision:
            raise SystemExit(5)
    if report.decision_contract_failures or report.auto_incorrect > args.max_unsafe_auto:
        raise SystemExit(6)
    if (
        args.require_automation_coverage is not None
        and report.automation_coverage < args.require_automation_coverage
    ):
        raise SystemExit(8)
    if (
        args.require_suggestion_accuracy is not None
        and report.suggestion_accuracy < args.require_suggestion_accuracy
    ):
        raise SystemExit(9)


def _benchmark_workflow(args: argparse.Namespace) -> None:
    report, resources = run_workflow_benchmark(
        records=args.records,
        batch_size=args.batch_size,
        work_dir=args.work_dir,
        keep_work_dir=args.keep_work_dir,
        signed_audit=args.audit,
        trace_python_allocations=args.tracemalloc,
    )
    resource_payload = _benchmark_resource_payload(resources)
    _emit(
        {
            "benchmark": "workflow",
            "version": 1,
            "measurement": _benchmark_measurement_payload(args.tracemalloc),
            "environment": {
                "product_version": __version__,
                "python_version": platform.python_version(),
                "operating_system": platform.system(),
                "operating_system_release": platform.release(),
                "machine": platform.machine(),
                "logical_cpus": os.cpu_count(),
                "sqlite_version": sqlite3.sqlite_version,
                "state_store_journal_policy": selected_journal_mode(),
                "state_store_synchronous": "full",
            },
            "resources": resource_payload,
            "workflow": report.as_dict(),
        },
        output=args.output,
    )
    if not report.success:
        raise SystemExit(7)


def _add_output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", "-o")


def _add_parser_worker_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--magika", action="store_true", help="add local Magika evidence")
    parser.add_argument(
        "--backend",
        choices=("auto", "process", "bubblewrap"),
        default="auto",
        help="worker backend; auto never downgrades below the required containment",
    )
    parser.add_argument(
        "--require-containment",
        choices=tuple(_CONTAINMENT_LEVELS),
        default="os-sandbox",
        help="minimum accepted containment level (default: os-sandbox)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="worker wall timeout in seconds",
    )
    parser.add_argument(
        "--max-input-mib",
        type=int,
        default=512,
        help="maximum snapshot size in MiB",
    )


def _add_model_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--models", action="store_true", help="use both installed CPU profiles")
    parser.add_argument("--model-dir")
    parser.add_argument("--reranker-dir")


def _benchmark_measurement_payload(trace_python_allocations: bool) -> dict[str, object]:
    return {
        "mode": "python_allocation_trace" if trace_python_allocations else "standard",
        "python_allocation_tracing": trace_python_allocations,
        "observer_effect": (
            "CPython allocation tracing is enabled and may materially increase wall time"
            if trace_python_allocations
            else "wall time, CPU time and optional sampled process RSS only"
        ),
    }


def _benchmark_resource_payload(metrics: BenchmarkResult) -> dict[str, object]:
    payload = metrics.as_dict()
    # A process id is neither a performance metric nor stable report data. Keep it available on
    # the in-process result for debugging, but do not write it to portable CLI artifacts.
    payload.pop("pid", None)
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="polymorph",
        description="Policy-driven, payload-blind data bridge tooling.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_parser = sub.add_parser("inspect", help="inspect a source schema locally")
    inspect_sub = inspect_parser.add_subparsers(dest="kind", required=True)

    auto = inspect_sub.add_parser("auto", help="detect content from bytes, then inspect safely")
    auto.add_argument("path")
    auto.add_argument("--magika", action="store_true", help="add local Magika evidence")
    _add_output(auto)
    auto.set_defaults(func=_inspect_auto)

    isolated_content = inspect_sub.add_parser(
        "isolated-content",
        help="inspect content in an exact-snapshot worker; OS sandbox required by default",
    )
    isolated_content.add_argument("path")
    _add_parser_worker_options(isolated_content)
    _add_output(isolated_content)
    isolated_content.set_defaults(func=_inspect_isolated_content)

    excel = inspect_sub.add_parser("excel")
    excel.add_argument("path")
    excel.add_argument("--sheet")
    excel.add_argument("--header-row", type=int, default=None)
    _add_output(excel)
    excel.set_defaults(func=_inspect_excel)

    csv_parser = inspect_sub.add_parser("csv")
    csv_parser.add_argument("path")
    csv_parser.add_argument("--delimiter")
    csv_parser.add_argument("--encoding", default="utf-8-sig")
    _add_output(csv_parser)
    csv_parser.set_defaults(func=_inspect_csv)

    json_parser = inspect_sub.add_parser("json")
    json_parser.add_argument("path")
    _add_output(json_parser)
    json_parser.set_defaults(func=_inspect_json)

    db = inspect_sub.add_parser("db")
    db.add_argument("url")
    db.add_argument("--table", required=True)
    db.add_argument("--schema")
    _add_output(db)
    db.set_defaults(func=_inspect_db)

    mapping = sub.add_parser("map", help="propose schema mappings without executing them")
    mapping.add_argument("source")
    mapping.add_argument("target")
    _add_model_options(mapping)
    _add_output(mapping)
    mapping.set_defaults(func=_map)

    plan = sub.add_parser("plan", help="create, verify and repair immutable mapping plans")
    plan_sub = plan.add_subparsers(dest="plan_command", required=True)

    create = plan_sub.add_parser("create")
    create.add_argument("source")
    create.add_argument("target")
    create.add_argument("--output", "-o", required=True)
    _add_model_options(create)
    create.add_argument("--allow-review", action="store_true")
    create.set_defaults(func=_plan_create)

    validate = plan_sub.add_parser("validate")
    validate.add_argument("plan")
    validate.add_argument("source")
    validate.add_argument("target")
    validate.set_defaults(func=_plan_validate)

    show = plan_sub.add_parser("show")
    show.add_argument("plan")
    show.set_defaults(func=_plan_show)

    repair = plan_sub.add_parser("repair")
    repair.add_argument("plan")
    repair.add_argument("old_source")
    repair.add_argument("new_source")
    repair.add_argument("old_target")
    repair.add_argument("new_target")
    repair.add_argument("--output", "-o", required=True)
    _add_model_options(repair)
    repair.add_argument("--allow-review", action="store_true")
    repair.set_defaults(func=_plan_repair)

    model = sub.add_parser("model", help="manage the optional local semantic encoder")
    model_sub = model.add_subparsers(dest="model_command", required=True)
    install = model_sub.add_parser("install")
    install.add_argument(
        "--profile",
        choices=["multilingual-cpu", "reranker-multilingual-cpu"],
        default="multilingual-cpu",
    )
    install.add_argument("--destination")
    install.set_defaults(func=_model_install)

    preflight = sub.add_parser(
        "preflight", help="exercise a plan against source records without destination writes"
    )
    preflight.add_argument("source")
    preflight.add_argument("target_schema")
    preflight.add_argument("plan")
    preflight.add_argument("--max-records", type=int)
    preflight.add_argument("--magika", action="store_true")
    preflight.add_argument("--resolver-db-url")
    preflight.add_argument("--resolver-db-table")
    preflight.add_argument("--resolver-db-schema")
    preflight.add_argument("--remember", action="store_true")
    preflight.add_argument("--recipe-store", default=str(recipe_store_path()))
    preflight.add_argument("--approved-by", default="local-user")
    _add_output(preflight)
    preflight.set_defaults(func=_preflight_file)

    prepare = sub.add_parser(
        "prepare",
        help="content-check, map, reuse recipes and preflight a route without destination writes",
    )
    prepare.add_argument("source")
    prepare.add_argument("target_schema")
    _add_model_options(prepare)
    prepare.add_argument("--magika", action="store_true")
    prepare.add_argument("--max-records", type=int)
    prepare.add_argument("--resolver-db-url")
    prepare.add_argument("--resolver-db-table")
    prepare.add_argument("--resolver-db-schema")
    prepare.add_argument("--recipe-store", default=str(recipe_store_path()))
    prepare.add_argument(
        "--recipe-rejection-threshold",
        type=int,
        default=DEFAULT_RECIPE_REJECTION_THRESHOLD,
        help="suspend automatic recipe reuse after this many consecutive rejected runs",
    )
    prepare.add_argument("--remember", action="store_true")
    prepare.add_argument("--approved-by", default="local-user")
    prepare.add_argument("--output-plan")
    _add_output(prepare)
    prepare.set_defaults(func=_prepare)

    recipe = sub.add_parser("recipe", help="manage locally validated mapping recipes")
    recipe_sub = recipe.add_subparsers(dest="recipe_command", required=True)
    remember = recipe_sub.add_parser("remember")
    remember.add_argument("plan")
    remember.add_argument("source_schema")
    remember.add_argument("target_schema")
    remember.add_argument("--store", default=str(recipe_store_path()))
    remember.add_argument("--approved-by", default="local-user")
    remember.set_defaults(func=_recipe_remember)
    recipe_list = recipe_sub.add_parser("list")
    recipe_list.add_argument("--store", default=str(recipe_store_path()))
    recipe_list.add_argument("--limit", type=int, default=100)
    recipe_list.set_defaults(func=_recipe_list)
    recipe_health = recipe_sub.add_parser("health")
    recipe_health.add_argument("recipe_id", nargs="?")
    recipe_health.add_argument("--store", default=str(recipe_store_path()))
    recipe_health.add_argument("--limit", type=int, default=100)
    recipe_health.add_argument(
        "--rejection-threshold",
        type=int,
        default=DEFAULT_RECIPE_REJECTION_THRESHOLD,
    )
    recipe_health.set_defaults(func=_recipe_health)
    recipe_find = recipe_sub.add_parser("find")
    recipe_find.add_argument("source_schema")
    recipe_find.add_argument("target_schema")
    recipe_find.add_argument("--store", default=str(recipe_store_path()))
    recipe_find.add_argument("--output-plan")
    recipe_find.add_argument(
        "--rejection-threshold",
        type=int,
        default=DEFAULT_RECIPE_REJECTION_THRESHOLD,
        help="report automatic reuse as suspended after this many consecutive rejections",
    )
    recipe_find.set_defaults(func=_recipe_find)

    doctor = sub.add_parser(
        "doctor", help="report local reliability and optional acceleration features"
    )
    doctor.set_defaults(func=_doctor)

    benchmark = sub.add_parser(
        "benchmark", help="opt-in resource diagnostics with no normal-run overhead"
    )
    benchmark_sub = benchmark.add_subparsers(dest="benchmark_command", required=True)
    benchmark_inspect = benchmark_sub.add_parser("inspect")
    benchmark_inspect.add_argument("path")
    benchmark_inspect.add_argument("--records", type=int, default=1000)
    benchmark_inspect.add_argument("--magika", action="store_true")
    benchmark_inspect.add_argument(
        "--tracemalloc",
        action="store_true",
        help="trace CPython allocations; intrusive and may materially distort wall time",
    )
    _add_output(benchmark_inspect)
    benchmark_inspect.set_defaults(func=_benchmark_inspect)

    benchmark_worker = benchmark_sub.add_parser(
        "parser-worker",
        help="measure exact-snapshot content-worker startup and inspection",
    )
    benchmark_worker.add_argument("path")
    benchmark_worker.add_argument("--runs", type=int, default=5)
    _add_parser_worker_options(benchmark_worker)
    _add_output(benchmark_worker)
    benchmark_worker.set_defaults(func=_benchmark_parser_worker)
    benchmark_mapping = benchmark_sub.add_parser(
        "mapping", help="score auto precision and coverage against a labelled schema corpus"
    )
    benchmark_mapping.add_argument("manifest")
    _add_model_options(benchmark_mapping)
    benchmark_mapping.add_argument("--require-auto-precision", type=float)
    benchmark_mapping.add_argument("--require-automation-coverage", type=float)
    benchmark_mapping.add_argument("--require-suggestion-accuracy", type=float)
    benchmark_mapping.add_argument("--max-unsafe-auto", type=int, default=0)
    benchmark_mapping.add_argument(
        "--tracemalloc",
        action="store_true",
        help="trace CPython allocations; intrusive and may materially distort wall time",
    )
    _add_output(benchmark_mapping)
    benchmark_mapping.set_defaults(func=_benchmark_mapping)
    benchmark_workflow = benchmark_sub.add_parser(
        "workflow",
        help="run the signed and encrypted local workflow against a real SQLite destination",
    )
    benchmark_workflow.add_argument("--records", type=int, default=1000)
    benchmark_workflow.add_argument("--batch-size", type=int, default=100)
    benchmark_workflow.add_argument(
        "--work-dir",
        help="use and retain this new or empty directory for benchmark state",
    )
    benchmark_workflow.add_argument(
        "--keep-work-dir",
        action="store_true",
        help="retain an automatically allocated work directory",
    )
    benchmark_workflow.add_argument(
        "--audit",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="write and verify a signed destination audit chain",
    )
    benchmark_workflow.add_argument(
        "--tracemalloc",
        action="store_true",
        help="trace CPython allocations; intrusive and may materially distort wall time",
    )
    _add_output(benchmark_workflow)
    benchmark_workflow.set_defaults(func=_benchmark_workflow)

    key = sub.add_parser("key", help="manage password-encrypted destination recipient keys")
    key_sub = key.add_subparsers(dest="key_command", required=True)
    key_generate = key_sub.add_parser("generate")
    key_generate.add_argument("--output", "-o", required=True)
    key_generate.set_defaults(func=_key_generate)
    key_public = key_sub.add_parser("public")
    key_public.add_argument("path")
    key_public.set_defaults(func=_key_public)
    key_validate = key_sub.add_parser("validate")
    key_validate.add_argument("path")
    key_validate.set_defaults(func=_key_validate)

    audit = sub.add_parser("audit", help="verify or export the metadata-only audit chain")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    verify = audit_sub.add_parser("verify")
    verify.add_argument("path")
    verify.add_argument("--public-key-hex")
    verify.set_defaults(func=_audit_verify)
    export = audit_sub.add_parser("export")
    export.add_argument("path")
    export.add_argument("--output", "-o", required=True)
    export.set_defaults(func=_audit_export)
    audit_summary = audit_sub.add_parser("summary")
    audit_summary.add_argument("path")
    audit_summary.add_argument("--public-key-hex")
    audit_summary.set_defaults(func=_audit_summary)

    events = sub.add_parser(
        "events", help="validate and summarize a local payload-free operational event stream"
    )
    events_sub = events.add_subparsers(dest="events_command", required=True)
    events_summary = events_sub.add_parser("summary")
    events_summary.add_argument("path")
    events_summary.add_argument("--run-id")
    _add_output(events_summary)
    events_summary.set_defaults(func=_events_summary)
    events_check = events_sub.add_parser(
        "check", help="exit non-zero for failed statuses, missing runs or unclosed workflows"
    )
    events_check.add_argument("path")
    events_check.add_argument("--run-id", required=True)
    _add_output(events_check)
    events_check.set_defaults(func=_events_check)

    quarantine = sub.add_parser("quarantine", help="inspect sealed quarantine metadata")
    quarantine_sub = quarantine.add_subparsers(dest="quarantine_command", required=True)
    list_parser = quarantine_sub.add_parser("list")
    list_parser.add_argument("path")
    list_parser.add_argument("--limit", type=int, default=100)
    list_parser.set_defaults(func=_quarantine_list)

    explain = sub.add_parser("explain", help="explain a machine reason code and safe next action")
    explain.add_argument("reason_code")
    explain.set_defaults(func=_explain)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except BrokenPipeError:
        try:
            sys.stdout.close()
        finally:
            raise SystemExit(0) from None
    except SandboxError as exc:
        print(f"error [{exc.code.value}]: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
    except (PolymorphError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None

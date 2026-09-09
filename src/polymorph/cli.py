from __future__ import annotations

import argparse
import getpass
import importlib.util
import json
import platform
import shutil
import sqlite3
import sys
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import unquote

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from . import __version__
from .audit import AuditLog
from .benchmark import MappingBenchmarkCase, benchmark_call, benchmark_mapping_cases
from .connectors.base import SourceConnector
from .connectors.csv_file import CsvConnector
from .connectors.database import DatabaseConnector
from .connectors.excel import ExcelConnector
from .connectors.json_file import JsonFileConnector
from .content import ContentInspector, ContentKind, FileInspection, MagikaClassifier
from .diagnostics import explain_reason
from .errors import PolymorphError
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
                "note": "availability only; no OS sandbox is assumed by default",
            },
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
    metric_payloads = [content_metrics.as_dict()]
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
            metric_payloads.append(schema_metrics.as_dict())
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
                metric_payloads.append(records_metrics.as_dict())
    _emit(payload, output=args.output)


def _benchmark_mapping(args: argparse.Namespace) -> None:
    _protect_write_path(args.output, args.manifest)
    manifest_path = Path(args.manifest).expanduser().resolve()
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise PolymorphError("mapping benchmark manifest must be an object with version 1")
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise PolymorphError("mapping benchmark manifest must contain at least one case")

    cases: list[MappingBenchmarkCase] = []
    for index, raw in enumerate(raw_cases, start=1):
        if not isinstance(raw, dict):
            raise PolymorphError(f"benchmark case {index} must be an object")
        source_payload = raw.get("source_schema")
        target_payload = raw.get("target_schema")
        expected_payload = raw.get("expected")
        if not isinstance(source_payload, dict) or not isinstance(target_payload, dict):
            raise PolymorphError(
                f"benchmark case {index} must contain inline source/target schemas"
            )
        if not isinstance(expected_payload, dict) or not expected_payload:
            raise PolymorphError(f"benchmark case {index} must contain expected mappings")
        expected: dict[str, str | None] = {}
        for source_id, target_id in expected_payload.items():
            if target_id is not None and not isinstance(target_id, str):
                raise PolymorphError(f"benchmark case {index} has an invalid expected target")
            expected[str(source_id)] = target_id
        cases.append(
            MappingBenchmarkCase(
                id=str(raw.get("id") or f"case-{index}"),
                source_schema=schema_from_dict(source_payload),
                target_schema=schema_from_dict(target_payload),
                expected=expected,
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
        "resources": metrics.as_dict(),
    }
    _emit(result, output=args.output)

    if args.require_auto_precision is not None:
        precision = report.auto_precision
        if precision is None or precision < args.require_auto_precision:
            raise SystemExit(5)
    if report.unsafe_auto_on_unmappable > args.max_unsafe_auto:
        raise SystemExit(6)


def _add_output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", "-o")


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
    benchmark_mapping = benchmark_sub.add_parser(
        "mapping", help="score auto precision and coverage against a labelled schema corpus"
    )
    benchmark_mapping.add_argument("manifest")
    _add_model_options(benchmark_mapping)
    benchmark_mapping.add_argument("--require-auto-precision", type=float)
    benchmark_mapping.add_argument("--max-unsafe-auto", type=int, default=0)
    benchmark_mapping.add_argument(
        "--tracemalloc",
        action="store_true",
        help="trace CPython allocations; intrusive and may materially distort wall time",
    )
    _add_output(benchmark_mapping)
    benchmark_mapping.set_defaults(func=_benchmark_mapping)

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
    except (PolymorphError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None

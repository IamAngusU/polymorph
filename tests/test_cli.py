from __future__ import annotations

import json

import pytest

from polymorph.cli import _auto_source, build_parser
from polymorph.errors import ConnectorError, PolymorphError


def test_cli_excel_header_detection_defaults_to_auto() -> None:
    args = build_parser().parse_args(["inspect", "excel", "book.xlsx"])
    assert args.header_row is None


def test_cli_supports_csv_and_plan_commands() -> None:
    parser = build_parser()
    csv_args = parser.parse_args(["inspect", "csv", "orders.csv", "--delimiter", ";"])
    assert csv_args.delimiter == ";"
    plan_args = parser.parse_args(
        ["plan", "create", "source.json", "target.json", "-o", "plan.json"]
    )
    assert plan_args.output == "plan.json"


def test_cli_supports_content_auto_preflight_and_recipes() -> None:
    parser = build_parser()
    auto = parser.parse_args(["inspect", "auto", "upload.bin"])
    assert auto.path == "upload.bin"
    preflight = parser.parse_args(["preflight", "input.bin", "target.json", "plan.json"])
    assert preflight.max_records is None
    recipe = parser.parse_args(["recipe", "list"])
    assert recipe.limit == 100
    health = parser.parse_args(["recipe", "health", "recipe-id"])
    assert health.rejection_threshold == 3
    find = parser.parse_args(["recipe", "find", "source.json", "target.json"])
    assert find.rejection_threshold == 3
    audit_summary = parser.parse_args(["audit", "summary", "audit.sqlite"])
    assert audit_summary.path == "audit.sqlite"
    explain = parser.parse_args(["explain", "write_outcome_unknown"])
    assert explain.reason_code == "write_outcome_unknown"


def test_cli_supports_optional_reranker_profile() -> None:
    args = build_parser().parse_args(["model", "install", "--profile", "reranker-multilingual-cpu"])
    assert args.profile == "reranker-multilingual-cpu"
    assert args.destination is None


def test_cli_can_enable_both_installed_models_with_one_flag() -> None:
    args = build_parser().parse_args(["map", "source.json", "target.json", "--models"])
    assert args.models is True


def test_cli_benchmark_is_explicit_opt_in() -> None:
    args = build_parser().parse_args(["benchmark", "inspect", "orders.csv", "--records", "50"])
    assert args.records == 50
    assert args.tracemalloc is False

    traced = build_parser().parse_args(["benchmark", "inspect", "orders.csv", "--tracemalloc"])
    assert traced.tracemalloc is True


def test_cli_mapping_benchmark_defaults_to_zero_unsafe_auto() -> None:
    args = build_parser().parse_args(
        ["benchmark", "mapping", "corpus.json", "--require-auto-precision", "1.0"]
    )
    assert args.require_auto_precision == 1.0
    assert args.max_unsafe_auto == 0
    assert args.tracemalloc is False

    traced = build_parser().parse_args(["benchmark", "mapping", "corpus.json", "--tracemalloc"])
    assert traced.tracemalloc is True


def test_inspect_benchmark_output_labels_observer_mode(tmp_path, capsys) -> None:
    source = tmp_path / "orders.csv"
    source.write_text("id,name\n1,Ada\n", encoding="utf-8")

    standard = build_parser().parse_args(["benchmark", "inspect", str(source), "--records", "1"])
    standard.func(standard)
    standard_payload = json.loads(capsys.readouterr().out)

    assert standard_payload["measurement"]["mode"] == "standard"
    assert all(item["peak_python_bytes"] is None for item in standard_payload["metrics"])

    traced = build_parser().parse_args(
        ["benchmark", "inspect", str(source), "--records", "1", "--tracemalloc"]
    )
    traced.func(traced)
    traced_payload = json.loads(capsys.readouterr().out)

    assert traced_payload["measurement"]["mode"] == "python_allocation_trace"
    assert all(item["python_allocation_tracing"] for item in traced_payload["metrics"])
    assert all(item["peak_python_bytes"] is not None for item in traced_payload["metrics"])


def test_prepare_runs_safe_one_command_workflow_and_remembers_recipe(tmp_path, capsys) -> None:
    from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
    from polymorph.models.types import DataType
    from polymorph.serialization import save_schema

    source_path = tmp_path / "payload.unknown"
    source_path.write_text('[{"customer id": "A-1"}]', encoding="utf-8")
    target_path = tmp_path / "target.json"
    save_schema(
        target_path,
        SchemaDescriptor(
            "target",
            (FieldDescriptor("customer_id", "customer id", DataType.STRING, nullable=False),),
        ),
    )
    plan_path = tmp_path / "ready.plan.json"
    recipe_path = tmp_path / "recipes.sqlite3"
    args = build_parser().parse_args(
        [
            "prepare",
            str(source_path),
            str(target_path),
            "--output-plan",
            str(plan_path),
            "--recipe-store",
            str(recipe_path),
            "--remember",
        ]
    )

    args.func(args)
    payload = json.loads(capsys.readouterr().out)

    assert payload["ready"] is True
    assert payload["route_source"] == "fresh_mapping"
    assert payload["recipe_remembered"] is True
    assert payload["recipe_monitoring"]["events_recorded"]["preflight"] is True
    assert payload["recipe_monitoring"]["active_health"]["total_runs"] == 1
    assert plan_path.exists()
    assert recipe_path.exists()

    args.func(args)
    reused = json.loads(capsys.readouterr().out)
    assert reused["route_source"] == "recipe"
    assert reused["recipe_remembered"] is False
    assert reused["recipe_monitoring"]["active_health"]["total_runs"] == 2


def test_prepare_suspends_rejected_recipe_and_builds_fresh_version(tmp_path, capsys) -> None:
    from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
    from polymorph.models.types import DataType
    from polymorph.recipes import RecipeRunOutcome, RecipeStore
    from polymorph.serialization import save_schema

    source_path = tmp_path / "payload.unknown"
    source_path.write_text('[{"customer id": "A-1"}]', encoding="utf-8")
    target_path = tmp_path / "target.json"
    save_schema(
        target_path,
        SchemaDescriptor(
            "target",
            (FieldDescriptor("customer_id", "customer id", DataType.STRING, nullable=False),),
        ),
    )
    recipe_path = tmp_path / "recipes.sqlite3"
    args = build_parser().parse_args(
        [
            "prepare",
            str(source_path),
            str(target_path),
            "--recipe-store",
            str(recipe_path),
            "--remember",
        ]
    )
    args.func(args)
    first = json.loads(capsys.readouterr().out)
    old_recipe_id = first["recipe_id"]
    store = RecipeStore(recipe_path)
    old_recipe = store.get(old_recipe_id)
    assert old_recipe is not None
    for _ in range(3):
        store.record_run(
            old_recipe,
            old_recipe.plan,
            RecipeRunOutcome.REJECTED,
            reason_code="required_target_null",
        )

    args.func(args)
    adapted = json.loads(capsys.readouterr().out)

    assert adapted["ready"] is True
    assert adapted["route_source"] == "fresh_mapping"
    assert adapted["recipe_remembered"] is True
    assert adapted["recipe_id"] != old_recipe_id
    assert adapted["recipe_monitoring"]["adaptation"]["code"] == ("recipe_auto_reuse_suspended")
    assert adapted["recipe_monitoring"]["candidate_health"]["state"] == "suspended"
    assert adapted["recipe_monitoring"]["active_health"]["state"] == "healthy"


def test_recipe_find_reports_suspension_while_allowing_manual_plan_export(tmp_path, capsys) -> None:
    from polymorph.models.mapping import MappingPlan, MappingRule
    from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
    from polymorph.models.types import DataType
    from polymorph.recipes import RecipeRunOutcome, RecipeStore
    from polymorph.serialization import save_schema

    source = SchemaDescriptor(
        "source",
        (FieldDescriptor("customer_id", "customer id", DataType.STRING, nullable=False),),
    )
    target = SchemaDescriptor(
        "target",
        (FieldDescriptor("customer_id", "customer id", DataType.STRING, nullable=False),),
    )
    plan = MappingPlan(
        "route",
        source.id,
        target.id,
        source.fingerprint(),
        target.fingerprint(),
        (MappingRule("customer_id", "customer_id", "copy"),),
    )
    source_path = tmp_path / "source.json"
    target_path = tmp_path / "target.json"
    store_path = tmp_path / "recipes.sqlite3"
    output_path = tmp_path / "manual-review-plan.json"
    save_schema(source_path, source)
    save_schema(target_path, target)
    store = RecipeStore(store_path)
    recipe = store.remember(plan, source, target, approved_by="test")
    for _ in range(3):
        store.record_run(
            recipe,
            plan,
            RecipeRunOutcome.REJECTED,
            reason_code="required_target_null",
        )

    args = build_parser().parse_args(
        [
            "recipe",
            "find",
            str(source_path),
            str(target_path),
            "--store",
            str(store_path),
            "--output-plan",
            str(output_path),
        ]
    )
    args.func(args)
    payload = json.loads(capsys.readouterr().out)

    assert payload["found"] is True
    assert payload["automatic_reuse_allowed"] is False
    assert payload["health"]["state"] == "suspended"
    assert output_path.is_file()


def test_inspect_refuses_to_overwrite_its_source_file(tmp_path) -> None:
    source = tmp_path / "source.json"
    original = b'[{"customer_id":"A-1"}]'
    source.write_bytes(original)
    args = build_parser().parse_args(["inspect", "json", str(source), "--output", str(source)])

    with pytest.raises(PolymorphError, match="must not overwrite"):
        args.func(args)

    assert source.read_bytes() == original


def test_plan_create_refuses_to_overwrite_an_input_schema(tmp_path) -> None:
    from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
    from polymorph.serialization import save_schema

    source = tmp_path / "source.schema.json"
    target = tmp_path / "target.schema.json"
    save_schema(source, SchemaDescriptor("source", (FieldDescriptor("id", "id"),)))
    save_schema(target, SchemaDescriptor("target", (FieldDescriptor("id", "id"),)))
    original = source.read_bytes()
    args = build_parser().parse_args(
        ["plan", "create", str(source), str(target), "--output", str(source)]
    )

    with pytest.raises(PolymorphError, match="must not overwrite"):
        args.func(args)

    assert source.read_bytes() == original


def test_audit_export_refuses_to_overwrite_the_audit_database(tmp_path) -> None:
    audit = tmp_path / "audit.sqlite"
    original = b"not-opened-because-the-path-guard-runs-first"
    audit.write_bytes(original)
    args = build_parser().parse_args(["audit", "export", str(audit), "--output", str(audit)])

    with pytest.raises(PolymorphError, match="must not overwrite"):
        args.func(args)

    assert audit.read_bytes() == original


def test_audit_verify_refuses_missing_path_without_creating_it(tmp_path) -> None:
    audit = tmp_path / "missing-audit.sqlite"
    args = build_parser().parse_args(["audit", "verify", str(audit)])

    with pytest.raises(PolymorphError, match="does not exist"):
        args.func(args)

    assert not audit.exists()


def test_audit_verify_does_not_initialize_an_existing_empty_file(tmp_path) -> None:
    audit = tmp_path / "empty-audit.sqlite"
    audit.write_bytes(b"")
    args = build_parser().parse_args(["audit", "verify", str(audit)])

    with pytest.raises(PolymorphError, match="schema is missing"):
        args.func(args)

    assert audit.read_bytes() == b""


def test_explain_returns_safe_operator_guidance(capsys) -> None:
    args = build_parser().parse_args(["explain", "write_outcome_unknown"])

    args.func(args)
    payload = json.loads(capsys.readouterr().out)

    assert payload["category"] == "write_ambiguity"
    assert payload["retry_policy"] == "never_blind_retry"
    assert "Reconcile" in payload["next_action"]


def test_inspect_db_refuses_to_overwrite_its_sqlite_database(tmp_path) -> None:
    database = tmp_path / "source.sqlite"
    original = b"guard-runs-before-database-open"
    database.write_bytes(original)
    sqlite_url = f"sqlite:///{database.as_posix()}"
    args = build_parser().parse_args(
        ["inspect", "db", sqlite_url, "--table", "orders", "--output", str(database)]
    )

    with pytest.raises(PolymorphError, match="must not overwrite"):
        args.func(args)

    assert database.read_bytes() == original


def test_auto_source_rejects_path_swap_after_accepted_inspection(tmp_path) -> None:
    source = tmp_path / "source.unknown"
    replacement = tmp_path / "replacement.unknown"
    source.write_text('[{"customer_id":"before"}]', encoding="utf-8")
    replacement.write_text('[{"customer_id":"after"}]', encoding="utf-8")

    report, connector = _auto_source(str(source))
    assert report.safe
    assert connector is not None
    replacement.replace(source)

    with pytest.raises(ConnectorError, match="changed after accepted content inspection"):
        connector.inspect_schema()

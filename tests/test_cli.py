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


def test_cli_mapping_benchmark_defaults_to_zero_unsafe_auto() -> None:
    args = build_parser().parse_args(
        ["benchmark", "mapping", "corpus.json", "--require-auto-precision", "1.0"]
    )
    assert args.require_auto_precision == 1.0
    assert args.max_unsafe_auto == 0


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
    assert plan_path.exists()
    assert recipe_path.exists()


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

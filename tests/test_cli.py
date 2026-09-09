from __future__ import annotations

import json

from polymorph.cli import build_parser


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
    args = build_parser().parse_args(
        ["model", "install", "--profile", "reranker-multilingual-cpu"]
    )
    assert args.profile == "reranker-multilingual-cpu"
    assert args.destination is None


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

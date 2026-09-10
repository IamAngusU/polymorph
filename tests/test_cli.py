from __future__ import annotations

import json

import pytest

import polymorph.cli as cli_module
from polymorph.cli import _auto_source, build_parser
from polymorph.errors import ConnectorError, IntegrityError, PolymorphError


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

    preflight_args = parser.parse_args(
        [
            "preflight",
            "orders.csv",
            "target.json",
            "plan.json",
            "--max-input-records",
            "5000",
        ]
    )
    prepare_args = parser.parse_args(
        ["prepare", "orders.csv", "target.json", "--max-input-records", "5000"]
    )
    assert preflight_args.max_input_records == 5000
    assert prepare_args.max_input_records == 5000


def test_event_commands_accept_the_writer_stream_budget() -> None:
    parser = build_parser()
    summary = parser.parse_args(
        ["events", "summary", "events.jsonl", "--event-stream-max-mib", "256"]
    )
    check = parser.parse_args(
        [
            "events",
            "check",
            "events.jsonl",
            "--run-id",
            "11" * 16,
            "--event-stream-max-mib",
            "1024",
        ]
    )

    assert summary.event_stream_max_mib == 256
    assert check.event_stream_max_mib == 1024


def test_event_summary_uses_its_explicit_stream_budget(tmp_path) -> None:
    path = tmp_path / "oversized-for-default.jsonl"
    with path.open("wb") as handle:
        handle.truncate(65 * 1024 * 1024)
    args = build_parser().parse_args(
        ["events", "summary", str(path), "--event-stream-max-mib", "66"]
    )

    # Passing the configured writer budget gets beyond the total-size gate. The deliberately
    # malformed sparse body is then rejected by the independent per-line boundary.
    with pytest.raises(IntegrityError, match="line 1 exceeds the size limit"):
        args.func(args)


def test_cli_supports_recipient_certificate_inspect_and_accept() -> None:
    parser = build_parser()
    common = [
        "certificate.json",
        "--identity-public-key-hex",
        "11" * 32,
        "--tenant",
        "tenant-1",
        "--destination-connector",
        "destination-1",
    ]
    inspect = parser.parse_args(["key", "certificate-inspect", *common])
    assert inspect.path == "certificate.json"
    accept = parser.parse_args(
        ["key", "certificate-accept", *common, "--state", "recipient-trust.json"]
    )
    assert accept.state == "recipient-trust.json"


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
    event_check = parser.parse_args(
        ["events", "check", "operational-events.jsonl", "--run-id", "11" * 16]
    )
    assert event_check.path == "operational-events.jsonl"
    explain = parser.parse_args(["explain", "write_outcome_unknown"])
    assert explain.reason_code == "write_outcome_unknown"


def test_cli_supports_optional_reranker_profile() -> None:
    args = build_parser().parse_args(["model", "install", "--profile", "reranker-multilingual-cpu"])
    assert args.profile == "reranker-multilingual-cpu"
    assert args.destination is None


def test_cli_models_flag_selects_research_encoder_without_reranker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected: dict[str, str | None] = {}
    sentinel = object()

    def capture(model_dir: str | None, reranker_dir: str | None = None):
        selected.update(model=model_dir, reranker=reranker_dir)
        return sentinel

    monkeypatch.setattr(cli_module, "_matcher", capture)
    args = build_parser().parse_args(["map", "source.json", "target.json", "--models"])
    assert args.models is True
    assert args.reranker_dir is None
    assert cli_module._matcher_for_args(args) is sentinel
    assert selected["model"] is not None
    assert selected["model"].endswith("multilingual-cpu")
    assert selected["reranker"] is None


def test_doctor_labels_both_model_profiles_as_research_only(
    tmp_path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli_module, "model_home", lambda name: tmp_path / name)
    args = build_parser().parse_args(["doctor"])

    args.func(args)
    payload = json.loads(capsys.readouterr().out)

    assert payload["models"]["multilingual-cpu"]["usage"] == "research_only"
    assert payload["models"]["reranker-multilingual-cpu"]["usage"] == "research_only"


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
    assert args.require_automation_coverage is None
    assert args.require_suggestion_accuracy is None
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
    assert all("pid" not in item for item in standard_payload["metrics"])
    assert all(item["peak_python_bytes"] is None for item in standard_payload["metrics"])

    traced = build_parser().parse_args(
        ["benchmark", "inspect", str(source), "--records", "1", "--tracemalloc"]
    )
    traced.func(traced)
    traced_payload = json.loads(capsys.readouterr().out)

    assert traced_payload["measurement"]["mode"] == "python_allocation_trace"
    assert all(item["python_allocation_tracing"] for item in traced_payload["metrics"])
    assert all(item["peak_python_bytes"] is not None for item in traced_payload["metrics"])


def test_mapping_benchmark_rejects_incomplete_or_dangling_labels(tmp_path) -> None:
    base = {
        "version": 1,
        "cases": [
            {
                "id": "case-one",
                "source_schema": {
                    "id": "source",
                    "fields": [
                        {"id": "one", "name": "one"},
                        {"id": "two", "name": "two"},
                    ],
                },
                "target_schema": {
                    "id": "target",
                    "fields": [{"id": "target_one", "name": "one"}],
                },
                "expected": {"one": "target_one"},
            }
        ],
    }
    manifest = tmp_path / "corpus.json"
    manifest.write_text(json.dumps(base), encoding="utf-8")
    args = build_parser().parse_args(["benchmark", "mapping", str(manifest)])

    with pytest.raises(PolymorphError, match="label every source field"):
        args.func(args)

    base["cases"][0]["expected"] = {"one": "missing", "two": None}
    manifest.write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(PolymorphError, match="unknown target field"):
        args.func(args)


def test_mapping_benchmark_rejects_duplicate_case_ids(tmp_path) -> None:
    case = {
        "id": "duplicate",
        "source_schema": {"id": "source", "fields": [{"id": "one", "name": "one"}]},
        "target_schema": {"id": "target", "fields": [{"id": "one", "name": "one"}]},
        "expected": {"one": "one"},
    }
    manifest = tmp_path / "corpus.json"
    manifest.write_text(
        json.dumps({"version": 1, "cases": [case, case]}),
        encoding="utf-8",
    )
    args = build_parser().parse_args(["benchmark", "mapping", str(manifest)])

    with pytest.raises(PolymorphError, match="case ids must be unique"):
        args.func(args)


def test_mapping_benchmark_rejects_duplicate_or_unknown_safety_labels(tmp_path) -> None:
    manifest = tmp_path / "corpus.json"
    manifest.write_text(
        '{"version":1,"cases":[{"id":"case","source_schema":{"id":"s",'
        '"fields":[{"id":"one","name":"one"}]},"target_schema":{"id":"t",'
        '"fields":[{"id":"one","name":"one"}]},"expected":{"one":"one",'
        '"one":null}}]}',
        encoding="utf-8",
    )
    args = build_parser().parse_args(["benchmark", "mapping", str(manifest)])

    with pytest.raises(PolymorphError, match="duplicate JSON key"):
        args.func(args)

    payload = {
        "version": 1,
        "cases": [
            {
                "id": "case",
                "source_schema": {"id": "s", "fields": [{"id": "one", "name": "one"}]},
                "target_schema": {"id": "t", "fields": [{"id": "one", "name": "one"}]},
                "expected": {"one": "one"},
                "review_onyl": ["one"],
            }
        ],
    }
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PolymorphError, match="unknown fields: review_onyl"):
        args.func(args)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda payload: payload.update(version=True), "version 1"),
        (lambda payload: payload["cases"][0].update(id=7), "invalid id"),
        (lambda payload: payload.update(provenance={"contains_customer_data": "no"}), "boolean"),
        (lambda payload: payload.update(provenance={"source": "made up"}), "unknown fields"),
    ],
)
def test_mapping_benchmark_rejects_ambiguous_manifest_metadata(tmp_path, mutation, message) -> None:
    payload = {
        "version": 1,
        "cases": [
            {
                "id": "case",
                "source_schema": {"id": "s", "fields": [{"id": "one", "name": "one"}]},
                "target_schema": {"id": "t", "fields": [{"id": "one", "name": "one"}]},
                "expected": {"one": "one"},
            }
        ],
    }
    mutation(payload)
    manifest = tmp_path / "corpus.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    args = build_parser().parse_args(["benchmark", "mapping", str(manifest)])

    with pytest.raises(PolymorphError, match=message):
        args.func(args)


def test_mapping_benchmark_rejects_unknown_lookup_key_fields(tmp_path) -> None:
    payload = {
        "version": 1,
        "cases": [
            {
                "id": "typed-relation",
                "source_schema": {"id": "s", "fields": [{"id": "one", "name": "one"}]},
                "target_schema": {
                    "id": "t",
                    "fields": [{"id": "one", "name": "one"}],
                    "relations": [
                        {
                            "source_field_id": "one",
                            "target_container": "parent",
                            "target_field": "id",
                            "lookup_keys": [
                                {"name": "business_key", "data_type": "string", "typo": True}
                            ],
                        }
                    ],
                },
                "expected": {"one": "one"},
            }
        ],
    }
    manifest = tmp_path / "corpus.json"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    args = build_parser().parse_args(["benchmark", "mapping", str(manifest)])

    with pytest.raises(PolymorphError, match="unknown fields: typo"):
        args.func(args)


@pytest.mark.parametrize(
    "extra_args, message",
    [
        (["--require-auto-precision", "1.01"], "between zero and one"),
        (["--require-automation-coverage", "-0.01"], "between zero and one"),
        (["--require-suggestion-accuracy", "1.01"], "between zero and one"),
        (["--max-unsafe-auto", "-1"], "must not be negative"),
    ],
)
def test_mapping_benchmark_validates_gate_ranges(extra_args, message) -> None:
    args = build_parser().parse_args(["benchmark", "mapping", "missing.json", *extra_args])

    with pytest.raises(ValueError, match=message):
        args.func(args)


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


def test_prepare_blast_limit_does_not_punish_a_valid_recipe(tmp_path, capsys) -> None:
    from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
    from polymorph.models.types import DataType
    from polymorph.recipes import RecipeHealthState, RecipeRunOutcome, RecipeStore
    from polymorph.serialization import save_schema

    source_path = tmp_path / "payload.unknown"
    source_path.write_text(
        '[{"customer id":"A-1"},{"customer id":"A-2"}]',
        encoding="utf-8",
    )
    target_path = tmp_path / "target.json"
    save_schema(
        target_path,
        SchemaDescriptor(
            "target",
            (FieldDescriptor("customer_id", "customer id", DataType.STRING, nullable=False),),
        ),
    )
    recipe_path = tmp_path / "recipes.sqlite3"
    base_arguments = [
        "prepare",
        str(source_path),
        str(target_path),
        "--recipe-store",
        str(recipe_path),
        "--remember",
    ]
    first_args = build_parser().parse_args(base_arguments)
    first_args.func(first_args)
    first = json.loads(capsys.readouterr().out)
    assert first["ready"] is True

    limited_args = build_parser().parse_args([*base_arguments, "--max-input-records", "1"])
    with pytest.raises(SystemExit) as stopped:
        limited_args.func(limited_args)
    limited = json.loads(capsys.readouterr().out)

    store = RecipeStore(recipe_path)
    recipe = store.get(first["recipe_id"])
    assert recipe is not None
    health = store.health(recipe)
    assert limited["ready"] is False
    assert stopped.value.code == 2
    assert limited["route_source"] == "recipe"
    assert limited["preflight"]["input_record_limit_exceeded"] is True
    assert health.state is RecipeHealthState.DEGRADED
    assert health.last_outcome is RecipeRunOutcome.QUARANTINED
    assert health.consecutive_rejections == 0
    assert health.auto_reuse_allowed


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


def test_event_summary_and_health_gate_are_machine_usable(tmp_path, capsys) -> None:
    from polymorph.observability import EventStream

    path = tmp_path / "operational-events.jsonl"
    run_id = "11" * 16
    stream = EventStream(path, run_id=run_id)
    correlation_id = stream.correlation_id("workflow")
    stream.emit(
        component="workflow_benchmark",
        event_type="workflow_started",
        status="started",
        correlation_id=correlation_id,
        item_count=0,
    )
    stream.emit(
        component="workflow_benchmark",
        event_type="workflow_completed",
        status="passed",
        correlation_id=correlation_id,
        item_count=0,
    )

    summary_args = build_parser().parse_args(["events", "summary", str(path), "--run-id", run_id])
    summary_args.func(summary_args)
    summary = json.loads(capsys.readouterr().out)
    assert summary["valid"] is True
    assert summary["events"] == 2
    assert summary["verification"] == "structural"

    check_args = build_parser().parse_args(["events", "check", str(path), "--run-id", run_id])
    check_args.func(check_args)
    healthy = json.loads(capsys.readouterr().out)
    assert healthy["healthy"] is True
    assert healthy["health_reasons"] == []
    assert healthy["health_diagnostics"] == []
    assert healthy["workflow_counts_valid"] is True

    stream.emit(
        component="destination_runtime",
        event_type="delivery",
        status="quarantined",
        correlation_id=stream.correlation_id("record"),
        reason_code="write_outcome_unknown",
        item_count=1,
    )
    with pytest.raises(SystemExit, match="10"):
        check_args.func(check_args)
    unhealthy = json.loads(capsys.readouterr().out)
    assert unhealthy["healthy"] is False
    assert unhealthy["unhealthy_statuses"] == {"quarantined": 1}
    assert unhealthy["health_reasons"] == [
        "operational_failure_status_present",
        "operational_run_not_closed",
    ]
    assert unhealthy["health_diagnostics"][0]["category"] == "observability"


def test_event_commands_reject_a_missing_stream(tmp_path) -> None:
    path = tmp_path / "missing-events.jsonl"
    args = build_parser().parse_args(["events", "summary", str(path)])

    with pytest.raises(PolymorphError, match="does not exist"):
        args.func(args)

    assert not path.exists()


def test_event_commands_do_not_follow_stream_symlinks(tmp_path) -> None:
    from polymorph.observability import EventStream

    target = tmp_path / "target.jsonl"
    EventStream(target, run_id="44" * 16).emit(
        component="runtime",
        event_type="workflow_started",
        status="started",
    )
    link = tmp_path / "link.jsonl"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    args = build_parser().parse_args(["events", "summary", str(link)])

    with pytest.raises(IntegrityError, match="not a regular file"):
        args.func(args)


def test_event_health_gate_rejects_duplicate_lifecycle_events(tmp_path, capsys) -> None:
    from polymorph.observability import EventStream

    path = tmp_path / "operational-events.jsonl"
    run_id = "22" * 16
    stream = EventStream(path, run_id=run_id)
    correlation_id = stream.correlation_id("workflow")
    for event_type, status in (
        ("workflow_started", "started"),
        ("workflow_started", "started"),
        ("workflow_completed", "passed"),
        ("workflow_completed", "passed"),
    ):
        stream.emit(
            component="workflow_benchmark",
            event_type=event_type,
            status=status,
            correlation_id=correlation_id,
            item_count=0,
        )

    args = build_parser().parse_args(["events", "check", str(path), "--run-id", run_id])
    with pytest.raises(SystemExit, match="10"):
        args.func(args)

    payload = json.loads(capsys.readouterr().out)
    assert payload["healthy"] is False
    assert payload["unclosed_run_count"] == 1
    assert payload["health_reasons"] == ["operational_run_not_closed"]


@pytest.mark.parametrize(
    "variant", ["out_of_order", "wrong_component", "wrong_correlation", "wrong_status"]
)
def test_event_health_gate_validates_lifecycle_semantics(tmp_path, capsys, variant: str) -> None:
    from polymorph.observability import EventStream

    path = tmp_path / f"{variant}.jsonl"
    run_id = "55" * 16
    stream = EventStream(path, run_id=run_id)
    first_id = "66" * 16
    second_id = "77" * 16 if variant == "wrong_correlation" else first_id
    events = [
        ("workflow_started", "started", first_id),
        (
            "workflow_completed",
            "started" if variant == "wrong_status" else "passed",
            second_id,
        ),
    ]
    if variant == "out_of_order":
        events.reverse()
    for event_type, status, correlation_id in events:
        stream.emit(
            component=(
                "destination_runtime"
                if variant == "wrong_component" and event_type == "workflow_started"
                else "workflow_benchmark"
            ),
            event_type=event_type,
            status=status,
            correlation_id=correlation_id,
            item_count=0,
        )

    args = build_parser().parse_args(["events", "check", str(path), "--run-id", run_id])
    with pytest.raises(SystemExit, match="10"):
        args.func(args)

    payload = json.loads(capsys.readouterr().out)
    assert payload["healthy"] is False
    assert payload["workflow_lifecycle_valid"] is False
    expected_reasons = ["operational_run_not_closed"]
    if variant in {"wrong_component", "wrong_status"}:
        expected_reasons.append("operational_event_contract_invalid")
    assert payload["health_reasons"] == expected_reasons


def test_event_health_gate_rejects_ambiguous_delivery(tmp_path, capsys) -> None:
    from polymorph.observability import EventStream

    path = tmp_path / "operational-events.jsonl"
    run_id = "33" * 16
    stream = EventStream(path, run_id=run_id)
    workflow_id = stream.correlation_id("workflow")
    stream.emit(
        component="workflow_benchmark",
        event_type="workflow_started",
        status="started",
        correlation_id=workflow_id,
        item_count=0,
    )
    stream.emit(
        component="destination_runtime",
        event_type="delivery",
        status="ambiguous",
        correlation_id=stream.correlation_id("record"),
        reason_code="write_outcome_unknown",
        item_count=1,
    )
    stream.emit(
        component="workflow_benchmark",
        event_type="workflow_completed",
        status="passed",
        correlation_id=workflow_id,
        item_count=0,
    )

    args = build_parser().parse_args(["events", "check", str(path), "--run-id", run_id])
    with pytest.raises(SystemExit, match="10"):
        args.func(args)

    payload = json.loads(capsys.readouterr().out)
    assert payload["healthy"] is False
    assert payload["unhealthy_statuses"] == {"ambiguous": 1}
    assert payload["reason_counts"] == {"write_outcome_unknown": 1}
    assert payload["health_reasons"] == ["operational_failure_status_present"]


def test_event_health_gate_rejects_invalid_intermediate_event_contract(tmp_path, capsys) -> None:
    from polymorph.observability import EventStream

    path = tmp_path / "invalid-event-contract.jsonl"
    run_id = "88" * 16
    stream = EventStream(path, run_id=run_id)
    workflow_id = stream.correlation_id("workflow")
    stream.emit(
        component="workflow_benchmark",
        event_type="workflow_started",
        status="started",
        correlation_id=workflow_id,
        item_count=0,
    )
    stream.emit(
        component="destination_runtime",
        event_type="delivery",
        status="started",
        correlation_id=stream.correlation_id("record"),
        item_count=1,
    )
    stream.emit(
        component="workflow_benchmark",
        event_type="workflow_completed",
        status="passed",
        correlation_id=workflow_id,
        item_count=0,
    )

    args = build_parser().parse_args(["events", "check", str(path), "--run-id", run_id])
    with pytest.raises(SystemExit, match="10"):
        args.func(args)

    payload = json.loads(capsys.readouterr().out)
    assert payload["workflow_lifecycle_valid"] is True
    assert payload["event_contract_valid"] is False
    assert payload["health_reasons"] == ["operational_event_contract_invalid"]


def test_event_health_gate_rejects_duplicate_event_ids(tmp_path, capsys) -> None:
    from polymorph.observability import EventStream

    path = tmp_path / "duplicate-event-id.jsonl"
    run_id = "99" * 16
    stream = EventStream(path, run_id=run_id)
    workflow_id = stream.correlation_id("workflow")
    stream.emit(
        component="workflow_benchmark",
        event_type="workflow_started",
        status="started",
        correlation_id=workflow_id,
        item_count=1,
    )
    delivery = stream.emit(
        component="destination_runtime",
        event_type="delivery",
        status="delivered",
        correlation_id=stream.correlation_id("record"),
        item_count=1,
    )
    stream.emit(
        component="workflow_benchmark",
        event_type="batch_completed",
        status="passed",
        correlation_id=stream.correlation_id("batch:1"),
        item_count=1,
    )
    stream.append(delivery)
    stream.emit(
        component="workflow_benchmark",
        event_type="workflow_completed",
        status="passed",
        correlation_id=workflow_id,
        item_count=1,
    )

    args = build_parser().parse_args(["events", "check", str(path), "--run-id", run_id])
    with pytest.raises(SystemExit, match="10"):
        args.func(args)

    payload = json.loads(capsys.readouterr().out)
    assert payload["workflow_lifecycle_valid"] is True
    assert payload["event_ids_unique"] is False
    assert payload["duplicate_event_ids"] == 1
    assert payload["health_reasons"] == [
        "operational_event_contract_invalid",
        "operational_workflow_count_mismatch",
    ]


def test_event_health_gate_rejects_missing_required_item_counts(tmp_path, capsys) -> None:
    from polymorph.observability import EventStream

    path = tmp_path / "missing-event-counts.jsonl"
    run_id = "aa" * 16
    stream = EventStream(path, run_id=run_id)
    workflow_id = stream.correlation_id("workflow")
    stream.emit(
        component="workflow_benchmark",
        event_type="workflow_started",
        status="started",
        correlation_id=workflow_id,
    )
    stream.emit(
        component="workflow_benchmark",
        event_type="workflow_completed",
        status="passed",
        correlation_id=workflow_id,
    )

    args = build_parser().parse_args(["events", "check", str(path), "--run-id", run_id])
    with pytest.raises(SystemExit, match="10"):
        args.func(args)

    payload = json.loads(capsys.readouterr().out)
    assert payload["workflow_lifecycle_valid"] is True
    assert payload["event_contract_valid"] is False
    assert payload["workflow_counts_valid"] is False
    assert payload["health_reasons"] == [
        "operational_event_contract_invalid",
        "operational_workflow_count_mismatch",
    ]


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

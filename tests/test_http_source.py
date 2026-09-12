from __future__ import annotations

import json

import httpx
import pytest

from polymorph.connectors.http_json import (
    HttpEndpoint,
    HttpJsonConnector,
    HttpJsonSourceConnector,
    HttpPagination,
    HttpSourceEndpoint,
    PaginationMode,
)
from polymorph.errors import (
    ConnectorError,
    ConnectorWriteError,
    PartialConnectorWriteError,
    ProtocolError,
    WriteOutcome,
)
from polymorph.models.schema import SchemaDescriptor
from polymorph.models.types import DataType, Sensitivity
from polymorph.work_budget import WorkBudget


def test_http_json_source_infers_schema_without_transforming_values() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "example.test"
        assert request.url.params["page"] == "1"
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={
                "data": [
                    {"customer_number": "000042", "amount": 12.5, "api_token": "s1"},
                    {"customer_number": "000043", "amount": 3, "api_token": "s2"},
                ]
            },
        )

    connector = HttpJsonSourceConnector(
        HttpSourceEndpoint(
            "https://example.test",
            "/orders",
            records_pointer="/data",
            pagination=HttpPagination(mode=PaginationMode.NONE),
            query={"page": "1"},
        ),
        transport=httpx.MockTransport(handler),
    )
    schema = connector.inspect_schema()
    by_id = schema.by_id()
    assert by_id["customer_number"].data_type is DataType.STRING
    assert by_id["api_token"].sensitivity is Sensitivity.SECRET
    records = list(connector.iter_records())
    assert records[0]["customer_number"] == "000042"
    assert records[0]["api_token"] == "s1"


def test_http_cursor_pagination_is_bounded_and_detects_loops() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"data": [{"id": calls}], "next": "same"},
        )

    connector = HttpJsonSourceConnector(
        HttpSourceEndpoint(
            "https://example.test",
            "/items",
            records_pointer="/data",
            pagination=HttpPagination(
                mode=PaginationMode.CURSOR,
                parameter="cursor",
                next_pointer="/next",
            ),
        ),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ProtocolError, match="repeated a cursor"):
        list(connector.iter_records())


def test_http_source_rejects_oversized_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.dumps([{"value": "x" * 4096}]).encode()
        return httpx.Response(200, headers={"content-type": "application/json"}, content=body)

    connector = HttpJsonSourceConnector(
        HttpSourceEndpoint("https://example.test", "/data"),
        max_response_bytes=1024,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ConnectorError, match="size limit"):
        list(connector.iter_records())


def test_http_source_enforces_json_complexity_and_total_records() -> None:
    nested = HttpJsonSourceConnector(
        HttpSourceEndpoint("https://example.test", "/data"),
        work_budget=WorkBudget(max_structure_depth=2),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"outer": {"inner": 1}})
        ),
    )
    with pytest.raises(ConnectorError, match="max_structure_depth"):
        list(nested.iter_records())

    records = HttpJsonSourceConnector(
        HttpSourceEndpoint("https://example.test", "/data"),
        work_budget=WorkBudget(max_total_records=2),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=[{"id": 1}, {"id": 2}, {"id": 3}])
        ),
    )
    with pytest.raises(ConnectorError, match="max_total_records"):
        list(records.iter_records())


def test_http_source_rejects_cross_host_endpoint() -> None:
    with pytest.raises(ValueError, match="escape"):
        HttpJsonSourceConnector(
            HttpSourceEndpoint("https://example.test/base", "https://evil.test/data")
        )


@pytest.mark.parametrize(
    "body",
    [
        b'{"data":[{"id":1,"id":2}]}',
        b'{"data":[{"amount":NaN}]}',
    ],
)
def test_http_source_rejects_noncanonical_json(body: bytes) -> None:
    connector = HttpJsonSourceConnector(
        HttpSourceEndpoint("https://example.test", "/data", records_pointer="/data"),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=body,
            )
        ),
    )

    with pytest.raises(ConnectorError, match="invalid JSON"):
        list(connector.iter_records())


def test_http_idempotency_requires_an_explicit_endpoint_contract() -> None:
    schema = SchemaDescriptor("target", ())
    advisory = HttpJsonConnector(
        HttpEndpoint(
            "https://example.test",
            "/records",
            idempotency_header="Idempotency-Key",
        ),
        schema,
    )
    asserted = HttpJsonConnector(
        HttpEndpoint(
            "https://example.test",
            "/records",
            idempotency_header="Idempotency-Key",
            idempotency_contract=True,
        ),
        schema,
    )

    assert not advisory.capabilities.supports_idempotency
    assert advisory.capabilities.idempotency_contract_id is None
    assert asserted.capabilities.supports_idempotency
    assert (
        asserted.capabilities.idempotency_contract_id
        == "polymorph.http-json.single-record-delivery-key/v1"
    )


@pytest.mark.parametrize("header", ["Bad Header", "Authorization", "Content-Length"])
def test_http_idempotency_header_rejects_unsafe_names(header: str) -> None:
    with pytest.raises(ValueError, match="header"):
        HttpJsonConnector(
            HttpEndpoint(
                "https://example.test",
                "/records",
                idempotency_header=header,
            ),
            SchemaDescriptor("target", ()),
        )


@pytest.mark.parametrize("status", (301, 302, 307, 308))
def test_http_destination_never_counts_redirect_as_committed(status: int) -> None:
    connector = HttpJsonConnector(
        HttpEndpoint("https://example.test", "/records"),
        SchemaDescriptor("target", ()),
        transport=httpx.MockTransport(lambda request: httpx.Response(status)),
    )

    with pytest.raises(ConnectorWriteError) as caught:
        connector.write_records([{"value": "must-not-count"}])

    assert caught.value.outcome is WriteOutcome.UNKNOWN


def test_http_budget_before_first_request_is_not_committed() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(201)

    connector = HttpJsonConnector(
        HttpEndpoint("https://example.test", "/records"),
        SchemaDescriptor("target", ()),
        work_budget=WorkBudget(max_total_bytes=1),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(ConnectorWriteError) as caught:
        connector.write_records([{"id": 1}])

    assert not isinstance(caught.value, PartialConnectorWriteError)
    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert requests == 0


def test_http_budget_after_committed_prefix_is_structured_and_resumable() -> None:
    committed: list[object] = []

    def handler(request: httpx.Request) -> httpx.Response:
        committed.append(json.loads(request.content))
        return httpx.Response(201)

    records = [{"id": 1}, {"id": 2}]
    first_size = len(json.dumps(records[0], separators=(",", ":")).encode("utf-8"))
    connector = HttpJsonConnector(
        HttpEndpoint("https://example.test", "/records"),
        SchemaDescriptor("target", ()),
        work_budget=WorkBudget(max_total_bytes=first_size),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(PartialConnectorWriteError) as caught:
        connector.write_records(records)

    assert caught.value.outcome is WriteOutcome.PARTIAL
    assert caught.value.committed_count == 1
    assert caught.value.next_record_index == 1
    assert caught.value.next_record_outcome is WriteOutcome.NOT_COMMITTED
    assert committed == [records[0]]

    resumed = HttpJsonConnector(
        HttpEndpoint("https://example.test", "/records"),
        SchemaDescriptor("target", ()),
        transport=httpx.MockTransport(handler),
    )
    assert resumed.write_records(records[caught.value.next_record_index :]) == 1
    assert committed == records


def test_http_destination_sends_exact_budgeted_json_bytes() -> None:
    seen: list[bytes] = []
    record = {"currency": "EUR", "amount": 12.5}
    encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.content)
        return httpx.Response(204)

    connector = HttpJsonConnector(
        HttpEndpoint("https://example.test", "/records"),
        SchemaDescriptor("target", ()),
        work_budget=WorkBudget(max_total_bytes=len(encoded)),
        transport=httpx.MockTransport(handler),
    )
    assert connector.write_records([record]) == 1
    assert seen == [encoded]


def test_http_destination_does_not_materialize_response_body() -> None:
    class UnreadableBody(httpx.SyncByteStream):
        closed = False

        def __iter__(self):
            raise AssertionError("destination response body was read")

        def close(self) -> None:
            self.closed = True

    body = UnreadableBody()
    connector = HttpJsonConnector(
        HttpEndpoint("https://example.test", "/records"),
        SchemaDescriptor("target", ()),
        transport=httpx.MockTransport(lambda request: httpx.Response(201, stream=body)),
    )

    assert connector.write_records([{"id": 1}]) == 1
    assert body.closed


def test_http_single_record_idempotency_contract_rejects_batch_before_write() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(201)

    connector = HttpJsonConnector(
        HttpEndpoint(
            "https://example.test",
            "/records",
            idempotency_header="Idempotency-Key",
            idempotency_contract=True,
        ),
        SchemaDescriptor("target", ()),
        transport=httpx.MockTransport(handler),
    )
    from polymorph.connectors.base import DeliveryContext

    with pytest.raises(ConnectorWriteError) as caught:
        connector.write_records(
            [{"id": 1}, {"id": 2}],
            context=DeliveryContext(
                idempotency_key="safe-key",
                transfer_id="transfer-1",
                record_id="record-1",
                record_digest="a" * 64,
            ),
        )

    assert caught.value.outcome is WriteOutcome.NOT_COMMITTED
    assert requests == 0


def test_http_iterator_failure_after_commit_preserves_prefix() -> None:
    committed: list[object] = []

    def handler(request: httpx.Request) -> httpx.Response:
        committed.append(json.loads(request.content))
        return httpx.Response(201)

    def records():
        yield {"id": 1}
        raise RuntimeError("input failed")

    connector = HttpJsonConnector(
        HttpEndpoint("https://example.test", "/records"),
        SchemaDescriptor("target", ()),
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(PartialConnectorWriteError) as caught:
        connector.write_records(records())

    assert caught.value.committed_count == 1
    assert caught.value.next_record_outcome is WriteOutcome.NOT_COMMITTED
    assert committed == [{"id": 1}]

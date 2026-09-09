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
from polymorph.errors import ConnectorError, ConnectorWriteError, ProtocolError, WriteOutcome
from polymorph.models.schema import SchemaDescriptor
from polymorph.models.types import DataType, Sensitivity


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
    assert asserted.capabilities.supports_idempotency


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

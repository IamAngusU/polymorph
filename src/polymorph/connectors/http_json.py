from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import urljoin, urlparse

import httpx

from polymorph.classification import classify_field_name, infer_role
from polymorph.errors import ConnectorError, ConnectorWriteError, ProtocolError, WriteOutcome
from polymorph.models.schema import FieldDescriptor, SchemaDescriptor
from polymorph.models.types import Sensitivity
from polymorph.secrets import SecretProvider

from .base import ConnectorCapabilities, DeliveryContext
from .inference import merge_types, runtime_type

_HTTP_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_RESERVED_IDEMPOTENCY_HEADERS = frozenset(
    {
        "authorization",
        "connection",
        "content-length",
        "content-type",
        "cookie",
        "host",
        "proxy-authorization",
        "set-cookie",
        "transfer-encoding",
    }
)


def _object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("HTTP JSON response contains a duplicate object key")
        output[key] = value
    return output


def _reject_nonfinite_constant(value: str) -> object:
    raise ValueError(f"HTTP JSON response contains non-finite number {value}")


@dataclass(frozen=True, slots=True)
class HttpEndpoint:
    base_url: str
    path: str
    method: str = "POST"
    credential_ref: str | None = None
    idempotency_header: str | None = None
    idempotency_contract: bool = False


class HttpJsonConnector:
    """Restricted JSON-over-HTTPS destination.

    Endpoint discovery and arbitrary URL following are deliberately excluded from this
    connector. The configured host is an execution boundary, not a suggestion.
    """

    def __init__(
        self,
        endpoint: HttpEndpoint,
        schema: SchemaDescriptor,
        *,
        secret_provider: SecretProvider | None = None,
        timeout: float = 20.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.endpoint = endpoint
        self._schema = schema
        self._secret_provider = secret_provider
        self._timeout = timeout
        self._transport = transport
        self.capabilities = ConnectorCapabilities(
            read_schema=True,
            write_records=True,
            supports_idempotency=(
                endpoint.idempotency_header is not None and endpoint.idempotency_contract
            ),
        )
        self._url = _validated_url(endpoint.base_url, endpoint.path)

        if endpoint.method.upper() not in {"POST", "PUT", "PATCH"}:
            raise ValueError("unsupported HTTP write method")
        if endpoint.idempotency_header is not None:
            _validate_header_name(endpoint.idempotency_header)
        if endpoint.idempotency_contract and endpoint.idempotency_header is None:
            raise ValueError("HTTP idempotency contract requires a configured header")

    def inspect_schema(self) -> SchemaDescriptor:
        return self._schema

    def write_records(
        self,
        records: Iterable[Mapping[str, object]],
        *,
        context: DeliveryContext | None = None,
    ) -> int:
        headers = {"content-type": "application/json", "accept": "application/json"}
        _attach_bearer(headers, self.endpoint.credential_ref, self._secret_provider)
        if self.endpoint.idempotency_header is not None:
            if context is None:
                raise ConnectorError("idempotent HTTP destination requires delivery context")
            headers[self.endpoint.idempotency_header] = context.idempotency_key

        count = 0
        with httpx.Client(
            timeout=self._timeout,
            follow_redirects=False,
            trust_env=False,
            transport=self._transport,
        ) as client:
            for record in records:
                try:
                    response = client.request(
                        self.endpoint.method.upper(),
                        self._url,
                        json=dict(record),
                        headers=headers,
                    )
                except httpx.HTTPError as exc:
                    raise ConnectorWriteError(
                        "HTTP destination write outcome is unknown",
                        outcome=WriteOutcome.UNKNOWN,
                    ) from exc
                if not 200 <= response.status_code < 300:
                    # A response status does not prove that a custom endpoint made no side
                    # effects. Treat it conservatively unless a future endpoint contract
                    # explicitly provides stronger semantics.
                    raise ConnectorWriteError(
                        f"HTTP destination rejected record with status {response.status_code}",
                        outcome=WriteOutcome.UNKNOWN,
                    )
                count += 1
        return count


class PaginationMode(StrEnum):
    NONE = "none"
    PAGE = "page"
    OFFSET = "offset"
    CURSOR = "cursor"


@dataclass(frozen=True, slots=True)
class HttpPagination:
    mode: PaginationMode = PaginationMode.NONE
    parameter: str = "page"
    start: int = 1
    step: int = 1
    next_pointer: str | None = None
    max_pages: int = 1000

    def __post_init__(self) -> None:
        if not self.parameter or any(ch in self.parameter for ch in "\r\n&="):
            raise ValueError("invalid HTTP pagination parameter")
        if self.step <= 0:
            raise ValueError("HTTP pagination step must be positive")
        if not 1 <= self.max_pages <= 100_000:
            raise ValueError("HTTP pagination max_pages is outside supported range")
        if self.mode is PaginationMode.CURSOR and not self.next_pointer:
            raise ValueError("cursor pagination requires next_pointer")


@dataclass(frozen=True, slots=True)
class HttpSourceEndpoint:
    base_url: str
    path: str
    credential_ref: str | None = None
    records_pointer: str = ""
    query: Mapping[str, str] = field(default_factory=dict)
    pagination: HttpPagination = field(default_factory=HttpPagination)


class HttpJsonSourceConnector:
    """Read-only HTTPS JSON source with bounded, explicit pagination.

    It infers only schema metadata. Payload values remain local to the source connector and
    are yielded unchanged to the source agent.
    """

    capabilities = ConnectorCapabilities(read_schema=True, read_records=True)

    def __init__(
        self,
        endpoint: HttpSourceEndpoint,
        *,
        secret_provider: SecretProvider | None = None,
        sensitivity_overrides: Mapping[str, Sensitivity] | None = None,
        timeout: float = 20.0,
        max_response_bytes: int = 16 * 1024 * 1024,
        schema_sample_records: int = 256,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if max_response_bytes < 1024:
            raise ValueError("HTTP response limit is too small")
        if schema_sample_records < 1:
            raise ValueError("schema_sample_records must be positive")
        self.endpoint = endpoint
        self._url = _validated_url(endpoint.base_url, endpoint.path)
        self._secret_provider = secret_provider
        self.sensitivity_overrides = dict(sensitivity_overrides or {})
        self._timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.schema_sample_records = schema_sample_records
        self._transport = transport
        self._schema_cache: SchemaDescriptor | None = None

    def _headers(self) -> dict[str, str]:
        headers = {"accept": "application/json"}
        _attach_bearer(headers, self.endpoint.credential_ref, self._secret_provider)
        return headers

    def _request_json(
        self,
        client: httpx.Client,
        params: Mapping[str, str],
    ) -> object:
        with client.stream(
            "GET", self._url, params=dict(params), headers=self._headers()
        ) as response:
            if response.status_code >= 400:
                raise ConnectorError(
                    f"HTTP source rejected request with status {response.status_code}"
                )
            media_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if media_type and media_type != "application/json" and not media_type.endswith("+json"):
                raise ConnectorError("HTTP source response is not JSON")
            buffer = bytearray()
            for chunk in response.iter_bytes():
                buffer.extend(chunk)
                if len(buffer) > self.max_response_bytes:
                    raise ConnectorError("HTTP source response exceeds configured size limit")
        try:
            return json.loads(
                buffer,
                object_pairs_hook=_object_without_duplicate_keys,
                parse_constant=_reject_nonfinite_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ConnectorError("HTTP source returned invalid JSON") from exc

    @staticmethod
    def _records_from(payload: object, pointer: str) -> list[Mapping[str, object]]:
        selected = _json_pointer(payload, pointer)
        if isinstance(selected, Mapping):
            return [selected]
        if isinstance(selected, list) and all(isinstance(item, Mapping) for item in selected):
            return list(selected)
        raise ConnectorError("configured records pointer does not select object records")

    def _iter(self, *, max_records: int | None = None) -> Iterable[Mapping[str, object]]:
        pagination = self.endpoint.pagination
        static_params = {str(key): str(value) for key, value in self.endpoint.query.items()}
        position = pagination.start
        cursor: str | None = None
        emitted = 0
        seen_cursors: set[str] = set()

        with httpx.Client(
            timeout=self._timeout,
            follow_redirects=False,
            trust_env=False,
            transport=self._transport,
        ) as client:
            for _page_index in range(pagination.max_pages):
                params = dict(static_params)
                if pagination.mode in {PaginationMode.PAGE, PaginationMode.OFFSET}:
                    params[pagination.parameter] = str(position)
                elif pagination.mode is PaginationMode.CURSOR and cursor is not None:
                    params[pagination.parameter] = cursor

                payload = self._request_json(client, params)
                records = self._records_from(payload, self.endpoint.records_pointer)
                if not records:
                    break
                for record in records:
                    yield record
                    emitted += 1
                    if max_records is not None and emitted >= max_records:
                        return

                if pagination.mode is PaginationMode.NONE:
                    return
                if pagination.mode in {PaginationMode.PAGE, PaginationMode.OFFSET}:
                    position += pagination.step
                    continue

                assert pagination.next_pointer is not None
                next_value = _json_pointer(payload, pagination.next_pointer)
                if next_value in {None, ""}:
                    return
                cursor = str(next_value)
                if cursor in seen_cursors:
                    raise ProtocolError("HTTP cursor pagination repeated a cursor")
                seen_cursors.add(cursor)
            else:
                raise ProtocolError("HTTP pagination reached configured page limit")

    def inspect_schema(self) -> SchemaDescriptor:
        if self._schema_cache is not None:
            return self._schema_cache
        records = list(self._iter(max_records=self.schema_sample_records))
        if not records:
            raise ConnectorError("HTTP source returned no records for schema inference")
        keys = sorted({str(key) for record in records for key in record})
        fields: list[FieldDescriptor] = []
        for key in keys:
            values = [record.get(key) for record in records]
            observed = [runtime_type(value) for value in values if value is not None]
            fields.append(
                FieldDescriptor(
                    id=key,
                    name=key,
                    data_type=merge_types(observed),
                    nullable=any(value is None for value in values),
                    sensitivity=self.sensitivity_overrides.get(key, classify_field_name(key)),
                    role=infer_role(key),
                )
            )
        target = urlparse(self._url)
        self._schema_cache = SchemaDescriptor(
            id=f"http-json:{target.hostname}{target.path}",
            fields=tuple(fields),
            metadata={
                "host": target.hostname or "",
                "path": target.path,
                "pagination": self.endpoint.pagination.mode.value,
            },
        )
        return self._schema_cache

    def iter_records(self) -> Iterable[Mapping[str, object]]:
        yield from self._iter()


def _validated_url(base_url: str, path: str) -> str:
    base = urlparse(base_url)
    target = urlparse(urljoin(base_url.rstrip("/") + "/", path.lstrip("/")))
    if base.scheme != "https" or target.scheme != "https":
        raise ValueError("HTTP connector requires HTTPS")
    if base.hostname is None or target.hostname is None:
        raise ValueError("HTTP connector requires a valid hostname")
    if base.username is not None or base.password is not None:
        raise ValueError("credentials must not be embedded in HTTP URLs")
    if (base.hostname, base.port) != (target.hostname, target.port):
        raise ValueError("endpoint path may not escape configured host or port")
    if target.username is not None or target.password is not None:
        raise ValueError("credentials must not be embedded in HTTP URLs")
    return target.geturl()


def _validate_header_name(value: str) -> None:
    header = value.strip()
    if not _HTTP_TOKEN.fullmatch(header):
        raise ValueError("invalid HTTP header name")
    if header.casefold() in _RESERVED_IDEMPOTENCY_HEADERS:
        raise ValueError("idempotency header may not replace a reserved HTTP header")


def _attach_bearer(
    headers: dict[str, str],
    credential_ref: str | None,
    provider: SecretProvider | None,
) -> None:
    if credential_ref is None:
        return
    if provider is None:
        raise ConnectorError("credential provider is required")
    token = provider.get(credential_ref)
    if "\r" in token or "\n" in token:
        raise ConnectorError("credential provider returned an invalid token")
    headers["authorization"] = f"Bearer {token}"


def _json_pointer(payload: object, pointer: str) -> object:
    if pointer in {"", "/"}:
        return payload
    if not pointer.startswith("/"):
        raise ValueError("JSON pointer must be empty or start with '/'")
    current = payload
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if token not in current:
                raise ConnectorError("configured JSON pointer was not found")
            current = current[token]
        elif isinstance(current, list):
            try:
                index = int(token)
                current = current[index]
            except (ValueError, IndexError) as exc:
                raise ConnectorError(
                    "configured JSON pointer contains an invalid list index"
                ) from exc
        else:
            raise ConnectorError("configured JSON pointer traverses a scalar value")
    return current

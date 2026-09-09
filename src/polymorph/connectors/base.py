from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol

from polymorph.models.schema import SchemaDescriptor


@dataclass(frozen=True, slots=True)
class ConnectorCapabilities:
    read_schema: bool = True
    read_records: bool = False
    write_records: bool = False
    transactional_write: bool = False
    supports_idempotency: bool = False


@dataclass(frozen=True, slots=True)
class DeliveryContext:
    """Opaque delivery metadata that a destination may use for idempotency.

    It contains identifiers only and never contains record values.
    """

    transfer_id: str
    record_id: str
    record_digest: str
    idempotency_key: str


class SourceConnector(Protocol):
    capabilities: ConnectorCapabilities

    def inspect_schema(self) -> SchemaDescriptor: ...

    def iter_records(self) -> Iterable[Mapping[str, object]]: ...


class DestinationConnector(Protocol):
    capabilities: ConnectorCapabilities

    def inspect_schema(self) -> SchemaDescriptor: ...

    def write_records(
        self,
        records: Iterable[Mapping[str, object]],
        *,
        context: DeliveryContext | None = None,
    ) -> int: ...

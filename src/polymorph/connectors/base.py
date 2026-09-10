from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from polymorph.models.schema import SchemaDescriptor

MAX_IDEMPOTENCY_CONTRACT_ID_LENGTH = 128


@dataclass(frozen=True, slots=True)
class AtomicBatchCapabilities:
    """Hard limits and replay semantics for an all-or-nothing batch writer."""

    max_records: int
    max_wire_bytes: int
    per_item_idempotency_across_batch_and_scalar: bool = False

    def __post_init__(self) -> None:
        for name, value in (
            ("max_records", self.max_records),
            ("max_wire_bytes", self.max_wire_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"atomic batch {name} must be a positive integer")
        if not isinstance(self.per_item_idempotency_across_batch_and_scalar, bool):
            raise ValueError("atomic batch cross-path idempotency must be a boolean")


@dataclass(frozen=True, slots=True)
class ConnectorCapabilities:
    """Immutable connector contract captured once at each runtime operation boundary.

    A trusted connector may replace its capabilities between operations. Replacing them while
    an operation is in flight is unsupported and causes the runtime to stop before writing.
    """

    read_schema: bool = True
    read_records: bool = False
    write_records: bool = False
    transactional_write: bool = False
    supports_idempotency: bool = False
    idempotency_contract_id: str | None = None
    atomic_batch_write: AtomicBatchCapabilities | None = None

    def __post_init__(self) -> None:
        contract_id = self.idempotency_contract_id
        if self.supports_idempotency:
            if (
                not isinstance(contract_id, str)
                or not contract_id
                or len(contract_id) > MAX_IDEMPOTENCY_CONTRACT_ID_LENGTH
                or not contract_id.isprintable()
                or contract_id != contract_id.strip()
            ):
                raise ValueError(
                    "idempotent connectors require a bounded printable idempotency contract id"
                )
        elif contract_id is not None:
            raise ValueError(
                "idempotency contract id requires the connector to support idempotency"
            )


@dataclass(frozen=True, slots=True)
class DeliveryContext:
    """Opaque delivery metadata that a destination may use for idempotency.

    It contains identifiers only and never contains record values.
    """

    transfer_id: str
    record_id: str
    record_digest: str
    idempotency_key: str


@dataclass(frozen=True, slots=True, repr=False)
class BatchWriteItem:
    """One plaintext row and its payload-free delivery identity for an atomic batch.

    ``wire_bytes`` is the exact size of the authenticated sealed transport record. It lets
    connectors enforce a memory and transaction budget without receiving or retaining another
    copy of those wire bytes.
    """

    values: Mapping[str, object]
    context: DeliveryContext
    wire_bytes: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.wire_bytes, bool)
            or not isinstance(self.wire_bytes, int)
            or self.wire_bytes <= 0
        ):
            raise ValueError("batch item wire_bytes must be a positive integer")


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


class AtomicBatchDestinationConnector(DestinationConnector, Protocol):
    """Destination whose batch either commits every item or commits no item.

    The commit result is synchronous. The runtime drops its own plaintext references after the
    call but never mutates connector-visible mappings. Implementations that retain plaintext are
    responsible for its lifecycle and protection inside the destination trust boundary.
    """

    def write_batch(self, items: Sequence[BatchWriteItem]) -> int: ...

from __future__ import annotations

import base64
import hashlib
import json
import math
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .crypto import OpaqueEnvelope, TransferContext, open_envelope, seal_for_recipient
from .errors import IntegrityError, ProtocolError
from .models.mapping import MappingPlan
from .models.schema import SchemaDescriptor
from .models.types import Sensitivity
from .policy import PolicyEngine
from .transforms import TransformStage, apply_transform, transform_stage
from .validation import PlanValidator


class PayloadCodec:
    """Canonical payload encoding used only inside encrypted envelopes."""

    @staticmethod
    def encode(value: object) -> bytes:
        if isinstance(value, Decimal):
            payload = {"kind": "decimal", "value": str(value)}
        elif isinstance(value, datetime):
            payload = {"kind": "datetime", "value": value.isoformat()}
        elif isinstance(value, date):
            payload = {"kind": "date", "value": value.isoformat()}
        elif isinstance(value, bytes):
            payload = {
                "kind": "bytes",
                "value": base64.urlsafe_b64encode(value).decode("ascii"),
            }
        else:
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("non-finite floats are not transportable")
            payload = {"kind": "json", "value": value}
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode(
            "utf-8"
        )

    @staticmethod
    def decode(payload: bytes) -> object:
        data = json.loads(payload.decode("utf-8"))
        kind = data["kind"]
        value = data["value"]
        if kind == "decimal":
            return Decimal(value)
        if kind == "datetime":
            return datetime.fromisoformat(value)
        if kind == "date":
            return date.fromisoformat(value)
        if kind == "bytes":
            return base64.urlsafe_b64decode(value.encode("ascii"))
        if kind == "json":
            return value
        raise ValueError("unsupported payload kind")


@dataclass(frozen=True, slots=True)
class ProtocolLimits:
    max_fields_per_record: int = 4096
    max_ciphertext_bytes_per_field: int = 16 * 1024 * 1024
    max_record_wire_bytes: int = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True, repr=False)
class SealedField:
    target_field_id: str
    context: TransferContext
    envelope: OpaqueEnvelope

    def __repr__(self) -> str:
        return f"SealedField(target_field_id={self.target_field_id!r}, <sealed>)"

    def to_wire(self) -> dict[str, object]:
        return {
            "target_field_id": self.target_field_id,
            "context": self.context.to_wire(),
            "envelope": self.envelope.to_wire(),
        }

    @classmethod
    def from_wire(cls, payload: dict[str, object], limits: ProtocolLimits) -> "SealedField":
        context = TransferContext.from_wire(dict(payload["context"]))
        envelope = OpaqueEnvelope.from_wire(
            dict(payload["envelope"]),
            max_ciphertext_bytes=limits.max_ciphertext_bytes_per_field,
        )
        return cls(str(payload["target_field_id"]), context, envelope)


@dataclass(frozen=True, slots=True, repr=False)
class BlindTransportRecord:
    record_id: str
    fields: tuple[SealedField, ...]

    def __post_init__(self) -> None:
        if not self.fields:
            raise ProtocolError("blind transport record must contain at least one field")
        field_ids: set[str] = set()
        first = self.fields[0].context
        for item in self.fields:
            if item.target_field_id in field_ids:
                raise ProtocolError("blind transport record contains a duplicate target field")
            field_ids.add(item.target_field_id)
            context = item.context
            if item.target_field_id != context.field_id:
                raise ProtocolError("sealed field id does not match authenticated field id")
            if context.record_id != self.record_id:
                raise ProtocolError("record id does not match authenticated context")
            for name in (
                "tenant",
                "source_connector",
                "destination_connector",
                "transfer_id",
                "plan_id",
                "plan_digest",
                "schema_version",
                "protocol_version",
            ):
                if getattr(context, name) != getattr(first, name):
                    raise ProtocolError(f"mixed {name} values in one blind transport record")

    def __repr__(self) -> str:
        field_ids = ", ".join(field.target_field_id for field in self.fields)
        return f"BlindTransportRecord(record_id={self.record_id!r}, fields=[{field_ids}], <sealed>)"

    @property
    def transfer_id(self) -> str:
        return self.fields[0].context.transfer_id

    @property
    def tenant(self) -> str:
        return self.fields[0].context.tenant

    @property
    def source_connector(self) -> str:
        return self.fields[0].context.source_connector

    @property
    def destination_connector(self) -> str:
        return self.fields[0].context.destination_connector

    @property
    def plan_id(self) -> str:
        return self.fields[0].context.plan_id

    @property
    def plan_digest(self) -> str:
        return self.fields[0].context.plan_digest

    def to_wire(self) -> dict[str, object]:
        return {
            "protocol": "opaque-record",
            "version": self.fields[0].context.protocol_version,
            "record_id": self.record_id,
            "fields": [item.to_wire() for item in self.fields],
        }

    def canonical_wire_bytes(self) -> bytes:
        return json.dumps(
            self.to_wire(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_wire_bytes()).hexdigest()

    @classmethod
    def from_wire(
        cls,
        payload: dict[str, object],
        *,
        limits: ProtocolLimits | None = None,
    ) -> "BlindTransportRecord":
        limits = limits or ProtocolLimits()
        if payload.get("protocol") != "opaque-record":
            raise ProtocolError("unsupported transport record protocol")
        if int(payload.get("version", 0)) != 2:
            raise ProtocolError("unsupported transport record version")
        raw_fields = payload.get("fields")
        if not isinstance(raw_fields, list) or not raw_fields:
            raise ProtocolError("transport record fields must be a non-empty list")
        if len(raw_fields) > limits.max_fields_per_record:
            raise ProtocolError("transport record exceeds field count limit")
        approx = len(
            json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        )
        if approx > limits.max_record_wire_bytes:
            raise ProtocolError("transport record exceeds wire size limit")
        fields = tuple(SealedField.from_wire(dict(item), limits) for item in raw_fields)
        return cls(record_id=str(payload["record_id"]), fields=fields)


@dataclass(slots=True)
class BlindSourceAgent:
    """Executes value-dependent work at the source trust boundary, then seals every field."""

    tenant: str
    source_connector_id: str
    destination_connector_id: str
    source_schema: SchemaDescriptor
    target_schema: SchemaDescriptor
    plan: MappingPlan
    destination_public_key: bytes
    schema_version: str = "1"
    transfer_ttl: timedelta | None = None

    def __post_init__(self) -> None:
        PlanValidator().validate(self.plan, self.source_schema, self.target_schema).raise_if_invalid()

    def prepare_record(
        self,
        record: Mapping[str, object],
        *,
        record_id: str,
        transfer_id: str | None = None,
    ) -> BlindTransportRecord:
        transfer_id = transfer_id or str(uuid.uuid4())
        source_fields = self.source_schema.by_id()
        target_fields = self.target_schema.by_id()
        policy = PolicyEngine()
        sealed: list[SealedField] = []
        issued_at = datetime.now(UTC)
        expires_at = issued_at + self.transfer_ttl if self.transfer_ttl is not None else None
        plan_digest = self.plan.digest()

        for rule in self.plan.rules:
            source = source_fields[rule.source_field_id]
            target = target_fields[rule.target_field_id]
            policy.validate_route(source, target, rule.transform)
            value = record.get(source.id)

            stage = transform_stage(rule.transform)
            if source.sensitivity in {Sensitivity.SECRET, Sensitivity.OPAQUE}:
                transformed = value
            elif stage is TransformStage.SOURCE:
                transformed = apply_transform(rule.transform, value, rule.parameters)
            else:
                # Destination-stage operations need the original source value but execute
                # only after the envelope crosses into the destination trust boundary.
                transformed = value

            context = TransferContext(
                tenant=self.tenant,
                source_connector=self.source_connector_id,
                destination_connector=self.destination_connector_id,
                field_id=target.id,
                schema_version=self.schema_version,
                record_id=record_id,
                transfer_id=transfer_id,
                plan_id=self.plan.id,
                plan_digest=plan_digest,
                protocol_version=2,
                issued_at=issued_at,
                expires_at=expires_at,
            )
            envelope = seal_for_recipient(
                PayloadCodec.encode(transformed),
                self.destination_public_key,
                context,
            )
            sealed.append(SealedField(target.id, context, envelope))

        return BlindTransportRecord(record_id=record_id, fields=tuple(sealed))


@dataclass(slots=True)
class BlindDestinationAgent:
    """Opens blind transport records only inside the destination trust boundary."""

    private_key: X25519PrivateKey
    expected_tenant: str | None = None
    expected_connector_id: str | None = None
    allowed_plan_digests: frozenset[str] | None = None

    def _authorize_record(self, transport: BlindTransportRecord) -> None:
        if self.expected_tenant is not None and transport.tenant != self.expected_tenant:
            raise IntegrityError("transport tenant is not authorized for this destination agent")
        if (
            self.expected_connector_id is not None
            and transport.destination_connector != self.expected_connector_id
        ):
            raise IntegrityError("transport is addressed to a different destination connector")
        if (
            self.allowed_plan_digests is not None
            and transport.plan_digest not in self.allowed_plan_digests
        ):
            raise IntegrityError("transport mapping plan is not authorized")

    def open_record(self, transport: BlindTransportRecord) -> dict[str, object]:
        self._authorize_record(transport)
        output: dict[str, object] = {}
        for field in transport.fields:
            plaintext = open_envelope(field.envelope, self.private_key, field.context)
            output[field.target_field_id] = PayloadCodec.decode(plaintext)
        return output

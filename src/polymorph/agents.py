from __future__ import annotations

import base64
import hashlib
import json
import math
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .crypto import (
    OpaqueEnvelope,
    RecipientKeyPair,
    TransferContext,
    open_envelope,
    seal_for_recipient,
)
from .errors import IntegrityError, ProtocolError
from .models.mapping import MappingPlan
from .models.schema import SchemaDescriptor
from .models.types import Sensitivity
from .policy import PolicyEngine
from .recipient_auth import RecipientKeyTrustStore, recipient_key_id
from .signing import SigningKeyPair, SourceTrustStore, signing_key_id
from .transforms import TransformStage, apply_transform, transform_stage
from .validation import PlanValidator


class PayloadCodec:
    """Canonical payload encoding used only inside encrypted envelopes."""

    @staticmethod
    def encode(value: object) -> bytes:
        payload: dict[str, object]
        if isinstance(value, Decimal):
            if not value.is_finite():
                raise ValueError("non-finite decimals are not transportable")
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
        return json.dumps(
            payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    @staticmethod
    def decode(payload: bytes) -> object:
        def reject_constant(value: str) -> object:
            raise ValueError(f"non-finite JSON constant is not transportable: {value}")

        def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate payload key: {key}")
                result[key] = value
            return result

        data = json.loads(
            payload.decode("utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
        if not isinstance(data, dict) or set(data) != {"kind", "value"}:
            raise ValueError("payload must contain exactly kind and value")
        kind = data["kind"]
        value = data["value"]
        if kind == "decimal":
            if not isinstance(value, str):
                raise ValueError("decimal payload value must be a string")
            number = Decimal(value)
            if not number.is_finite():
                raise ValueError("non-finite decimals are not transportable")
            return number
        if kind == "datetime":
            if not isinstance(value, str):
                raise ValueError("datetime payload value must be a string")
            return datetime.fromisoformat(value)
        if kind == "date":
            if not isinstance(value, str):
                raise ValueError("date payload value must be a string")
            return date.fromisoformat(value)
        if kind == "bytes":
            if not isinstance(value, str):
                raise ValueError("bytes payload value must be a string")
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
class RecordAuthentication:
    key_id: str
    signature: bytes
    algorithm: str = "ed25519"

    def __post_init__(self) -> None:
        if self.algorithm != "ed25519":
            raise ProtocolError("unsupported source signature algorithm")
        if len(self.key_id) != 64 or any(char not in "0123456789abcdef" for char in self.key_id):
            raise ProtocolError("source signing key id must be a lowercase SHA-256 digest")
        if len(self.signature) != 64:
            raise ProtocolError("Ed25519 source signature must be 64 bytes")

    def __repr__(self) -> str:
        return (
            f"RecordAuthentication(key_id={self.key_id!r}, algorithm={self.algorithm!r}, <signed>)"
        )

    def to_wire(self) -> dict[str, str]:
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "signature": base64.urlsafe_b64encode(self.signature).decode("ascii"),
        }

    @classmethod
    def from_wire(cls, payload: dict[str, object]) -> RecordAuthentication:
        try:
            signature = base64.b64decode(
                str(payload["signature"]).encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
            key_id = str(payload["key_id"])
        except (KeyError, UnicodeEncodeError, ValueError) as exc:
            raise ProtocolError("source signature is not valid base64url") from exc
        return cls(
            key_id=key_id,
            signature=signature,
            algorithm=str(payload.get("algorithm", "")),
        )


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
    def from_wire(cls, payload: dict[str, object], limits: ProtocolLimits) -> SealedField:
        raw_context = payload.get("context")
        raw_envelope = payload.get("envelope")
        if not isinstance(raw_context, dict) or not all(
            isinstance(key, str) for key in raw_context
        ):
            raise ProtocolError("sealed field context must be an object with string keys")
        if not isinstance(raw_envelope, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in raw_envelope.items()
        ):
            raise ProtocolError("sealed field envelope must contain string fields")
        context = TransferContext.from_wire(raw_context)
        envelope = OpaqueEnvelope.from_wire(
            raw_envelope,
            max_ciphertext_bytes=limits.max_ciphertext_bytes_per_field,
        )
        return cls(str(payload["target_field_id"]), context, envelope)


@dataclass(frozen=True, slots=True, repr=False)
class BlindTransportRecord:
    record_id: str
    fields: tuple[SealedField, ...]
    authentication: RecordAuthentication | None = None
    allow_legacy_blank_recipient_key_id: bool = False

    def __post_init__(self) -> None:
        if not self.fields:
            raise ProtocolError("blind transport record must contain at least one field")
        field_ids: set[str] = set()
        first = self.fields[0].context
        if first.protocol_version not in {2, 3}:
            raise ProtocolError("unsupported transport record version")
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
                "recipient_key_id",
                "issued_at",
                "expires_at",
            ):
                if getattr(context, name) != getattr(first, name):
                    raise ProtocolError(f"mixed {name} values in one blind transport record")
        if first.protocol_version == 2 and self.authentication is not None:
            raise ProtocolError("legacy transport records may not carry v3 source authentication")
        if first.protocol_version == 2 and first.recipient_key_id:
            raise ProtocolError("legacy v2 transport records may not carry a recipient key id")
        if first.protocol_version == 2 and self.allow_legacy_blank_recipient_key_id:
            raise ProtocolError("legacy recipient-key-id policy applies only to v3 records")
        if (
            first.protocol_version == 3
            and not first.recipient_key_id
            and not self.allow_legacy_blank_recipient_key_id
        ):
            raise ProtocolError("v3 transport record has no authenticated recipient key id")

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

    @property
    def protocol_version(self) -> int:
        return self.fields[0].context.protocol_version

    def _content_wire(self) -> dict[str, object]:
        return {
            "protocol": "opaque-record",
            "version": self.protocol_version,
            "record_id": self.record_id,
            "fields": [item.to_wire() for item in self.fields],
        }

    def source_authentication_bytes(self, key_id: str, algorithm: str = "ed25519") -> bytes:
        if self.protocol_version != 3:
            raise ProtocolError("source authentication is supported only for record protocol v3")
        payload = {
            **self._content_wire(),
            "authentication": {"algorithm": algorithm, "key_id": key_id},
        }
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return b"angusu.bridge/opaque-record/source-auth/v3\x00" + canonical

    def signed(self, signer: SigningKeyPair) -> BlindTransportRecord:
        if self.protocol_version != 3:
            raise ProtocolError("legacy transport records cannot be source-signed")
        if self.authentication is not None:
            raise ProtocolError("transport record is already source-signed")
        key_id = signing_key_id(signer.public_bytes())
        signature = signer.sign(self.source_authentication_bytes(key_id))
        return BlindTransportRecord(
            self.record_id,
            self.fields,
            RecordAuthentication(key_id=key_id, signature=signature),
            self.allow_legacy_blank_recipient_key_id,
        )

    def to_wire(self) -> dict[str, object]:
        payload = self._content_wire()
        if self.authentication is not None:
            payload["authentication"] = self.authentication.to_wire()
        return payload

    def canonical_wire_bytes(self) -> bytes:
        return json.dumps(
            self.to_wire(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def digest(self) -> str:
        content = json.dumps(
            self._content_wire(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(content).hexdigest()

    @classmethod
    def from_wire(
        cls,
        payload: dict[str, object],
        *,
        limits: ProtocolLimits | None = None,
        allow_legacy_unsigned: bool = False,
        allow_legacy_blank_recipient_key_id: bool = False,
    ) -> BlindTransportRecord:
        limits = limits or ProtocolLimits()
        if payload.get("protocol") != "opaque-record":
            raise ProtocolError("unsupported transport record protocol")
        raw_version = payload.get("version", 0)
        if isinstance(raw_version, bool) or not isinstance(raw_version, (int, str)):
            raise ProtocolError("transport record version is invalid")
        try:
            version = int(raw_version)
        except ValueError as exc:
            raise ProtocolError("transport record version is invalid") from exc
        if version not in {2, 3}:
            raise ProtocolError("unsupported transport record version")
        if version == 2 and not allow_legacy_unsigned:
            raise ProtocolError("unsigned v2 transport records require explicit legacy policy")
        raw_fields = payload.get("fields")
        if not isinstance(raw_fields, list) or not raw_fields:
            raise ProtocolError("transport record fields must be a non-empty list")
        if len(raw_fields) > limits.max_fields_per_record:
            raise ProtocolError("transport record exceeds field count limit")
        approx = len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        if approx > limits.max_record_wire_bytes:
            raise ProtocolError("transport record exceeds wire size limit")
        fields = tuple(SealedField.from_wire(dict(item), limits) for item in raw_fields)
        authentication_payload = payload.get("authentication")
        if version == 3:
            if not isinstance(authentication_payload, dict):
                raise ProtocolError("v3 transport record has no source authentication")
            authentication = RecordAuthentication.from_wire(authentication_payload)
        else:
            if authentication_payload is not None:
                raise ProtocolError("legacy transport record contains unexpected authentication")
            authentication = None
        record = cls(
            record_id=str(payload["record_id"]),
            fields=fields,
            authentication=authentication,
            allow_legacy_blank_recipient_key_id=(
                version == 3
                and not fields[0].context.recipient_key_id
                and allow_legacy_blank_recipient_key_id
            ),
        )
        if record.protocol_version != version:
            raise ProtocolError("outer record version does not match authenticated field context")
        return record


@dataclass(slots=True)
class BlindSourceAgent:
    """Executes value-dependent work at the source trust boundary, then seals every field."""

    tenant: str
    source_connector_id: str
    destination_connector_id: str
    source_schema: SchemaDescriptor
    target_schema: SchemaDescriptor
    plan: MappingPlan
    destination_public_key: bytes | None = None
    signing_key: SigningKeyPair | None = None
    schema_version: str = "1"
    transfer_ttl: timedelta | None = None
    protocol_version: int = 3
    allow_legacy_unsigned: bool = False
    recipient_key_trust_store: RecipientKeyTrustStore | None = None
    allow_unauthenticated_recipient_key: bool = False

    def __post_init__(self) -> None:
        PlanValidator().validate(
            self.plan, self.source_schema, self.target_schema
        ).raise_if_invalid()
        if self.protocol_version == 3 and self.signing_key is None:
            raise ValueError("record protocol v3 requires a source signing key")
        if self.protocol_version == 2 and not self.allow_legacy_unsigned:
            raise ValueError("record protocol v2 requires explicit legacy opt-in")
        if self.protocol_version not in {2, 3}:
            raise ValueError("unsupported source record protocol version")
        if self.recipient_key_trust_store is not None:
            if self.destination_public_key is not None:
                raise ValueError(
                    "destination public key must come only from the recipient key trust store"
                )
            self.recipient_key_trust_store.authorize(
                tenant=self.tenant,
                destination_connector=self.destination_connector_id,
            )
        elif self.protocol_version == 3 and not self.allow_unauthenticated_recipient_key:
            raise ValueError(
                "record protocol v3 requires an authenticated recipient key trust store; "
                "legacy raw keys require explicit opt-in"
            )
        elif self.destination_public_key is None:
            raise ValueError("legacy recipient key mode requires a destination public key")
        else:
            recipient_key_id(self.destination_public_key)

    def _recipient_key(self, *, now: datetime) -> tuple[bytes, str]:
        if self.recipient_key_trust_store is not None:
            certificate = self.recipient_key_trust_store.authorize(
                tenant=self.tenant,
                destination_connector=self.destination_connector_id,
                now=now,
            )
            key_id = certificate.key_id if self.protocol_version == 3 else ""
            return certificate.public_key, key_id
        assert self.destination_public_key is not None
        key_id = recipient_key_id(self.destination_public_key) if self.protocol_version == 3 else ""
        return self.destination_public_key, key_id

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
        destination_public_key, destination_key_id = self._recipient_key(now=issued_at)

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
                protocol_version=self.protocol_version,
                recipient_key_id=destination_key_id,
                issued_at=issued_at,
                expires_at=expires_at,
            )
            envelope = seal_for_recipient(
                PayloadCodec.encode(transformed),
                destination_public_key,
                context,
            )
            sealed.append(SealedField(target.id, context, envelope))

        transport = BlindTransportRecord(record_id=record_id, fields=tuple(sealed))
        if self.protocol_version == 2:
            return transport
        assert self.signing_key is not None
        return transport.signed(self.signing_key)


@dataclass(slots=True)
class BlindDestinationAgent:
    """Opens blind transport records only inside the destination trust boundary."""

    private_key: X25519PrivateKey
    expected_tenant: str | None = None
    expected_connector_id: str | None = None
    allowed_plan_digests: frozenset[str] | None = None
    source_trust_store: SourceTrustStore | None = None
    allow_legacy_unsigned: bool = False
    additional_private_keys: tuple[X25519PrivateKey, ...] = ()
    allow_legacy_blank_recipient_key_id: bool = False

    def _recipient_private_key(self, transport: BlindTransportRecord) -> X25519PrivateKey:
        authenticated_recipient = transport.fields[0].context.recipient_key_id
        if not authenticated_recipient:
            return self.private_key
        matches = [
            private_key
            for private_key in (self.private_key, *self.additional_private_keys)
            if recipient_key_id(RecipientKeyPair(private_key).public_bytes())
            == authenticated_recipient
        ]
        if len(matches) != 1:
            raise IntegrityError("transport record targets an unavailable recipient key")
        return matches[0]

    def _authorize_record(self, transport: BlindTransportRecord) -> X25519PrivateKey:
        if (
            transport.protocol_version == 3
            and not transport.fields[0].context.recipient_key_id
            and not self.allow_legacy_blank_recipient_key_id
        ):
            raise IntegrityError("v3 transport record has no authenticated recipient key id")
        if transport.protocol_version == 2:
            if not self.allow_legacy_unsigned:
                raise IntegrityError("unsigned v2 transport record is not allowed")
        else:
            if self.source_trust_store is None:
                raise IntegrityError("destination has no trusted source key registry")
            self.source_trust_store.verify_record(transport)
        if self.expected_tenant is not None and transport.tenant != self.expected_tenant:
            raise IntegrityError("transport tenant is not authorized for this destination agent")
        if (
            self.expected_connector_id is not None
            and transport.destination_connector != self.expected_connector_id
        ):
            raise IntegrityError("transport is addressed to a different destination connector")
        private_key = self._recipient_private_key(transport)
        if (
            self.allowed_plan_digests is not None
            and transport.plan_digest not in self.allowed_plan_digests
        ):
            raise IntegrityError("transport mapping plan is not authorized")
        return private_key

    def open_record(self, transport: BlindTransportRecord) -> dict[str, object]:
        private_key = self._authorize_record(transport)
        output: dict[str, object] = {}
        for field in transport.fields:
            plaintext = open_envelope(field.envelope, private_key, field.context)
            output[field.target_field_id] = PayloadCodec.decode(plaintext)
        return output

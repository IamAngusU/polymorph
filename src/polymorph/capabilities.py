from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from .errors import PolicyViolation, ProtocolError
from .signing import SigningKeyPair, verify_ed25519


class CapabilityOperation(StrEnum):
    READ_SCHEMA = "read_schema"
    READ_RECORDS = "read_records"
    WRITE_RECORDS = "write_records"
    REPLAY = "replay"
    FORCE_UNCERTAIN_REPLAY = "force_uncertain_replay"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class CapabilityGrant:
    id: str
    issuer: str
    subject: str
    tenant: str
    connector_id: str
    operations: tuple[CapabilityOperation, ...]
    allowed_plan_digests: tuple[str, ...] = ()
    issued_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime = field(
        default_factory=lambda: datetime.now(UTC) + timedelta(hours=1)
    )
    protocol_version: int = 1

    def canonical_dict(self) -> dict[str, object]:
        return {
            "allowed_plan_digests": sorted(set(self.allowed_plan_digests)),
            "connector_id": self.connector_id,
            "expires_at": _utc(self.expires_at).isoformat(),
            "id": self.id,
            "issued_at": _utc(self.issued_at).isoformat(),
            "issuer": self.issuer,
            "operations": sorted({item.value for item in self.operations}),
            "protocol_version": self.protocol_version,
            "subject": self.subject,
            "tenant": self.tenant,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.canonical_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    @classmethod
    def issue(
        cls,
        *,
        issuer: str,
        subject: str,
        tenant: str,
        connector_id: str,
        operations: tuple[CapabilityOperation, ...],
        allowed_plan_digests: tuple[str, ...] = (),
        ttl: timedelta = timedelta(hours=1),
    ) -> "CapabilityGrant":
        now = datetime.now(UTC)
        return cls(
            id=str(uuid.uuid4()),
            issuer=issuer,
            subject=subject,
            tenant=tenant,
            connector_id=connector_id,
            operations=operations,
            allowed_plan_digests=allowed_plan_digests,
            issued_at=now,
            expires_at=now + ttl,
        )

    def authorize(
        self,
        operation: CapabilityOperation,
        *,
        subject: str,
        tenant: str,
        connector_id: str,
        plan_digest: str | None = None,
        now: datetime | None = None,
    ) -> None:
        current = _utc(now or datetime.now(UTC))
        if self.protocol_version != 1:
            raise PolicyViolation("unsupported capability protocol version")
        if current < _utc(self.issued_at) or current > _utc(self.expires_at):
            raise PolicyViolation("capability grant is outside its validity window")
        if self.subject != subject:
            raise PolicyViolation("capability subject mismatch")
        if self.tenant != tenant:
            raise PolicyViolation("capability tenant mismatch")
        if self.connector_id != connector_id:
            raise PolicyViolation("capability connector mismatch")
        if operation not in self.operations:
            raise PolicyViolation(f"capability does not allow {operation.value}")
        if self.allowed_plan_digests:
            if plan_digest is None or plan_digest not in self.allowed_plan_digests:
                raise PolicyViolation("mapping plan is outside capability scope")


@dataclass(frozen=True, slots=True)
class SignedCapabilityGrant:
    grant: CapabilityGrant
    signature: bytes

    @classmethod
    def sign(cls, grant: CapabilityGrant, signer: SigningKeyPair) -> "SignedCapabilityGrant":
        return cls(grant, signer.sign(grant.canonical_bytes()))

    def verify(self, trusted_public_key: bytes, *, expected_issuer: str | None = None) -> None:
        verify_ed25519(trusted_public_key, self.grant.canonical_bytes(), self.signature)
        if expected_issuer is not None and self.grant.issuer != expected_issuer:
            raise PolicyViolation("capability issuer is not trusted")

    def to_wire(self) -> dict[str, object]:
        return {
            "grant": self.grant.canonical_dict(),
            "signature": base64.urlsafe_b64encode(self.signature).decode("ascii"),
        }

    @classmethod
    def from_wire(cls, payload: dict[str, object]) -> "SignedCapabilityGrant":
        raw = dict(payload["grant"])
        operations = tuple(CapabilityOperation(item) for item in raw.get("operations", []))
        grant = CapabilityGrant(
            id=str(raw["id"]),
            issuer=str(raw["issuer"]),
            subject=str(raw["subject"]),
            tenant=str(raw["tenant"]),
            connector_id=str(raw["connector_id"]),
            operations=operations,
            allowed_plan_digests=tuple(str(item) for item in raw.get("allowed_plan_digests", [])),
            issued_at=datetime.fromisoformat(str(raw["issued_at"])),
            expires_at=datetime.fromisoformat(str(raw["expires_at"])),
            protocol_version=int(raw.get("protocol_version", 1)),
        )
        try:
            signature = base64.b64decode(
                str(payload["signature"]).encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
        except Exception as exc:
            raise ProtocolError("invalid capability signature encoding") from exc
        return cls(grant, signature)


@dataclass(frozen=True, slots=True)
class CapabilityAuthorizer:
    signed_grant: SignedCapabilityGrant
    trusted_public_key: bytes
    subject: str
    expected_issuer: str | None = None

    def authorize(
        self,
        operation: CapabilityOperation,
        *,
        tenant: str,
        connector_id: str,
        plan_digest: str | None = None,
    ) -> None:
        self.signed_grant.verify(
            self.trusted_public_key,
            expected_issuer=self.expected_issuer,
        )
        self.signed_grant.grant.authorize(
            operation,
            subject=self.subject,
            tenant=tenant,
            connector_id=connector_id,
            plan_digest=plan_digest,
        )

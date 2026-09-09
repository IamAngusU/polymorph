from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import IntegrityError, ProtocolError, TransferExpired

_PROTOCOL_NAMESPACE = b"angusu.bridge/opaque-envelope"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class TransferContext:
    tenant: str
    source_connector: str
    destination_connector: str
    field_id: str
    schema_version: str
    record_id: str
    transfer_id: str
    plan_id: str = ""
    plan_digest: str = ""
    protocol_version: int = 2
    issued_at: datetime | None = None
    expires_at: datetime | None = None

    def aad_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "destination_connector": self.destination_connector,
            "field_id": self.field_id,
            "plan_digest": self.plan_digest,
            "plan_id": self.plan_id,
            "protocol_version": self.protocol_version,
            "record_id": self.record_id,
            "schema_version": self.schema_version,
            "source_connector": self.source_connector,
            "tenant": self.tenant,
            "transfer_id": self.transfer_id,
        }
        if self.issued_at is not None:
            payload["issued_at"] = _utc(self.issued_at).isoformat()
        if self.expires_at is not None:
            payload["expires_at"] = _utc(self.expires_at).isoformat()
        return payload

    def aad(self) -> bytes:
        return json.dumps(
            self.aad_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def validate_time(self, *, now: datetime | None = None) -> None:
        if self.expires_at is None:
            return
        current = _utc(now or datetime.now(UTC))
        if current > _utc(self.expires_at):
            raise TransferExpired("authenticated transfer has expired")

    def to_wire(self) -> dict[str, object]:
        return self.aad_payload()

    @classmethod
    def from_wire(cls, payload: dict[str, object]) -> "TransferContext":
        def parse_time(name: str) -> datetime | None:
            raw = payload.get(name)
            return None if raw in {None, ""} else datetime.fromisoformat(str(raw))

        return cls(
            tenant=str(payload["tenant"]),
            source_connector=str(payload["source_connector"]),
            destination_connector=str(payload["destination_connector"]),
            field_id=str(payload["field_id"]),
            schema_version=str(payload["schema_version"]),
            record_id=str(payload["record_id"]),
            transfer_id=str(payload["transfer_id"]),
            plan_id=str(payload.get("plan_id", "")),
            plan_digest=str(payload.get("plan_digest", "")),
            protocol_version=int(payload.get("protocol_version", 2)),
            issued_at=parse_time("issued_at"),
            expires_at=parse_time("expires_at"),
        )


@dataclass(frozen=True, slots=True)
class RecipientKeyPair:
    private_key: X25519PrivateKey

    @classmethod
    def generate(cls) -> "RecipientKeyPair":
        return cls(X25519PrivateKey.generate())

    def public_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _b64_decode(value: str, *, field: str, max_bytes: int) -> bytes:
    if len(value) > ((max_bytes + 2) // 3) * 4 + 8:
        raise ProtocolError(f"{field} exceeds protocol size limit")
    try:
        decoded = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ProtocolError(f"{field} is not valid base64url") from exc
    if len(decoded) > max_bytes:
        raise ProtocolError(f"{field} exceeds protocol size limit")
    return decoded


@dataclass(frozen=True, slots=True, repr=False)
class OpaqueEnvelope:
    ephemeral_public_key: bytes
    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        if len(self.ephemeral_public_key) != 32:
            raise ProtocolError("ephemeral X25519 public key must be 32 bytes")
        if len(self.nonce) != 12:
            raise ProtocolError("ChaCha20-Poly1305 nonce must be 12 bytes")
        if len(self.ciphertext) < 16:
            raise ProtocolError("ciphertext is shorter than the authentication tag")

    def __repr__(self) -> str:
        return "OpaqueEnvelope(<sealed>)"

    def to_wire(self) -> dict[str, str]:
        return {
            "epk": _b64_encode(self.ephemeral_public_key),
            "nonce": _b64_encode(self.nonce),
            "ciphertext": _b64_encode(self.ciphertext),
        }

    @classmethod
    def from_wire(
        cls,
        payload: dict[str, str],
        *,
        max_ciphertext_bytes: int = 16 * 1024 * 1024,
    ) -> "OpaqueEnvelope":
        return cls(
            ephemeral_public_key=_b64_decode(payload["epk"], field="epk", max_bytes=32),
            nonce=_b64_decode(payload["nonce"], field="nonce", max_bytes=12),
            ciphertext=_b64_decode(
                payload["ciphertext"],
                field="ciphertext",
                max_bytes=max_ciphertext_bytes,
            ),
        )


def _derive_key(shared_secret: bytes, context: TransferContext) -> bytes:
    if context.protocol_version != 2:
        raise ProtocolError("unsupported opaque-envelope protocol version")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_PROTOCOL_NAMESPACE + b"/v2\x00" + context.aad(),
    ).derive(shared_secret)


def seal_for_recipient(
    plaintext: bytes,
    recipient_public_key: bytes,
    context: TransferContext,
) -> OpaqueEnvelope:
    if len(recipient_public_key) != 32:
        raise ProtocolError("recipient X25519 public key must be 32 bytes")
    context.validate_time()
    ephemeral_private = X25519PrivateKey.generate()
    recipient_public = X25519PublicKey.from_public_bytes(recipient_public_key)
    shared = ephemeral_private.exchange(recipient_public)
    key = _derive_key(shared, context)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, context.aad())
    ephemeral_public = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return OpaqueEnvelope(ephemeral_public, nonce, ciphertext)


def open_envelope(
    envelope: OpaqueEnvelope,
    recipient_private_key: X25519PrivateKey,
    context: TransferContext,
) -> bytes:
    context.validate_time()
    try:
        ephemeral_public = X25519PublicKey.from_public_bytes(envelope.ephemeral_public_key)
        shared = recipient_private_key.exchange(ephemeral_public)
        key = _derive_key(shared, context)
        return ChaCha20Poly1305(key).decrypt(envelope.nonce, envelope.ciphertext, context.aad())
    except (InvalidTag, ValueError, TypeError) as exc:
        raise IntegrityError("opaque envelope authentication failed") from exc

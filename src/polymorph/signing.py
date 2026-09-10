from __future__ import annotations

import hashlib
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import IntegrityError, ProtocolError

if TYPE_CHECKING:
    from .agents import BlindTransportRecord


_DEFAULT_ROTATION_GRACE = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class SigningKeyPair:
    """In-memory Ed25519 signing identity.

    Private-key persistence is deliberately outside the core. Production deployments should
    load signing operations from an OS keystore, HSM or another explicitly trusted provider.
    """

    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> SigningKeyPair:
        return cls(Ed25519PrivateKey.generate())

    def public_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, payload: bytes) -> bytes:
        return self.private_key.sign(payload)


def signing_key_id(public_key: bytes) -> str:
    """Return the stable identifier used for an Ed25519 verification key."""

    if len(public_key) != 32:
        raise ProtocolError("Ed25519 public key must be 32 bytes")
    return hashlib.sha256(public_key).hexdigest()


class SourceKeyState(StrEnum):
    """Lifecycle state for a source record-signing key.

    ``VERIFY_ONLY`` supports planned rotation: an old key may drain records issued no later than
    its immutable cutoff. ``REVOKED`` is an immediate hard failure.
    """

    ACTIVE = "active"
    VERIFY_ONLY = "verify_only"
    REVOKED = "revoked"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("source key validity timestamps must be timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class TrustedSourceKey:
    public_key: bytes
    tenant: str
    source_connector: str
    state: SourceKeyState = SourceKeyState.ACTIVE
    not_before: datetime | None = None
    not_after: datetime | None = None
    key_id: str = ""
    signing_cutoff: datetime | None = None

    def __post_init__(self) -> None:
        try:
            state = SourceKeyState(self.state)
        except ValueError as exc:
            raise ValueError("source key state is invalid") from exc
        object.__setattr__(self, "state", state)
        expected = signing_key_id(self.public_key)
        if self.key_id and self.key_id != expected:
            raise ValueError("source key id does not match its public key")
        object.__setattr__(self, "key_id", expected)
        if not self.tenant or not self.source_connector:
            raise ValueError("trusted source keys require tenant and connector bindings")
        if self.not_before is not None:
            object.__setattr__(self, "not_before", _utc(self.not_before))
        if self.not_after is not None:
            object.__setattr__(self, "not_after", _utc(self.not_after))
        if self.signing_cutoff is not None:
            object.__setattr__(self, "signing_cutoff", _utc(self.signing_cutoff))
        if (
            self.not_before is not None
            and self.not_after is not None
            and self.not_after < self.not_before
        ):
            raise ValueError("source key validity interval is inverted")
        if self.state is SourceKeyState.ACTIVE and self.signing_cutoff is not None:
            raise ValueError("active source key cannot have a signing cutoff")
        if self.state is SourceKeyState.VERIFY_ONLY and self.signing_cutoff is None:
            raise ValueError("verification-only source key requires a signing cutoff")
        if self.state is SourceKeyState.VERIFY_ONLY and self.not_after is None:
            raise ValueError("verification-only source key requires an expiry deadline")


class SourceTrustVerificationSession:
    """Thread-bound verifier yielded only by ``SourceTrustStore.verification_session``."""

    __slots__ = ("_active", "_owner_thread", "_store")

    def __init__(self, store: SourceTrustStore) -> None:
        self._store = store
        self._owner_thread = threading.get_ident()
        self._active = True

    def verify_record(
        self,
        record: BlindTransportRecord,
        *,
        now: datetime | None = None,
    ) -> TrustedSourceKey:
        if not self._active:
            raise RuntimeError("source trust verification session is closed")
        if threading.get_ident() != self._owner_thread:
            raise RuntimeError("source trust verification session belongs to another thread")
        return self._store._verify_record_locked(record, now=now)

    def _close(self) -> None:
        self._active = False


class SourceTrustStore:
    """Thread-safe registry for source verification keys, rotation and hard revocation."""

    def __init__(self, keys: Iterable[TrustedSourceKey] = ()) -> None:
        self._lock = threading.RLock()
        self._keys: dict[str, TrustedSourceKey] = {}
        self._verification_depth = 0
        for key in keys:
            self.add(key)

    def add(self, key: TrustedSourceKey) -> None:
        with self._lock:
            self._ensure_mutation_allowed()
            current = self._keys.get(key.key_id)
            if current is not None and current != key:
                raise ValueError("source key id is already registered with different policy")
            self._keys[key.key_id] = key

    def get(self, key_id: str) -> TrustedSourceKey | None:
        with self._lock:
            return self._keys.get(key_id)

    def set_state(
        self,
        key_id: str,
        state: SourceKeyState,
        *,
        changed_at: datetime | None = None,
        verification_grace: timedelta = _DEFAULT_ROTATION_GRACE,
    ) -> None:
        state = SourceKeyState(state)
        with self._lock:
            self._ensure_mutation_allowed()
            current = self._keys.get(key_id)
            if current is None:
                raise KeyError("source verification key is not registered")
            if current.state is SourceKeyState.REVOKED and state is not SourceKeyState.REVOKED:
                raise ValueError("revoked source keys cannot be reactivated")
            cutoff: datetime | None
            deadline: datetime | None
            if state is SourceKeyState.VERIFY_ONLY:
                if verification_grace <= timedelta(0):
                    raise ValueError("source key rotation grace must be positive")
                cutoff = current.signing_cutoff or _utc(changed_at or datetime.now(UTC))
                deadline = cutoff + verification_grace
                if current.not_after is not None:
                    deadline = min(current.not_after, deadline)
            elif state is SourceKeyState.ACTIVE:
                cutoff = None
                deadline = current.not_after
            else:
                cutoff = current.signing_cutoff
                deadline = current.not_after
            self._keys[key_id] = TrustedSourceKey(
                public_key=current.public_key,
                tenant=current.tenant,
                source_connector=current.source_connector,
                state=state,
                not_before=current.not_before,
                not_after=deadline,
                key_id=current.key_id,
                signing_cutoff=cutoff,
            )

    def revoke(self, key_id: str) -> None:
        self.set_state(key_id, SourceKeyState.REVOKED)

    def rotate(
        self,
        previous_key_id: str,
        replacement: TrustedSourceKey,
        *,
        changed_at: datetime | None = None,
        verification_grace: timedelta = _DEFAULT_ROTATION_GRACE,
    ) -> None:
        """Cut off one bound key for new issuance and register its active replacement."""

        with self._lock:
            self._ensure_mutation_allowed()
            current = self._keys.get(previous_key_id)
            if current is None:
                raise KeyError("source verification key is not registered")
            if replacement.key_id == previous_key_id:
                raise ValueError("replacement source key must be a different key")
            if (
                replacement.tenant != current.tenant
                or replacement.source_connector != current.source_connector
            ):
                raise ValueError("rotated source key must preserve tenant and connector binding")
            if replacement.state is not SourceKeyState.ACTIVE:
                raise ValueError("replacement source key must be active")
            registered_replacement = self._keys.get(replacement.key_id)
            if registered_replacement is not None and registered_replacement != replacement:
                raise ValueError("replacement source key is registered with different policy")
            self.set_state(
                previous_key_id,
                SourceKeyState.VERIFY_ONLY,
                changed_at=changed_at,
                verification_grace=verification_grace,
            )
            self.add(replacement)

    @contextmanager
    def verification_session(self) -> Iterator[SourceTrustVerificationSession]:
        """Fence registry changes across one or more verifications and a caller commit.

        The returned verifier is thread-bound and becomes unusable when the context exits. A
        caller that publishes work after verification must keep this context open until that
        publication commits, so hard revocation linearizes before verification or after commit.
        """

        with self._lock:
            self._verification_depth += 1
            session = SourceTrustVerificationSession(self)
            try:
                yield session
            finally:
                session._close()
                self._verification_depth -= 1

    def _ensure_mutation_allowed(self) -> None:
        if self._verification_depth:
            raise RuntimeError("source trust registry cannot mutate inside a verification session")

    def verify_record(
        self,
        record: BlindTransportRecord,
        *,
        now: datetime | None = None,
    ) -> TrustedSourceKey:
        with self.verification_session() as session:
            return session.verify_record(record, now=now)

    def _verify_record_locked(
        self,
        record: BlindTransportRecord,
        *,
        now: datetime | None = None,
    ) -> TrustedSourceKey:
        authentication = record.authentication
        if authentication is None:
            raise IntegrityError("transport record has no source authentication")
        if authentication.algorithm != "ed25519":
            raise IntegrityError("transport record uses an unsupported source signature")
        key = self._keys.get(authentication.key_id)
        if key is None:
            raise IntegrityError("transport record source key is not trusted")
        if key.state is SourceKeyState.REVOKED:
            raise IntegrityError("transport record source key is revoked")
        if key.tenant != record.tenant or key.source_connector != record.source_connector:
            raise IntegrityError("transport source identity does not match its trusted key binding")
        verify_ed25519(
            key.public_key,
            record.source_authentication_bytes(authentication.key_id, authentication.algorithm),
            authentication.signature,
        )
        current = _utc(now or datetime.now(UTC))
        if key.not_before is not None and current < key.not_before:
            raise IntegrityError("transport record source key is not active yet")
        if key.not_after is not None and current > key.not_after:
            raise IntegrityError("transport record source key has expired")
        if key.state is SourceKeyState.VERIFY_ONLY:
            issued_at = record.fields[0].context.issued_at
            if issued_at is None or key.signing_cutoff is None:
                raise IntegrityError("verification-only source key requires signed issuance time")
            if _utc(issued_at) > key.signing_cutoff:
                raise IntegrityError("transport record was issued after source key rotation")
        return key


def verify_ed25519(public_key: bytes, payload: bytes, signature: bytes) -> None:
    if len(public_key) != 32:
        raise ProtocolError("Ed25519 public key must be 32 bytes")
    if len(signature) != 64:
        raise IntegrityError("Ed25519 signature must be 64 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (InvalidSignature, ValueError) as exc:
        raise IntegrityError("signature verification failed") from exc

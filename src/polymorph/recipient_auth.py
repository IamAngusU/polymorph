from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
import threading
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path

from .crypto import validate_recipient_public_key
from .errors import IntegrityError, ProtocolError
from .filesystem import atomic_write_text, exclusive_path_lock
from .signing import SigningKeyPair, signing_key_id, verify_ed25519

_CERTIFICATE_FORMAT = "angusu.bridge/recipient-key-certificate"
_CERTIFICATE_VERSION = 1
_STATE_FORMAT = "angusu.bridge/recipient-key-trust-state"
_STATE_VERSION = 2
_MAX_STATE_BYTES = 64 * 1024
_MAX_BINDING_BYTES = 256
_MAX_GENERATION = (1 << 63) - 1
_MAX_USED_KEY_IDS = 512
_X25519_FIELD_PRIME = (1 << 255) - 19
_StateFingerprint = tuple[int, int, int, int, int]


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"recipient key {label} must be timezone-aware")
    return value.astimezone(UTC)


def _binding(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"recipient key {label} must be a string")
    if not value or len(value.encode("utf-8")) > _MAX_BINDING_BYTES:
        raise ValueError(f"recipient key {label} must contain 1 to {_MAX_BINDING_BYTES} bytes")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ValueError(f"recipient key {label} contains a control character")
    return value


def _digest_id(value: bytes, label: str) -> str:
    if len(value) != 32:
        raise ProtocolError(f"{label} must be 32 bytes")
    return hashlib.sha256(value).hexdigest()


def recipient_key_id(public_key: bytes) -> str:
    """Return the stable identifier for a raw X25519 recipient public key."""

    raw = bytes(public_key)
    _digest_id(raw, "X25519 recipient public key")
    validate_recipient_public_key(raw)
    masked = bytearray(raw)
    masked[-1] &= 0x7F
    coordinate = int.from_bytes(masked, "little") % _X25519_FIELD_PRIME
    canonical = coordinate.to_bytes(32, "little")
    return hashlib.sha256(canonical).hexdigest()


def _key_id(value: str, label: str) -> str:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ProtocolError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: object, *, expected: int, label: str) -> bytes:
    if not isinstance(value, str):
        raise ProtocolError(f"recipient key certificate {label} must be a string")
    if len(value) > ((expected + 2) // 3) * 4 + 4:
        raise ProtocolError(f"recipient key certificate {label} exceeds its size limit")
    try:
        decoded = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ProtocolError(f"recipient key certificate {label} is not valid base64url") from exc
    if len(decoded) != expected:
        raise ProtocolError(f"recipient key certificate {label} has an invalid length")
    return decoded


def _parse_time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ProtocolError(f"recipient key certificate {label} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value)
        return _utc(parsed, label)
    except (OverflowError, ValueError) as exc:
        raise ProtocolError(f"recipient key certificate {label} is invalid") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ProtocolError("recipient key JSON contains a duplicate object key")
        output[key] = value
    return output


def _is_reparse_point(metadata: os.stat_result) -> bool:
    flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & flag)


def _file_fingerprint(metadata: os.stat_result) -> _StateFingerprint:
    """Identify one published trust-state file without reading its verified contents again."""

    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _reject_linked_path_components(path: Path, *, include_leaf: bool) -> None:
    """Reject lexical symlink/reparse components before resolving a trust-state path."""

    candidate = path if path.is_absolute() else Path.cwd() / path
    current = Path(candidate.anchor)
    parts = candidate.parts[1:] if candidate.anchor else candidate.parts
    inspected = parts if include_leaf else parts[:-1]
    for part in inspected:
        if part in {"", "."}:
            continue
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise IntegrityError("recipient key trust path cannot be inspected safely") from exc
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            raise IntegrityError("recipient key trust path contains a link or reparse point")


def _sync_parent_directory(path: Path) -> None:
    """Make an atomic trust-head replacement crash-durable where POSIX permits it."""

    if os.name != "posix":
        return
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path.parent, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError("recipient key trust-state parent is not a directory")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@dataclass(frozen=True, slots=True, repr=False)
class RecipientKeyCertificate:
    """Destination-signed binding for one rotating X25519 recipient key."""

    tenant: str
    destination_connector: str
    public_key: bytes
    generation: int
    previous_key_id: str | None
    issued_at: datetime
    not_before: datetime
    not_after: datetime
    identity_key_id: str
    signature: bytes
    algorithm: str = "ed25519"
    _canonical_key_id: str = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant", _binding(self.tenant, "tenant"))
        object.__setattr__(
            self,
            "destination_connector",
            _binding(self.destination_connector, "destination connector"),
        )
        raw_key = bytes(self.public_key)
        canonical_key_id = recipient_key_id(raw_key)
        object.__setattr__(self, "public_key", raw_key)
        object.__setattr__(self, "_canonical_key_id", canonical_key_id)
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or not 1 <= self.generation <= _MAX_GENERATION
        ):
            raise ProtocolError("recipient key generation is invalid")
        if self.generation == 1 and self.previous_key_id is not None:
            raise ProtocolError("initial recipient key certificate cannot have a predecessor")
        if self.generation > 1 and self.previous_key_id is None:
            raise ProtocolError("rotated recipient key certificate requires a predecessor")
        if self.previous_key_id is not None:
            _key_id(self.previous_key_id, "recipient predecessor key id")
            if self.previous_key_id == self.key_id:
                raise ProtocolError("recipient key rotation must change the public key")
        object.__setattr__(self, "issued_at", _utc(self.issued_at, "issuance time"))
        object.__setattr__(self, "not_before", _utc(self.not_before, "not-before time"))
        object.__setattr__(self, "not_after", _utc(self.not_after, "expiry time"))
        if self.not_after <= self.not_before:
            raise ProtocolError("recipient key certificate validity interval is empty or inverted")
        if self.issued_at > self.not_after:
            raise ProtocolError("recipient key certificate was issued after its expiry")
        _key_id(self.identity_key_id, "recipient identity key id")
        if self.algorithm != "ed25519":
            raise ProtocolError("recipient key certificate signature algorithm is unsupported")
        if len(self.signature) != 64:
            raise ProtocolError("recipient key certificate signature must be 64 bytes")

    def __repr__(self) -> str:
        return (
            "RecipientKeyCertificate("
            f"tenant={self.tenant!r}, destination_connector={self.destination_connector!r}, "
            f"generation={self.generation}, key_id={self.key_id!r}, <signed>)"
        )

    @property
    def key_id(self) -> str:
        return self._canonical_key_id

    def _unsigned_wire(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "destination_connector": self.destination_connector,
            "generation": self.generation,
            "identity_key_id": self.identity_key_id,
            "issued_at": self.issued_at.isoformat(),
            "key_id": self.key_id,
            "not_after": self.not_after.isoformat(),
            "not_before": self.not_before.isoformat(),
            "previous_key_id": self.previous_key_id,
            "public_key": _b64(self.public_key),
            "tenant": self.tenant,
        }

    def signing_bytes(self) -> bytes:
        canonical = json.dumps(
            self._unsigned_wire(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return b"angusu.bridge/recipient-key-certificate/v1\x00" + canonical

    def to_wire(self) -> dict[str, object]:
        return {
            "format": _CERTIFICATE_FORMAT,
            "version": _CERTIFICATE_VERSION,
            **self._unsigned_wire(),
            "signature": _b64(self.signature),
        }

    def to_json(self) -> str:
        """Serialize a distributable certificate without private material."""

        return (
            json.dumps(
                self.to_wire(),
                sort_keys=True,
                indent=2,
                ensure_ascii=False,
            )
            + "\n"
        )

    @classmethod
    def issue(
        cls,
        *,
        tenant: str,
        destination_connector: str,
        public_key: bytes,
        generation: int,
        previous_key_id: str | None,
        identity_signer: SigningKeyPair,
        issued_at: datetime,
        not_before: datetime,
        not_after: datetime,
    ) -> RecipientKeyCertificate:
        certificate = cls(
            tenant=tenant,
            destination_connector=destination_connector,
            public_key=public_key,
            generation=generation,
            previous_key_id=previous_key_id,
            issued_at=issued_at,
            not_before=not_before,
            not_after=not_after,
            identity_key_id=signing_key_id(identity_signer.public_bytes()),
            signature=b"\0" * 64,
        )
        return replace(certificate, signature=identity_signer.sign(certificate.signing_bytes()))

    @classmethod
    def from_wire(cls, payload: object) -> RecipientKeyCertificate:
        if not isinstance(payload, dict) or not all(isinstance(key, str) for key in payload):
            raise ProtocolError("recipient key certificate must be an object")
        required = {
            "algorithm",
            "destination_connector",
            "format",
            "generation",
            "identity_key_id",
            "issued_at",
            "key_id",
            "not_after",
            "not_before",
            "previous_key_id",
            "public_key",
            "signature",
            "tenant",
            "version",
        }
        if set(payload) != required:
            raise ProtocolError("recipient key certificate has unexpected or missing fields")
        if payload["format"] != _CERTIFICATE_FORMAT or (
            isinstance(payload["version"], bool)
            or not isinstance(payload["version"], int)
            or payload["version"] != _CERTIFICATE_VERSION
        ):
            raise ProtocolError("recipient key certificate format is unsupported")
        generation = payload["generation"]
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise ProtocolError("recipient key generation is invalid")
        previous = payload["previous_key_id"]
        if previous is not None and not isinstance(previous, str):
            raise ProtocolError("recipient predecessor key id must be a string or null")
        public_key = _unb64(payload["public_key"], expected=32, label="public key")
        for label in ("tenant", "destination_connector", "identity_key_id", "algorithm", "key_id"):
            if not isinstance(payload[label], str):
                raise ProtocolError(f"recipient key certificate {label} must be a string")
        try:
            certificate = cls(
                tenant=payload["tenant"],
                destination_connector=payload["destination_connector"],
                public_key=public_key,
                generation=generation,
                previous_key_id=previous,
                issued_at=_parse_time(payload["issued_at"], "issuance time"),
                not_before=_parse_time(payload["not_before"], "not-before time"),
                not_after=_parse_time(payload["not_after"], "expiry time"),
                identity_key_id=payload["identity_key_id"],
                signature=_unb64(payload["signature"], expected=64, label="signature"),
                algorithm=payload["algorithm"],
            )
        except (OverflowError, ValueError) as exc:
            raise ProtocolError("recipient key certificate field validation failed") from exc
        if payload["key_id"] != certificate.key_id:
            raise ProtocolError("recipient key certificate key id does not match its public key")
        return certificate

    @classmethod
    def from_json(cls, payload: str | bytes) -> RecipientKeyCertificate:
        encoded = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        if len(encoded) > _MAX_STATE_BYTES:
            raise ProtocolError("recipient key certificate exceeds its size limit")
        try:
            value = json.loads(
                encoded.decode("utf-8-sig"),
                object_pairs_hook=_reject_duplicate_keys,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ProtocolError("recipient key certificate is invalid JSON") from exc
        return cls.from_wire(value)

    @classmethod
    def load(cls, path: str | Path) -> RecipientKeyCertificate:
        source = Path(path)
        return cls.from_json(
            RecipientKeyTrustStore._read_bounded_regular_file(source, artifact="certificate")
        )


@dataclass(frozen=True, slots=True, repr=False)
class RecipientKeyBatchAuthorization:
    """One immutable recipient trust head used by an all-or-none source batch."""

    certificate: RecipientKeyCertificate
    _store_token: object = field(repr=False, compare=False)
    _head_revision: int = field(repr=False, compare=False)
    _state_fingerprint: _StateFingerprint | None = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return (
            "RecipientKeyBatchAuthorization("
            f"generation={self.certificate.generation}, "
            f"key_id={self.certificate.key_id!r})"
        )


class RecipientKeyTrustStore:
    """Pinned destination identity plus a monotonic recipient-key rotation checkpoint."""

    def __init__(
        self,
        *,
        identity_public_key: bytes,
        tenant: str,
        destination_connector: str,
        state_path: str | Path | None = None,
    ) -> None:
        self.identity_public_key = bytes(identity_public_key)
        self.identity_key_id = signing_key_id(self.identity_public_key)
        self.tenant = _binding(tenant, "tenant")
        self.destination_connector = _binding(destination_connector, "destination connector")
        self.state_path: Path | None
        if state_path is not None:
            lexical_state_path = Path(state_path)
            _reject_linked_path_components(lexical_state_path, include_leaf=True)
            self.state_path = Path(os.path.abspath(lexical_state_path))
            _reject_linked_path_components(self.state_path, include_leaf=True)
        else:
            self.state_path = None
        self._lock = threading.RLock()
        self._current: RecipientKeyCertificate | None = None
        self._used_key_ids: set[str] = set()
        self._state_fingerprint: _StateFingerprint | None = None
        self._head_revision = 0
        self._batch_authorization_token = object()
        if self.state_path is not None:
            _reject_linked_path_components(self.state_path, include_leaf=True)
            if self.state_path.exists():
                (
                    self._current,
                    self._used_key_ids,
                    self._state_fingerprint,
                ) = self._read_state()
                self._head_revision += 1

    def _verify_certificate(
        self,
        certificate: RecipientKeyCertificate,
        *,
        now: datetime | None,
        require_current_validity: bool,
    ) -> None:
        if certificate.identity_key_id != self.identity_key_id:
            raise IntegrityError("recipient key certificate identity is not trusted")
        if (
            certificate.tenant != self.tenant
            or certificate.destination_connector != self.destination_connector
        ):
            raise IntegrityError("recipient key certificate route binding is not trusted")
        verify_ed25519(
            self.identity_public_key,
            certificate.signing_bytes(),
            certificate.signature,
        )
        if require_current_validity:
            self._verify_current_validity(certificate, now=now)

    def _state_wire(self, certificate: RecipientKeyCertificate) -> dict[str, object]:
        return {
            "current_certificate": certificate.to_wire(),
            "destination_connector": self.destination_connector,
            "format": _STATE_FORMAT,
            "identity_key_id": self.identity_key_id,
            "tenant": self.tenant,
            "used_key_ids": sorted(self._used_key_ids),
            "version": _STATE_VERSION,
        }

    @staticmethod
    def _read_bounded_regular_file_snapshot(
        path: Path,
        *,
        artifact: str = "trust state",
    ) -> tuple[bytes, _StateFingerprint]:
        description = f"recipient key {artifact}"
        _reject_linked_path_components(path, include_leaf=True)
        try:
            linked = path.lstat()
        except OSError as exc:
            raise IntegrityError(f"{description} is unavailable") from exc
        if not stat.S_ISREG(linked.st_mode) or _is_reparse_point(linked):
            raise IntegrityError(f"{description} is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise IntegrityError(f"{description} cannot be opened safely") from exc
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or _is_reparse_point(opened)
                or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
            ):
                raise IntegrityError(f"{description} changed while opening")
            if opened.st_size > _MAX_STATE_BYTES:
                raise ProtocolError(f"{description} exceeds its size limit")
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                data = handle.read(_MAX_STATE_BYTES + 1)
            if len(data) > _MAX_STATE_BYTES:
                raise ProtocolError(f"{description} exceeds its size limit")
            return data, _file_fingerprint(opened)
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _read_bounded_regular_file(path: Path, *, artifact: str = "trust state") -> bytes:
        data, _ = RecipientKeyTrustStore._read_bounded_regular_file_snapshot(
            path,
            artifact=artifact,
        )
        return data

    def _state_path_fingerprint(self) -> _StateFingerprint:
        assert self.state_path is not None
        _reject_linked_path_components(self.state_path, include_leaf=True)
        try:
            metadata = self.state_path.lstat()
        except OSError as exc:
            raise IntegrityError("recipient key trust state is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode) or _is_reparse_point(metadata):
            raise IntegrityError("recipient key trust state is not a regular file")
        return _file_fingerprint(metadata)

    def _read_state(
        self,
    ) -> tuple[RecipientKeyCertificate, set[str], _StateFingerprint]:
        assert self.state_path is not None
        raw, fingerprint = self._read_bounded_regular_file_snapshot(self.state_path)
        try:
            payload = json.loads(
                raw.decode("utf-8-sig"),
                object_pairs_hook=_reject_duplicate_keys,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ProtocolError("recipient key trust state is invalid JSON") from exc
        required = {
            "current_certificate",
            "destination_connector",
            "format",
            "identity_key_id",
            "tenant",
            "used_key_ids",
            "version",
        }
        if not isinstance(payload, dict) or set(payload) != required:
            raise ProtocolError("recipient key trust state has unexpected or missing fields")
        if payload["format"] != _STATE_FORMAT or (
            isinstance(payload["version"], bool)
            or not isinstance(payload["version"], int)
            or payload["version"] != _STATE_VERSION
        ):
            raise ProtocolError("recipient key trust state format is unsupported")
        for label in ("identity_key_id", "tenant", "destination_connector"):
            if not isinstance(payload[label], str):
                raise ProtocolError(f"recipient key trust state {label} must be a string")
        if (
            payload["identity_key_id"] != self.identity_key_id
            or payload["tenant"] != self.tenant
            or payload["destination_connector"] != self.destination_connector
        ):
            raise IntegrityError("recipient key trust state does not match its pinned identity")
        certificate = RecipientKeyCertificate.from_wire(payload["current_certificate"])
        self._verify_certificate(certificate, now=None, require_current_validity=False)
        raw_used_key_ids = payload["used_key_ids"]
        if not isinstance(raw_used_key_ids, list) or len(raw_used_key_ids) > _MAX_USED_KEY_IDS:
            raise ProtocolError("recipient key trust state used-key history is invalid")
        used_key_ids: set[str] = set()
        for value in raw_used_key_ids:
            if not isinstance(value, str):
                raise ProtocolError("recipient key trust state used-key id must be a string")
            _key_id(value, "recipient trust-state used-key id")
            if value in used_key_ids:
                raise ProtocolError("recipient key trust state repeats a used-key id")
            used_key_ids.add(value)
        if certificate.key_id not in used_key_ids:
            raise IntegrityError("recipient key trust state omits its current key from history")
        return certificate, used_key_ids, fingerprint

    def _reload_state_if_changed(self) -> None:
        """Refresh a persisted head while callers hold both process-local and path locks."""

        fingerprint = self._state_path_fingerprint()
        if fingerprint == self._state_fingerprint:
            return
        self._current, self._used_key_ids, self._state_fingerprint = self._read_state()
        self._head_revision += 1

    @staticmethod
    def _verify_current_validity(
        certificate: RecipientKeyCertificate,
        *,
        now: datetime | None,
    ) -> None:
        current = _utc(now or datetime.now(UTC), "verification time")
        if current < certificate.not_before:
            raise IntegrityError("recipient key certificate is not active yet")
        if current > certificate.not_after:
            raise IntegrityError("recipient key certificate has expired")

    def _accept_transition(
        self,
        certificate: RecipientKeyCertificate,
        *,
        now: datetime | None,
    ) -> bool:
        self._verify_certificate(certificate, now=now, require_current_validity=True)
        current = self._current
        if current is None:
            if certificate.generation != 1 or certificate.previous_key_id is not None:
                raise IntegrityError("recipient key trust bootstrap must start at generation 1")
            if self._used_key_ids:
                raise IntegrityError("recipient key trust history exists without a current key")
        elif certificate == current:
            return False
        else:
            if certificate.generation <= current.generation:
                raise IntegrityError("recipient key certificate is a rollback or conflicting fork")
            if certificate.generation != current.generation + 1:
                raise IntegrityError("recipient key rotation skipped a generation")
            if certificate.previous_key_id != current.key_id:
                raise IntegrityError("recipient key rotation does not continue the trusted chain")
            if certificate.issued_at < current.issued_at:
                raise IntegrityError("recipient key rotation issuance time moved backwards")
            if certificate.key_id in self._used_key_ids:
                raise IntegrityError("recipient key rotation reuses retired key material")
            if len(self._used_key_ids) >= _MAX_USED_KEY_IDS:
                raise IntegrityError("recipient key rotation history capacity is exhausted")
        self._current = certificate
        self._used_key_ids.add(certificate.key_id)
        return True

    def accept(
        self,
        certificate: RecipientKeyCertificate,
        *,
        now: datetime | None = None,
    ) -> RecipientKeyCertificate:
        """Verify and atomically advance to exactly the next signed certificate."""

        with self._lock:
            if self.state_path is None:
                if self._accept_transition(certificate, now=now):
                    self._head_revision += 1
                return certificate
            _reject_linked_path_components(self.state_path, include_leaf=True)
            with exclusive_path_lock(self.state_path):
                _reject_linked_path_components(self.state_path, include_leaf=True)
                if self.state_path.exists():
                    self._reload_state_if_changed()
                elif self._current is not None:
                    raise IntegrityError("recipient key trust state disappeared")
                previous_current = self._current
                previous_used_key_ids = set(self._used_key_ids)
                changed = self._accept_transition(certificate, now=now)
                if changed:
                    # A concurrent source batch must fail closed even if publication later
                    # becomes ambiguous and the last in-memory head is restored.
                    self._head_revision += 1
                    try:
                        atomic_write_text(
                            self.state_path,
                            json.dumps(
                                self._state_wire(certificate),
                                sort_keys=True,
                                separators=(",", ":"),
                                ensure_ascii=False,
                            )
                            + "\n",
                            private=True,
                        )
                    except OSError as exc:
                        # The replace outcome can be ambiguous, so do not claim either head in
                        # memory. Restore the last state observed under the path lock; the next
                        # operation must reload the persisted head before making a decision.
                        self._current = previous_current
                        self._used_key_ids = previous_used_key_ids
                        self._state_fingerprint = None
                        raise IntegrityError(
                            "recipient key trust-state update outcome is uncertain; "
                            "inspect the persisted head before retrying"
                        ) from exc
                    self._state_fingerprint = self._state_path_fingerprint()
                # This also runs for an idempotent accept. A retry after an earlier directory
                # fsync error can therefore complete durability without rewriting the head.
                try:
                    _sync_parent_directory(self.state_path)
                except OSError as exc:
                    raise IntegrityError(
                        "recipient key trust-state durability is uncertain after replacement; "
                        "inspect the persisted head before retrying"
                    ) from exc
                return certificate

    def verify(
        self,
        certificate: RecipientKeyCertificate,
        *,
        now: datetime | None = None,
    ) -> RecipientKeyCertificate:
        """Verify identity, route and validity without changing the trusted head."""

        self._verify_certificate(certificate, now=now, require_current_validity=True)
        return certificate

    def current(self, *, now: datetime | None = None) -> RecipientKeyCertificate:
        """Return the current route key only after signature, binding and time checks."""

        with self._lock:
            certificate = self._refresh_current_locked()
            self._verify_current_validity(certificate, now=now)
            return certificate

    def _refresh_current_locked(self) -> RecipientKeyCertificate:
        """Refresh the head while the caller holds the store's process-local lock."""

        if self.state_path is not None:
            _reject_linked_path_components(self.state_path, include_leaf=True)
            with exclusive_path_lock(self.state_path):
                _reject_linked_path_components(self.state_path, include_leaf=True)
                if not self.state_path.exists():
                    raise IntegrityError("recipient key trust state is not initialized")
                self._reload_state_if_changed()
        certificate = self._current
        if certificate is None:
            raise IntegrityError("recipient key trust store is not initialized")
        return certificate

    def begin_batch_authorization(
        self,
        *,
        tenant: str,
        destination_connector: str,
    ) -> RecipientKeyBatchAuthorization:
        """Snapshot one verified head before an all-or-none in-memory source batch."""

        if tenant != self.tenant or destination_connector != self.destination_connector:
            raise IntegrityError("recipient key trust store is bound to a different route")
        with self._lock:
            certificate = self._refresh_current_locked()
            return RecipientKeyBatchAuthorization(
                certificate=certificate,
                _store_token=self._batch_authorization_token,
                _head_revision=self._head_revision,
                _state_fingerprint=self._state_fingerprint,
            )

    def authorize_batch_record(
        self,
        authorization: RecipientKeyBatchAuthorization,
        *,
        now: datetime,
    ) -> RecipientKeyCertificate:
        """Check the snapshotted certificate's validity for one record issuance time."""

        if authorization._store_token is not self._batch_authorization_token:
            raise IntegrityError("recipient batch authorization belongs to another trust store")
        self._verify_current_validity(authorization.certificate, now=now)
        return authorization.certificate

    def confirm_batch_authorization(
        self,
        authorization: RecipientKeyBatchAuthorization,
    ) -> None:
        """Fail if rotation, replacement or tampering happened while a batch was sealed."""

        if authorization._store_token is not self._batch_authorization_token:
            raise IntegrityError("recipient batch authorization belongs to another trust store")
        with self._lock:
            certificate = self._refresh_current_locked()
            if (
                self._head_revision != authorization._head_revision
                or self._state_fingerprint != authorization._state_fingerprint
                or certificate != authorization.certificate
            ):
                raise IntegrityError("recipient key trust head changed during source batch")

    def authorize(
        self,
        *,
        tenant: str,
        destination_connector: str,
        now: datetime | None = None,
    ) -> RecipientKeyCertificate:
        if tenant != self.tenant or destination_connector != self.destination_connector:
            raise IntegrityError("recipient key trust store is bound to a different route")
        return self.current(now=now)

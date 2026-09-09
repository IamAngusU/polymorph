from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .errors import IntegrityError, PolymorphError, ProtocolError
from .filesystem import atomic_write_text

_KEY_FILE_FORMAT = "angusu.bridge/recipient-key"
_KEY_FILE_VERSION = 1


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str, *, expected: int | None = None) -> bytes:
    try:
        data = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except Exception as exc:
        raise ProtocolError("encrypted key file contains invalid base64url") from exc
    if expected is not None and len(data) != expected:
        raise ProtocolError("encrypted key file contains an invalid field length")
    return data


def _passphrase_bytes(passphrase: str | bytes) -> bytes:
    value = passphrase.encode("utf-8") if isinstance(passphrase, str) else bytes(passphrase)
    if len(value) < 12:
        raise ValueError("key-file passphrase must contain at least 12 UTF-8 bytes")
    return value


@dataclass(frozen=True, slots=True)
class KeyFileParameters:
    memory_cost_kib: int = 64 * 1024
    iterations: int = 3
    lanes: int = 4

    def __post_init__(self) -> None:
        if not 8 * 1024 <= self.memory_cost_kib <= 1024 * 1024:
            raise ValueError("Argon2id memory cost is outside supported range")
        if not 1 <= self.iterations <= 20:
            raise ValueError("Argon2id iteration count is outside supported range")
        if not 1 <= self.lanes <= 16:
            raise ValueError("Argon2id lanes are outside supported range")


def _derive(passphrase: bytes, salt: bytes, params: KeyFileParameters) -> bytes:
    try:
        return Argon2id(
            salt=salt,
            length=32,
            iterations=params.iterations,
            lanes=params.lanes,
            memory_cost=params.memory_cost_kib,
            ad=_KEY_FILE_FORMAT.encode("ascii"),
            secret=None,
        ).derive(passphrase)
    except UnsupportedAlgorithm as exc:
        raise PolymorphError("Argon2id is unavailable in this cryptography/OpenSSL build") from exc


def _aad(public_key: bytes, params: KeyFileParameters) -> bytes:
    payload = {
        "format": _KEY_FILE_FORMAT,
        "version": _KEY_FILE_VERSION,
        "public_key": _b64(public_key),
        "kdf": {
            "name": "argon2id",
            "memory_cost_kib": params.memory_cost_kib,
            "iterations": params.iterations,
            "lanes": params.lanes,
        },
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class EncryptedRecipientKeyFile:
    """Password-encrypted X25519 recipient key stored without plaintext private material."""

    @staticmethod
    def create(
        path: str | Path,
        passphrase: str | bytes,
        *,
        params: KeyFileParameters | None = None,
    ) -> bytes:
        target = Path(path)
        params = params or KeyFileParameters()
        password = _passphrase_bytes(passphrase)
        private_key = X25519PrivateKey.generate()
        private_raw = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = _derive(password, salt, params)
        ciphertext = ChaCha20Poly1305(key).encrypt(nonce, private_raw, _aad(public_raw, params))
        payload = {
            "format": _KEY_FILE_FORMAT,
            "version": _KEY_FILE_VERSION,
            "public_key": _b64(public_raw),
            "kdf": {
                "name": "argon2id",
                "salt": _b64(salt),
                "memory_cost_kib": params.memory_cost_kib,
                "iterations": params.iterations,
                "lanes": params.lanes,
            },
            "cipher": {
                "name": "chacha20-poly1305",
                "nonce": _b64(nonce),
                "ciphertext": _b64(ciphertext),
            },
        }
        atomic_write_text(
            target,
            json.dumps(payload, sort_keys=True, indent=2) + "\n",
            private=True,
        )
        return public_raw

    @staticmethod
    def _load_payload(path: str | Path) -> dict[str, object]:
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProtocolError("recipient key file is unreadable or invalid") from exc
        if payload.get("format") != _KEY_FILE_FORMAT or payload.get("version") != _KEY_FILE_VERSION:
            raise ProtocolError("recipient key file format is unsupported")
        return payload

    @classmethod
    def public_key(cls, path: str | Path) -> bytes:
        payload = cls._load_payload(path)
        return _unb64(str(payload["public_key"]), expected=32)

    @classmethod
    def load(cls, path: str | Path, passphrase: str | bytes) -> X25519PrivateKey:
        payload = cls._load_payload(path)
        public_raw = _unb64(str(payload["public_key"]), expected=32)
        try:
            kdf = dict(payload["kdf"])
            cipher = dict(payload["cipher"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("recipient key file structure is invalid") from exc
        if kdf.get("name") != "argon2id" or cipher.get("name") != "chacha20-poly1305":
            raise ProtocolError("recipient key file algorithms are unsupported")
        try:
            params = KeyFileParameters(
                memory_cost_kib=int(kdf["memory_cost_kib"]),
                iterations=int(kdf["iterations"]),
                lanes=int(kdf["lanes"]),
            )
            salt = _unb64(str(kdf["salt"]), expected=16)
            nonce = _unb64(str(cipher["nonce"]), expected=12)
            ciphertext = _unb64(str(cipher["ciphertext"]), expected=48)
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("recipient key file parameters are invalid") from exc
        key = _derive(_passphrase_bytes(passphrase), salt, params)
        try:
            private_raw = ChaCha20Poly1305(key).decrypt(
                nonce,
                ciphertext,
                _aad(public_raw, params),
            )
        except InvalidTag as exc:
            raise IntegrityError("recipient key file authentication failed") from exc
        private = X25519PrivateKey.from_private_bytes(private_raw)
        actual_public = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if actual_public != public_raw:
            raise IntegrityError("recipient key file public/private key mismatch")
        return private

    @classmethod
    def validate(cls, path: str | Path, passphrase: str | bytes) -> bytes:
        private = cls.load(path, passphrase)
        return private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

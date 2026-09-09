from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import IntegrityError, ProtocolError


@dataclass(frozen=True, slots=True)
class SigningKeyPair:
    """In-memory Ed25519 signing identity.

    Private-key persistence is deliberately outside the core. Production deployments should
    load signing operations from an OS keystore, HSM or another explicitly trusted provider.
    """

    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "SigningKeyPair":
        return cls(Ed25519PrivateKey.generate())

    def public_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, payload: bytes) -> bytes:
        return self.private_key.sign(payload)


def verify_ed25519(public_key: bytes, payload: bytes, signature: bytes) -> None:
    if len(public_key) != 32:
        raise ProtocolError("Ed25519 public key must be 32 bytes")
    if len(signature) != 64:
        raise IntegrityError("Ed25519 signature must be 64 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (InvalidSignature, ValueError) as exc:
        raise IntegrityError("signature verification failed") from exc

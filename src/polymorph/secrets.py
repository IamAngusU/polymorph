from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

from .errors import ConnectorError, PolymorphError


class SecretProvider(Protocol):
    def get(self, reference: str) -> str: ...


@dataclass(frozen=True, slots=True)
class EnvironmentSecretProvider:
    """Explicit environment-backed provider for controlled server deployments.

    Environment variables are convenient but are not claimed to be a hardware-backed secret
    store. Prefer KeyringSecretProvider where a platform credential store is available.
    """

    prefix: str = "ANGUSU_BRIDGE_SECRET_"

    def get(self, reference: str) -> str:
        if not reference or not reference.replace("_", "").replace("-", "").isalnum():
            raise ConnectorError("secret reference contains unsupported characters")
        name = self.prefix + reference.upper().replace("-", "_")
        value = os.environ.get(name)
        if value is None:
            raise ConnectorError("referenced environment secret is unavailable")
        return value


@dataclass(frozen=True, slots=True)
class KeyringSecretProvider:
    """Resolve credential references through the operating system keyring backend."""

    service: str = "angusu.bridge"

    def get(self, reference: str) -> str:
        try:
            import keyring
        except ImportError as exc:
            raise PolymorphError(
                "keyring extra is required for OS credential-store access"
            ) from exc
        value = keyring.get_password(self.service, reference)
        if value is None:
            raise ConnectorError("referenced keyring secret is unavailable")
        return value


@dataclass(frozen=True, slots=True)
class MappingSecretProvider:
    """In-memory provider intended for tests and embedding into a trusted host process."""

    values: dict[str, str]

    def get(self, reference: str) -> str:
        try:
            return self.values[reference]
        except KeyError as exc:
            raise ConnectorError("referenced secret is unavailable") from exc

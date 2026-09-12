from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .errors import ConnectorError

MAX_ACCESS_TOKEN_CHARS = 16_384
MAX_TOKEN_LIFETIME_SECONDS = 366 * 24 * 60 * 60


class OAuthRefreshCallback(Protocol):
    def __call__(self, credential_reference: str) -> OAuthAccessToken: ...


@dataclass(frozen=True, slots=True)
class OAuthAccessToken:
    """An in-memory bearer token whose representation never contains the secret."""

    access_token: str
    expires_at_epoch: float
    scopes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.access_token or len(self.access_token) > MAX_ACCESS_TOKEN_CHARS:
            raise ConnectorError("OAuth access token has an invalid length")
        if "\r" in self.access_token or "\n" in self.access_token:
            raise ConnectorError("OAuth access token contains a line break")
        if not math.isfinite(self.expires_at_epoch) or self.expires_at_epoch <= 0:
            raise ConnectorError("OAuth access token has an invalid expiry")
        if len(self.scopes) > 256 or any(not scope or len(scope) > 256 for scope in self.scopes):
            raise ConnectorError("OAuth access token scopes exceed the local safety limit")

    def usable(self, now_epoch: float, refresh_skew_seconds: float) -> bool:
        return self.expires_at_epoch - refresh_skew_seconds > now_epoch

    def __repr__(self) -> str:
        return (
            "OAuthAccessToken(access_token=<redacted>, "
            f"expires_at_epoch={self.expires_at_epoch!r}, scopes={self.scopes!r})"
        )


class RefreshingOAuthSecretProvider:
    """Thread-safe, in-memory token refresh adapter implementing SecretProvider.

    Authorization-code handling, refresh-token persistence, and provider HTTP behavior stay in
    the trusted host callback. Polymorph receives only a credential reference and a short-lived
    access token. Failed refreshes never expose callback details through the public error text.
    """

    __slots__ = ("_clock", "_refresh", "_refresh_skew_seconds", "_lock", "_tokens")

    def __init__(
        self,
        refresh: OAuthRefreshCallback,
        *,
        refresh_skew_seconds: float = 60.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not math.isfinite(refresh_skew_seconds) or refresh_skew_seconds < 0:
            raise ValueError("refresh skew must be a finite non-negative number")
        self._refresh = refresh
        self._refresh_skew_seconds = refresh_skew_seconds
        self._clock = clock
        self._lock = threading.RLock()
        self._tokens: dict[str, OAuthAccessToken] = {}

    @staticmethod
    def _reference(reference: str) -> str:
        if (
            not reference
            or len(reference) > 256
            or not reference.replace("_", "").replace("-", "").isalnum()
        ):
            raise ConnectorError("OAuth credential reference contains unsupported characters")
        return reference

    def get(self, reference: str) -> str:
        key = self._reference(reference)
        with self._lock:
            now = self._clock()
            token = self._tokens.get(key)
            if token is not None and token.usable(now, self._refresh_skew_seconds):
                return token.access_token
            try:
                refreshed = self._refresh(key)
            except Exception as exc:
                raise ConnectorError("OAuth token refresh failed") from exc
            if not isinstance(refreshed, OAuthAccessToken):
                raise ConnectorError("OAuth refresh callback returned an unsupported token")
            if refreshed.expires_at_epoch - now > MAX_TOKEN_LIFETIME_SECONDS:
                raise ConnectorError("OAuth access token lifetime exceeds the local safety limit")
            if not refreshed.usable(now, self._refresh_skew_seconds):
                raise ConnectorError("OAuth refresh returned an already expiring access token")
            self._tokens[key] = refreshed
            return refreshed.access_token

    def invalidate(self, reference: str) -> None:
        key = self._reference(reference)
        with self._lock:
            self._tokens.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._tokens.clear()

    def cached_references(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._tokens))

    def __repr__(self) -> str:
        return (
            "RefreshingOAuthSecretProvider(refresh=<callback>, "
            f"refresh_skew_seconds={self._refresh_skew_seconds!r}, cached=<redacted>)"
        )

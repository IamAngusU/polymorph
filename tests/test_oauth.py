from __future__ import annotations

import traceback

import pytest

from polymorph.errors import ConnectorError
from polymorph.oauth import OAuthAccessToken, RefreshingOAuthSecretProvider


def test_refreshing_oauth_provider_caches_then_refreshes_without_repr_leak() -> None:
    now = [1000.0]
    calls: list[str] = []

    def refresh(reference: str) -> OAuthAccessToken:
        calls.append(reference)
        return OAuthAccessToken(f"secret-{len(calls)}", now[0] + 120)

    provider = RefreshingOAuthSecretProvider(refresh, refresh_skew_seconds=30, clock=lambda: now[0])
    assert provider.get("erp-main") == "secret-1"
    assert provider.get("erp-main") == "secret-1"
    now[0] = 1095.0
    assert provider.get("erp-main") == "secret-2"
    assert calls == ["erp-main", "erp-main"]
    assert "secret-2" not in repr(provider)


def test_refresh_failure_does_not_echo_provider_secret() -> None:
    def fail(_: str) -> OAuthAccessToken:
        raise RuntimeError("refresh-token-super-secret")

    provider = RefreshingOAuthSecretProvider(fail)
    with pytest.raises(ConnectorError, match="refresh failed") as captured:
        provider.get("api")
    assert "super-secret" not in str(captured.value)
    assert captured.value.__cause__ is None
    assert "super-secret" not in "".join(traceback.format_exception(captured.value))


def test_access_token_rejects_header_injection() -> None:
    with pytest.raises(ConnectorError, match="line break"):
        OAuthAccessToken("safe\r\nX-Evil: yes", 2000)

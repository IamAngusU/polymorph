from __future__ import annotations

import pytest

from polymorph.connectors.database import DatabaseEndpoint
from polymorph.errors import ConnectorError
from polymorph.secrets import EnvironmentSecretProvider, MappingSecretProvider


def test_database_endpoint_resolves_password_only_through_provider() -> None:
    endpoint = DatabaseEndpoint(
        drivername="postgresql+psycopg",
        host="db.internal",
        database="app",
        username="bridge",
        password_ref="db-main",
    )
    with pytest.raises(ConnectorError, match="provider"):
        endpoint.sqlalchemy_url()
    url = endpoint.sqlalchemy_url(MappingSecretProvider({"db-main": "top-secret"}))
    assert url.password == "top-secret"
    assert "top-secret" not in str(url)


def test_environment_secret_provider_uses_reference_not_value(monkeypatch) -> None:
    monkeypatch.setenv("ANGUSU_BRIDGE_SECRET_API_MAIN", "secret-value")
    provider = EnvironmentSecretProvider()
    assert provider.get("api-main") == "secret-value"

from __future__ import annotations

import time

from polymorph.oauth import OAuthAccessToken, RefreshingOAuthSecretProvider


def refresh_from_your_vault(credential_reference: str) -> OAuthAccessToken:
    # Exchange a vault-held refresh token in the trusted host. Never log either token.
    del credential_reference
    raise NotImplementedError("connect your provider-specific OAuth client here")


provider = RefreshingOAuthSecretProvider(refresh_from_your_vault, refresh_skew_seconds=90)

# HTTP connectors can use this object anywhere a SecretProvider is accepted. The access token is
# cached in memory only and refreshed before `time.time() + 90` reaches its expiry.
assert time.time() > 0

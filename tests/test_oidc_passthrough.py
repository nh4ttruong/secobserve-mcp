"""A gateway forwarding the caller's own OIDC access token, which SecObserve resolves to the real user."""

from __future__ import annotations

import pytest

from secobserve_mcp.config import CREDENTIAL_SCHEMES, ConfigError, request_auth_header, request_credential


def test_bearer_reaches_secobserve_untouched() -> None:
    """SecObserve's OIDCAuthentication reads `Bearer` and validates it against the IdP, so nothing is rewritten."""
    # Not JWT-shaped on purpose: a realistic-looking one trips secret scanning, and the assertion is
    # byte-equality, so the shape of the value proves nothing the fixture needs.
    with request_credential("Bearer an-access-token-from-the-idp"):
        assert request_auth_header() == "Bearer an-access-token-from-the-idp"


@pytest.mark.parametrize("scheme", CREDENTIAL_SCHEMES)
def test_every_accepted_scheme_survives_the_round_trip(scheme: str) -> None:
    with request_credential(f"{scheme} a-token"):
        assert request_auth_header() == f"{scheme} a-token"


def test_a_scheme_secobserve_does_not_implement_is_still_refused() -> None:
    """Widening the allowlist must not turn it into "anything with a space in it"."""
    with request_credential("Basic dXNlcjpwYXNz"), pytest.raises(ConfigError) as refused:
        request_auth_header()

    assert "Bearer" in str(refused.value)


def test_bearer_is_not_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """An access token frozen at startup expires; only a per-request one is worth honouring."""
    from secobserve_mcp import config

    monkeypatch.setenv(config.ENV_API_TOKEN, "the-service-account")
    config.get_config.cache_clear()
    try:
        assert config.get_config().auth_header == "APIToken the-service-account"
    finally:
        config.get_config.cache_clear()

"""Environment-driven configuration for the SecObserve MCP server."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache

ENV_BASE_URL = "SECOBSERVE_BASE_URL"
ENV_API_TOKEN = "SECOBSERVE_API_TOKEN"
ENV_JWT = "SECOBSERVE_JWT"
ENV_TIMEOUT = "SECOBSERVE_TIMEOUT"
ENV_VERIFY_SSL = "SECOBSERVE_VERIFY_SSL"
ENV_READ_ONLY = "SECOBSERVE_READ_ONLY"
ENV_ALLOW_DELETE = "SECOBSERVE_ALLOW_DELETE"
ENV_EXPORT_DIR = "SECOBSERVE_EXPORT_DIR"
ENV_IMPORT_DIR = "SECOBSERVE_IMPORT_DIR"

CREDENTIAL_HEADER = "X-SecObserve-Token"
CREDENTIAL_SCHEMES = ("APIToken", "JWT")

DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_TIMEOUT = 60.0


class ConfigError(RuntimeError):
    """Raised when the server is started without usable credentials."""


def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    base_url: str
    api_token: str | None
    jwt: str | None
    timeout: float
    verify_ssl: bool
    read_only: bool
    allow_delete: bool
    export_dir: str
    import_dir: str

    @property
    def auth_header(self) -> str:
        # API tokens are the documented integration path; JWT is accepted for
        # short-lived interactive use with a user's own frontend session.
        if self.api_token:
            return f"APIToken {self.api_token}"
        if self.jwt:
            return f"JWT {self.jwt}"
        raise ConfigError(
            f"No credentials configured. Set {ENV_API_TOKEN} (recommended) or {ENV_JWT}. "
            "A user API token is created via POST /api/authentication/create_user_api_token/."
        )

    @property
    def api_root(self) -> str:
        return f"{self.base_url}/api"


@lru_cache(maxsize=1)
def get_config() -> Config:
    base_url = os.environ.get(ENV_BASE_URL, DEFAULT_BASE_URL).rstrip("/")
    try:
        timeout = float(os.environ.get(ENV_TIMEOUT, DEFAULT_TIMEOUT))
    except ValueError as exc:
        raise ConfigError(f"{ENV_TIMEOUT} must be a number of seconds") from exc

    return Config(
        base_url=base_url,
        api_token=os.environ.get(ENV_API_TOKEN) or None,
        jwt=os.environ.get(ENV_JWT) or None,
        timeout=timeout,
        verify_ssl=_bool_env(ENV_VERIFY_SSL, True),
        read_only=_bool_env(ENV_READ_ONLY, False),
        # Deletes cascade in SecObserve, so they stay off unless switched on.
        allow_delete=_bool_env(ENV_ALLOW_DELETE, False),
        export_dir=os.environ.get(ENV_EXPORT_DIR) or os.path.join(os.getcwd(), "secobserve-exports"),
        # Uploads are confined to one tree so a crafted path cannot push
        # arbitrary local files into SecObserve.
        import_dir=os.environ.get(ENV_IMPORT_DIR) or os.getcwd(),
    )


# Config is cached for the process lifetime, so a credential that differs per caller cannot live on it.
_request_credential: ContextVar[str | None] = ContextVar("secobserve_request_credential", default=None)


@contextmanager
def request_credential(value: str | None) -> Iterator[None]:
    """Make `value` the credential inside this block; None leaves the environment's in force."""
    token = _request_credential.set(value)
    try:
        yield
    finally:
        _request_credential.reset(token)


def request_auth_header() -> str:
    """The Authorization value for the call in flight: the credential the request carried, else the environment's.

    Raises:
        ConfigError: when the request carried a credential this server cannot read, or when neither source has one.
    """
    raw = _request_credential.get()
    if raw is None:
        return get_config().auth_header

    scheme, _, token = raw.partition(" ")
    if scheme not in CREDENTIAL_SCHEMES or not token.strip():
        raise ConfigError(
            f"{CREDENTIAL_HEADER} is malformed: send '<scheme> <token>', scheme {' or '.join(CREDENTIAL_SCHEMES)}. "
            "The call was refused rather than fall back to the server's own credential, "
            "which would attribute the action to the service account."
        )
    return raw

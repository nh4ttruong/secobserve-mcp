"""HTTP client for the SecObserve REST API.

One shared httpx.AsyncClient is reused for the process lifetime. Every error is
translated into a SecObserveError whose message tells the agent what to do next
-- DRF validation bodies are surfaced verbatim because they name the offending
field, which is the fastest route to a correct retry.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from .config import ConfigError, get_config, request_auth_header

_client: httpx.AsyncClient | None = None


class SecObserveError(RuntimeError):
    """An API call failed. The message is written for an agent to act on."""


class ReadOnlyError(SecObserveError):
    """A mutating call was attempted while the server is in read-only mode."""


def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        config = get_config()
        _client = httpx.AsyncClient(
            base_url=config.api_root,
            timeout=config.timeout,
            verify=config.verify_ssl,
            follow_redirects=False,
        )
    return _client


async def close_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


def _auth_headers() -> dict[str, str]:
    return {"Authorization": request_auth_header()}


def _describe_validation_body(body: Any) -> str:
    """Flatten a DRF error body into one line per offending field."""
    if isinstance(body, dict):
        parts = []
        for field, messages in body.items():
            if isinstance(messages, list):
                rendered = "; ".join(str(m) for m in messages)
            else:
                rendered = str(messages)
            parts.append(f"{field}: {rendered}")
        return " | ".join(parts)
    if isinstance(body, list):
        return "; ".join(str(m) for m in body)
    return str(body)


def _raise_for_status(response: httpx.Response, method: str, path: str) -> None:
    if response.is_success:
        return

    status = response.status_code
    try:
        body: Any = response.json()
    except (json.JSONDecodeError, ValueError):
        body = response.text[:500]

    detail = _describe_validation_body(body)
    where = f"{method} {path}"

    if status == 400:
        raise SecObserveError(
            f"{where} rejected the request (400): {detail}. "
            "Fix the named fields and retry; use secobserve_describe_resource to see the accepted schema."
        )
    if status == 401:
        raise SecObserveError(
            f"{where} was not authenticated (401): {detail}. "
            "The API token is missing, revoked or malformed -- check SECOBSERVE_API_TOKEN."
        )
    if status == 403:
        raise SecObserveError(
            f"{where} was forbidden (403): {detail}. "
            "The token's role lacks this permission on the product, or the action needs a superuser."
        )
    if status == 404:
        raise SecObserveError(
            f"{where} found nothing (404): {detail}. "
            "The id may not exist, or the token has no view permission on its product -- "
            "SecObserve hides objects outside the caller's products."
        )
    if status == 409:
        raise SecObserveError(
            f"{where} conflicted with current state (409): {detail}. "
            "Something is already running or still referenced; wait or clear the reference, then retry."
        )
    if status == 429:
        raise SecObserveError(f"{where} was rate limited (429): {detail}. Back off before retrying.")
    if status >= 500:
        raise SecObserveError(
            f"{where} failed server-side ({status}): {detail}. "
            "Check the SecObserve backend logs; retrying an identical request will usually fail again."
        )
    raise SecObserveError(f"{where} failed ({status}): {detail}")


async def request(
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: Any = None,
    files: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
    expect_binary: bool = False,
) -> Any:
    """Call the SecObserve API and return parsed JSON (or bytes when expect_binary).

    Args:
        method: HTTP verb, upper case.
        path: API path relative to /api, with a leading slash (e.g. "/observations/").
        params: Query parameters; None values are dropped.
        json_body: JSON request body.
        files: Multipart file parts, for the import endpoints.
        data: Multipart form fields, used together with files.
        expect_binary: Return raw bytes instead of parsed JSON (exports).

    Returns:
        Parsed JSON (dict/list), raw bytes, or None for an empty 204 response.

    Raises:
        SecObserveError: on any non-2xx response, timeout or transport failure.
        ReadOnlyError: when a mutating verb is used in read-only mode.
        ConfigError: when no credentials are configured, or the request carried one this server cannot read.
    """
    config = get_config()
    if method.upper() != "GET" and config.read_only:
        raise ReadOnlyError(
            f"Refusing {method} {path}: the server runs in read-only mode "
            "(SECOBSERVE_READ_ONLY). Unset it to allow writes."
        )

    clean_params = {k: v for k, v in (params or {}).items() if v is not None}
    client = get_client()

    try:
        response = await client.request(
            method.upper(),
            path,
            params=clean_params or None,
            json=json_body,
            files=files,
            data=data,
            headers=_auth_headers(),
        )
    except httpx.TimeoutException as exc:
        raise SecObserveError(
            f"{method} {path} timed out after {config.timeout}s. "
            "Narrow the filters or raise SECOBSERVE_TIMEOUT; metrics and import calls are the slow ones."
        ) from exc
    except httpx.TransportError as exc:
        raise SecObserveError(
            f"Cannot reach SecObserve at {config.base_url} ({type(exc).__name__}: {exc}). "
            "Check SECOBSERVE_BASE_URL and that the backend is running."
        ) from exc
    except ConfigError:
        raise

    _raise_for_status(response, method.upper(), path)

    if expect_binary:
        return response.content
    if response.status_code == 204 or not response.content:
        return None
    try:
        return response.json()
    except (json.JSONDecodeError, ValueError):
        return {"raw": response.text[:2000]}


def tool_errors(func: Callable[..., Awaitable[str]]) -> Callable[..., Awaitable[str]]:
    """Return expected failures as text instead of raising them.

    A raised exception reaches the client as a bare "Error executing tool <name>":
    the message is dropped, and with it every hint about which field was wrong or
    which filter exists. Returning the text keeps that guidance in front of the
    agent. Unexpected exceptions are still raised, because they are bugs.
    """

    @functools.wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> str:
        try:
            return await func(*args, **kwargs)
        except KeyError as exc:
            return f"Error: {exc.args[0] if exc.args else exc}"
        except (SecObserveError, ConfigError, ValueError) as exc:
            return f"Error: {exc}"

    return wrapper

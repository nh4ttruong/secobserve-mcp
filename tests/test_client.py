"""The client's job is to turn HTTP failures into instructions an agent can act on."""

from __future__ import annotations

import httpx
import pytest
import respx

from secobserve_mcp import config
from secobserve_mcp.client import ReadOnlyError, SecObserveError, request

from .conftest import BASE_URL

API = f"{BASE_URL}/api"


@respx.mock
async def test_get_sends_api_token_and_drops_none_params() -> None:
    route = respx.get(f"{API}/products/").mock(return_value=httpx.Response(200, json={"count": 0, "results": []}))

    await request("GET", "/products/", params={"page": 1, "name": None})

    sent = route.calls.last.request
    assert sent.headers["Authorization"] == "APIToken test-token"
    assert sent.url.params["page"] == "1"
    assert "name" not in sent.url.params


@respx.mock
async def test_list_params_are_repeated_not_joined() -> None:
    route = respx.get(f"{API}/observations/").mock(return_value=httpx.Response(200, json={"count": 0, "results": []}))

    await request("GET", "/observations/", params={"current_status": ["Open", "In review"]})

    assert route.calls.last.request.url.params.get_list("current_status") == ["Open", "In review"]


@respx.mock
async def test_validation_error_surfaces_the_offending_field() -> None:
    respx.patch(f"{API}/observations/1/assessment/").mock(
        return_value=httpx.Response(400, json={"comment": ["This field is required."]})
    )

    with pytest.raises(SecObserveError) as caught:
        await request("PATCH", "/observations/1/assessment/", json_body={})

    message = str(caught.value)
    assert "comment: This field is required." in message
    assert "secobserve_describe_resource" in message


@respx.mock
async def test_not_found_explains_the_permission_case() -> None:
    respx.get(f"{API}/products/99/").mock(return_value=httpx.Response(404, json={"detail": "Not found."}))

    with pytest.raises(SecObserveError, match="no view permission"):
        await request("GET", "/products/99/")


@respx.mock
async def test_conflict_tells_the_agent_to_wait() -> None:
    respx.post(f"{API}/periodic_tasks/run/").mock(
        return_value=httpx.Response(409, json={"detail": "Task 'x' is currently running"})
    )

    with pytest.raises(SecObserveError, match="already running or still referenced"):
        await request("POST", "/periodic_tasks/run/", json_body={"task": "x"})


@respx.mock
async def test_unreachable_host_names_the_setting_to_fix() -> None:
    respx.get(f"{API}/status/version/").mock(side_effect=httpx.ConnectError("refused"))

    with pytest.raises(SecObserveError, match="SECOBSERVE_BASE_URL"):
        await request("GET", "/status/version/")


@respx.mock
async def test_204_returns_none() -> None:
    respx.post(f"{API}/observations/bulk_assessment/").mock(return_value=httpx.Response(204))

    assert await request("POST", "/observations/bulk_assessment/", json_body={}) is None


async def test_read_only_mode_blocks_writes_before_the_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.ENV_READ_ONLY, "true")
    config.get_config.cache_clear()

    # No respx mock: a request escaping the guard would fail as a connection error instead.
    with pytest.raises(ReadOnlyError, match="read-only mode"):
        await request("POST", "/products/", json_body={"name": "x"})


@respx.mock
async def test_jwt_credentials_use_the_jwt_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(config.ENV_API_TOKEN)
    monkeypatch.setenv(config.ENV_JWT, "jwt-value")
    config.get_config.cache_clear()
    route = respx.get(f"{API}/users/me/").mock(return_value=httpx.Response(200, json={}))

    await request("GET", "/users/me/")

    assert route.calls.last.request.headers["Authorization"] == "JWT jwt-value"


async def test_missing_credentials_raise_a_config_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(config.ENV_API_TOKEN)
    config.get_config.cache_clear()

    with pytest.raises(config.ConfigError, match="create_user_api_token"):
        _ = config.get_config().auth_header

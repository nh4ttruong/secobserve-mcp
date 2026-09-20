"""A shared deployment has to be able to answer who read what, and SecObserve's observation log only records writes.

The line is driven through the real transports rather than by calling the middleware, because what has to hold is
that the credential the request carried is the one identified -- and that none of it reaches the line.
"""

from __future__ import annotations

import base64
import json
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
import respx
from mcp.server.context import ServerRequestContext

from secobserve_mcp import prompts, tools_crud, tools_workflows  # noqa: F401  # registers the tools
from secobserve_mcp.app import mcp
from secobserve_mcp.audit import ENV_AUDIT_LOG, audit_tool_calls
from secobserve_mcp.config import CREDENTIAL_HEADER

from .conftest import BASE_URL

API = f"{BASE_URL}/api"
# Streamable HTTP refuses a Host outside its DNS-rebinding allow-list, whose patterns all carry a port.
GATEWAY = "http://127.0.0.1:8931"

LINE_KEYS = {"ts", "tool", "caller", "claimed_username", "resource", "outcome", "ms"}
SECRET = "caller-secret-value"


@asynccontextmanager
async def gateway() -> AsyncIterator[httpx.AsyncClient]:
    """The server behind `--transport http`, reached the way a gateway reaches it."""
    app = mcp.streamable_http_app(stateless_http=True, json_response=True)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=GATEWAY) as client,
    ):
        yield client


async def call_tool(
    client: httpx.AsyncClient, tool: str, arguments: dict[str, Any], *, credential: str | None = None
) -> dict[str, Any]:
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if credential is not None:
        headers[CREDENTIAL_HEADER] = credential

    response = await client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": arguments}},
    )
    assert response.status_code == 200, response.text
    result: dict[str, Any] = response.json()["result"]
    return result


def audit_lines(capsys: pytest.CaptureFixture[str]) -> tuple[list[dict[str, Any]], str]:
    """Every audit line written so far, with the raw stderr they came from."""
    raw = capsys.readouterr().err
    lines = []
    for candidate in raw.splitlines():
        try:
            entry = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(entry, dict) and "outcome" in entry:
            lines.append(entry)
    return lines, raw


def jwt_claiming(username: Any) -> str:
    """A JWT-shaped token; the signature is never checked here, and neither is the payload."""
    payload = base64.urlsafe_b64encode(json.dumps({"username": username}).encode()).decode().rstrip("=")
    return f"header.{payload}.signature"


@respx.mock
async def test_a_tool_call_writes_one_line_naming_the_tool_the_caller_and_the_resource(
    capsys: pytest.CaptureFixture[str],
) -> None:
    respx.get(f"{API}/products/1/").mock(return_value=httpx.Response(200, json={"id": 1, "name": "p"}))

    async with gateway() as client:
        await call_tool(client, "secobserve_get", {"resource": "products", "id": 1}, credential=f"APIToken {SECRET}")

    lines, _ = audit_lines(capsys)
    assert len(lines) == 1
    line = lines[0]
    assert line.keys() == LINE_KEYS
    assert line["tool"] == "secobserve_get"
    assert line["resource"] == "products"
    assert line["outcome"] == "returned"
    assert line["caller"].startswith("apitoken:")
    assert line["claimed_username"] is None
    assert line["ms"] >= 0
    assert line["ts"].endswith("+00:00")


@respx.mock
async def test_the_credential_never_appears_in_the_line_and_still_correlates_one_caller(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The digest is the whole point: same caller, same value; different caller, different value; token unrecoverable."""
    respx.get(f"{API}/products/1/").mock(return_value=httpx.Response(200, json={"id": 1}))

    async with gateway() as client:
        for credential in (f"APIToken {SECRET}", f"APIToken {SECRET}", "APIToken other-secret"):
            await call_tool(client, "secobserve_get", {"resource": "products", "id": 1}, credential=credential)

    lines, raw = audit_lines(capsys)
    assert SECRET not in raw
    assert "other-secret" not in raw
    first, second, third = (line["caller"] for line in lines)
    assert first == second != third
    digest = first.split(":", 1)[1]
    assert len(digest) == 12
    assert set(digest) <= set("0123456789abcdef")


@respx.mock
async def test_a_jwt_records_the_username_it_claims_without_trusting_it(capsys: pytest.CaptureFixture[str]) -> None:
    """A gateway's JWT names a person, which no digest can; the token is still the caller's own unverified data."""
    respx.get(f"{API}/products/1/").mock(return_value=httpx.Response(200, json={"id": 1}))
    token = jwt_claiming("alice")

    async with gateway() as client:
        await call_tool(client, "secobserve_get", {"resource": "products", "id": 1}, credential=f"JWT {token}")

    lines, raw = audit_lines(capsys)
    assert lines[0]["claimed_username"] == "alice"
    assert lines[0]["caller"].startswith("jwt:")
    assert token not in raw


@pytest.mark.parametrize("token", ["not-a-jwt", "a.!!!.c", jwt_claiming({"nested": 1})])
@respx.mock
async def test_a_jwt_that_carries_no_readable_username_still_writes_a_full_line(
    capsys: pytest.CaptureFixture[str], token: str
) -> None:
    respx.get(f"{API}/products/1/").mock(return_value=httpx.Response(200, json={"id": 1}))

    async with gateway() as client:
        await call_tool(client, "secobserve_get", {"resource": "products", "id": 1}, credential=f"JWT {token}")

    lines, _ = audit_lines(capsys)
    assert lines[0].keys() == LINE_KEYS
    assert lines[0]["claimed_username"] is None


@respx.mock
async def test_a_resource_the_catalogue_does_not_know_is_dropped_rather_than_written(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The only argument recorded is an allow-listed one, so an argument cannot be used to write into the log."""
    async with gateway() as client:
        result = await call_tool(
            client, "secobserve_get", {"resource": "smuggled-secret", "id": 1}, credential=f"APIToken {SECRET}"
        )

    assert "smuggled-secret" in result["content"][0]["text"]
    lines, raw = audit_lines(capsys)
    assert lines[0]["resource"] is None
    assert "smuggled-secret" not in raw


@respx.mock
async def test_an_expected_failure_returned_as_text_is_recorded_as_returned(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`@tool_errors` turns a 404 into text, and this layer cannot read the string to tell -- so it does not claim to."""
    respx.get(f"{API}/products/99/").mock(return_value=httpx.Response(404, json={"detail": "Not found."}))

    async with gateway() as client:
        result = await call_tool(client, "secobserve_get", {"resource": "products", "id": 99}, credential="APIToken x")

    assert result["content"][0]["text"].startswith("Error:")
    lines, _ = audit_lines(capsys)
    assert lines[0]["outcome"] == "returned"


@respx.mock
async def test_a_tool_that_raises_still_fails_and_is_still_recorded(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exception `@tool_errors` does not catch is a bug, and a bug is exactly what the record must not lose."""

    async def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("bug")

    monkeypatch.setattr(tools_crud, "request", boom)

    async with gateway() as client:
        result = await call_tool(client, "secobserve_get", {"resource": "products", "id": 1}, credential="APIToken x")

    assert result["isError"] is True
    lines, _ = audit_lines(capsys)
    assert lines[0]["outcome"] == "error"
    assert lines[0]["tool"] == "secobserve_get"


@respx.mock
async def test_an_audit_write_that_fails_does_not_change_the_outcome_of_the_call(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    respx.get(f"{API}/products/1/").mock(return_value=httpx.Response(200, json={"id": 1, "name": "p"}))

    class Broken:
        def write(self, _: str) -> int:
            raise OSError("stderr is gone")

        def flush(self) -> None:
            raise OSError("stderr is gone")

    monkeypatch.setattr(sys, "stderr", Broken())

    async with gateway() as client:
        result = await call_tool(client, "secobserve_get", {"resource": "products", "id": 1}, credential="APIToken x")

    assert result.get("isError") is not True
    assert "p" in result["content"][0]["text"]


@respx.mock
async def test_the_env_var_switches_the_record_off(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_AUDIT_LOG, "false")
    respx.get(f"{API}/products/1/").mock(return_value=httpx.Response(200, json={"id": 1}))

    async with gateway() as client:
        await call_tool(client, "secobserve_get", {"resource": "products", "id": 1}, credential="APIToken x")

    lines, _ = audit_lines(capsys)
    assert lines == []


async def test_stdio_is_recorded_as_the_server_identity_in_the_same_shape(capsys: pytest.CaptureFixture[str]) -> None:
    """There is no per-request credential on stdio, so the caller is whoever the environment's credential belongs to."""
    ctx = ServerRequestContext[Any, Any](
        session=None,  # type: ignore[arg-type]  # the middleware never touches it
        lifespan_context={},
        protocol_version="2025-06-18",
        method="tools/call",
        params={"name": "secobserve_status", "arguments": {}},
        request=None,
    )

    async def call_next(_: ServerRequestContext[Any, Any]) -> dict[str, Any]:
        return {"content": []}

    assert await audit_tool_calls(ctx, call_next) == {"content": []}

    lines, raw = audit_lines(capsys)
    assert lines[0].keys() == LINE_KEYS
    assert lines[0]["tool"] == "secobserve_status"
    assert lines[0]["resource"] is None
    assert lines[0]["outcome"] == "returned"
    assert lines[0]["caller"].startswith("server:")
    assert "test-token" not in raw


async def test_a_message_that_is_not_a_tool_call_writes_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    ctx = ServerRequestContext[Any, Any](
        session=None,  # type: ignore[arg-type]  # the middleware never touches it
        lifespan_context={},
        protocol_version="2025-06-18",
        method="tools/list",
        params=None,
        request=None,
    )

    async def call_next(_: ServerRequestContext[Any, Any]) -> None:
        return None

    await audit_tool_calls(ctx, call_next)

    lines, _ = audit_lines(capsys)
    assert lines == []

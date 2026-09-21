"""One HTTP process serves many callers, so the credential has to be the request's rather than the process's.

Everything here drives the real streamable-HTTP app, because the question is whether the SDK gives each inbound
message its own context -- not whether a contextvar works.
"""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
import respx
from mcp.server.context import ServerRequestContext

from secobserve_mcp import prompts, schema, tools_crud, tools_workflows  # noqa: F401  # registers the tools
from secobserve_mcp.app import bind_request_credential, mcp
from secobserve_mcp.config import CREDENTIAL_HEADER, request_auth_header

from .conftest import BASE_URL

API = f"{BASE_URL}/api"
# Streamable HTTP refuses a Host outside its DNS-rebinding allow-list, whose patterns all carry a port.
GATEWAY = "http://127.0.0.1:8931"
MCP_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
SESSION_HEADER = "mcp-session-id"
# One dispatcher serves a whole stateful session, so two messages in flight on it need two JSON-RPC ids.
message_ids = itertools.count(1)


@asynccontextmanager
async def gateway(*, stateless: bool = True) -> AsyncIterator[httpx.AsyncClient]:
    """The server behind the transport `--transport http` runs, reached the way a gateway reaches it.

    Not a fixture: the session manager's task group refuses to be torn down from the separate task pytest-asyncio
    would close an async generator fixture in.

    Stateless is what `__main__` runs, and it gives every POST its own transport and dispatcher. Stateful shares one
    dispatcher across a whole session, so there the isolation rests on the per-task context and nothing else.
    """
    app = mcp.streamable_http_app(stateless_http=stateless, json_response=True)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=GATEWAY) as client,
    ):
        if not stateless:
            await open_session(client)
        yield client


async def open_session(client: httpx.AsyncClient) -> None:
    """Handshake, then keep the session id on the client so every later POST lands on that session's dispatcher."""
    opened = await client.post(
        "/mcp",
        headers=MCP_HEADERS,
        json={
            "jsonrpc": "2.0",
            "id": next(message_ids),
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "gateway", "version": "0"},
            },
        },
    )
    assert opened.status_code == 200, opened.text
    client.headers[SESSION_HEADER] = opened.headers[SESSION_HEADER]

    ready = await client.post(
        "/mcp", headers=MCP_HEADERS, json={"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    assert ready.status_code == 202, ready.text


async def call_tool(
    client: httpx.AsyncClient, tool: str, arguments: dict[str, Any], *, credential: str | None = None
) -> str:
    """Call one tool over MCP and return the text the agent would see."""
    headers = dict(MCP_HEADERS)
    if credential is not None:
        headers[CREDENTIAL_HEADER] = credential

    response = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": next(message_ids),
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        },
    )
    assert response.status_code == 200, response.text
    text: str = response.json()["result"]["content"][0]["text"]
    return text


async def fetch_product(client: httpx.AsyncClient, *, credential: str | None = None) -> str:
    return await call_tool(client, "secobserve_get", {"resource": "products", "id": 1}, credential=credential)


async def list_resource(client: httpx.AsyncClient, resource: str, *, credential: str) -> str:
    """A filtered list, which reads the schema before it reads the resource."""
    return await call_tool(
        client, "secobserve_list", {"resource": resource, "filters": {"name": "x"}}, credential=credential
    )


@pytest.mark.parametrize("credential", ["APIToken caller-secret", "JWT caller-secret"])
@respx.mock
async def test_the_credential_the_request_carried_is_the_one_secobserve_sees(credential: str) -> None:
    route = respx.get(f"{API}/products/1/").mock(return_value=httpx.Response(200, json={"id": 1, "name": "p"}))

    async with gateway() as client:
        await fetch_product(client, credential=credential)

    sent = route.calls.last.request
    assert sent.headers["Authorization"] == credential
    assert "caller-secret" not in str(sent.url)


@respx.mock
async def test_a_request_without_the_header_falls_back_to_the_environment() -> None:
    """A single-user HTTP deployment still works; whether one identity may serve many callers is a startup question."""
    route = respx.get(f"{API}/products/1/").mock(return_value=httpx.Response(200, json={"id": 1, "name": "p"}))

    async with gateway() as client:
        await fetch_product(client)

    assert route.calls.last.request.headers["Authorization"] == "APIToken test-token"


@pytest.mark.parametrize("credential", ["caller-secret", "Basic dXNlcjpwYXNz", "APIToken   ", "APIToken"])
@respx.mock
async def test_a_malformed_credential_is_refused_rather_than_ignored(credential: str) -> None:
    """Ignoring it would run the call as the service account, which is the failure this change exists to stop."""
    route = respx.get(f"{API}/products/1/").mock(return_value=httpx.Response(200, json={"id": 1}))

    async with gateway() as client:
        text = await fetch_product(client, credential=credential)

    assert not route.called
    assert CREDENTIAL_HEADER in text
    assert "caller-secret" not in text


@pytest.mark.parametrize("stateless", [True, False], ids=["stateless", "stateful"])
@respx.mock
async def test_concurrent_requests_never_see_each_others_credential(
    stateless: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both callers are bound at once, and neither unbinds until both have built the request that carries a credential.

    A filtered list reads the schema first: that read is held until the second caller reaches it, so both credentials
    are bound together, and the list read is held until both have stamped their Authorization, so neither can unbind
    early and leave the other reading the right value by luck. A holder shared between requests fails both ways.
    An empty schema means the filters pass through, which is what this server does when the schema cannot be read.

    Both callers share one session in stateful mode, so both are served by one dispatcher, which is the mode where
    only the per-task context the dispatcher spawns each message into keeps them apart. Barriers that never release
    would mean that dispatcher serialises the two, which is its own answer and also a failure.
    """
    monkeypatch.setattr(schema, "_schema", None)
    both_bound = asyncio.Barrier(2)
    both_stamped = asyncio.Barrier(2)

    def hold(barrier: asyncio.Barrier, body: dict[str, Any]) -> Any:
        async def park(request: httpx.Request) -> httpx.Response:
            await barrier.wait()
            return httpx.Response(200, json=body)

        return park

    respx.get(f"{API}/oa3/schema/").mock(side_effect=hold(both_bound, {}))
    page = {"count": 0, "results": []}
    first = respx.get(f"{API}/products/").mock(side_effect=hold(both_stamped, page))
    second = respx.get(f"{API}/product_names/").mock(side_effect=hold(both_stamped, page))

    async with gateway(stateless=stateless) as client, asyncio.timeout(10):
        await asyncio.gather(
            list_resource(client, "products", credential="APIToken first-secret"),
            list_resource(client, "product_names", credential="APIToken second-secret"),
        )

    assert first.calls.last.request.headers["Authorization"] == "APIToken first-secret"
    assert second.calls.last.request.headers["Authorization"] == "APIToken second-secret"


@respx.mock
async def test_one_session_rebinds_the_credential_on_every_message() -> None:
    """`Server.middleware` is the SDK's provisional hook, and the rework it waits on is about which tier runs a
    middleware. A hook that moved to a per-connection seam would still run, still bind, and still satisfy every
    single-request test here, while a stateful session served every later caller as the one who opened it.

    Three messages down one session say the binding is per message: each credential reaches SecObserve as its own,
    and the message that carries no header falls back to the environment rather than inheriting the previous one.
    """
    route = respx.get(f"{API}/products/1/").mock(return_value=httpx.Response(200, json={"id": 1, "name": "p"}))

    async with gateway(stateless=False) as client:
        await fetch_product(client, credential="APIToken first-secret")
        await fetch_product(client, credential="APIToken second-secret")
        await fetch_product(client)

    assert [call.request.headers["Authorization"] for call in route.calls] == [
        "APIToken first-secret",
        "APIToken second-secret",
        "APIToken test-token",
    ]


async def test_stdio_keeps_using_the_environment_credential() -> None:
    """The SDK attaches `request` only when the transport carried an HTTP one, so on stdio there is nothing to read."""
    ctx = ServerRequestContext[Any, Any](
        session=None,  # type: ignore[arg-type]  # the middleware never touches it
        lifespan_context={},
        protocol_version="2025-06-18",
        method="tools/call",
        request=None,
    )
    seen: list[str] = []

    async def call_next(_: ServerRequestContext[Any, Any]) -> None:
        seen.append(request_auth_header())

    await bind_request_credential(ctx, call_next)

    assert seen == ["APIToken test-token"]
    assert request_auth_header() == "APIToken test-token"


async def test_a_refused_write_does_not_blame_an_environment_variable_alone() -> None:
    """--shared-identity forces read-only without the operator ever setting SECOBSERVE_READ_ONLY."""
    from secobserve_mcp.client import ReadOnlyError, request
    from secobserve_mcp.config import CREDENTIAL_HEADER, get_config

    get_config.cache_clear()
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("SECOBSERVE_READ_ONLY", "true")
        get_config.cache_clear()
        with pytest.raises(ReadOnlyError) as refused:
            await request("POST", "/products/")

    get_config.cache_clear()
    message = str(refused.value)
    assert "--shared-identity" in message
    assert CREDENTIAL_HEADER in message
    assert "Unset it" not in message

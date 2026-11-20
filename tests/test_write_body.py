"""Body keys a serializer would drop: refused against the live schema before the write is sent."""

from __future__ import annotations

import json

import httpx
import respx

from secobserve_mcp import schema
from secobserve_mcp.tools_crud import secobserve_create, secobserve_update

from .test_schema import API, SCHEMA


@respx.mock
async def test_an_unknown_body_key_is_refused_before_the_write() -> None:
    """DRF drops an unknown key and still answers 200, so a misspelled field reports a write that never happened."""
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json=SCHEMA))
    write = respx.patch(f"{API}/general_rules/4/").mock(return_value=httpx.Response(200, json={"id": 4}))

    result = await secobserve_update(resource="general_rules", id=4, data={"enable": False})

    assert "enable is not a writable field" in result
    assert "Writable fields: enabled, name." in result, "the error must list what the agent can send instead"
    assert not write.called, "the request must not be sent at all"


@respx.mock
async def test_a_read_only_body_key_is_refused_before_the_write() -> None:
    """Without COMPONENT_SPLIT_REQUEST a request component keeps its read-only fields, marked readOnly."""
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json=SCHEMA))
    write = respx.post(f"{API}/observations/").mock(return_value=httpx.Response(201, json={"id": 5}))

    result = await secobserve_create(resource="observations", data={"product": 1, "title": "x", "id": 5})

    assert "id is not a writable field" in result
    assert "Writable fields: product, title." in result
    assert not write.called


@respx.mock
async def test_writable_body_keys_are_sent() -> None:
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json=SCHEMA))
    write = respx.patch(f"{API}/general_rules/4/").mock(return_value=httpx.Response(200, json={"id": 4}))

    await secobserve_update(resource="general_rules", id=4, data={"enabled": False})

    assert json.loads(write.calls.last.request.content) == {"enabled": False}


@respx.mock
async def test_body_keys_pass_through_when_the_schema_is_unavailable() -> None:
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(503))
    write = respx.patch(f"{API}/general_rules/4/").mock(return_value=httpx.Response(200, json={"id": 4}))

    await secobserve_update(resource="general_rules", id=4, data={"enable": False})

    assert write.called


@respx.mock
async def test_body_keys_pass_through_when_the_schema_has_no_body_for_the_method() -> None:
    """SCHEMA describes PATCH on a general rule but not PUT, so replace=True cannot be checked."""
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json=SCHEMA))
    write = respx.put(f"{API}/general_rules/4/").mock(return_value=httpx.Response(200, json={"id": 4}))

    await secobserve_update(resource="general_rules", id=4, data={"enable": False}, replace=True)

    assert write.called

"""describe_resource slices the live OpenAPI schema; the slicing is the logic worth testing."""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest
import respx

from secobserve_mcp import schema
from secobserve_mcp.tools_crud import (
    secobserve_describe_resource,
    secobserve_list,
)

from .conftest import BASE_URL

API = f"{BASE_URL}/api"

SCHEMA = {
    "paths": {
        "/api/observations/": {
            "get": {
                "parameters": [
                    {
                        "name": "current_severity",
                        "in": "query",
                        "schema": {"type": "array", "items": {"enum": ["Critical", "High"]}},
                    },
                    {"name": "product", "in": "query", "required": True, "schema": {"type": "integer"}},
                ],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/PaginatedObservationList"}}
                        }
                    }
                },
            },
            "post": {
                "requestBody": {
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ObservationCreate"}}}
                }
            },
        },
        # Shapes copied from the live schema: a MultipleChoiceFilter is an array parameter,
        # an auto-generated exact filter a scalar, and a method filter carries no type at all.
        "/api/observation_logs/": {
            "get": {
                "parameters": [
                    {
                        "name": "severity",
                        "in": "query",
                        "schema": {"type": "string", "enum": ["Critical", "High"]},
                    },
                    {"name": "age", "in": "query", "schema": {"enum": ["Today", "Past 7 days"]}},
                    {"name": "product", "in": "query", "schema": {"type": "integer"}},
                ]
            }
        },
    },
    "components": {
        "schemas": {
            "PaginatedObservationList": {
                "properties": {
                    "count": {"type": "integer"},
                    "results": {"type": "array", "items": {"$ref": "#/components/schemas/Observation"}},
                }
            },
            "Observation": {"properties": {"id": {}, "title": {}, "current_severity": {}}},
            "ObservationCreate": {
                "required": ["product", "title"],
                "properties": {
                    "product": {"type": "integer"},
                    "title": {"type": "string", "maxLength": 255},
                    "id": {"type": "integer", "readOnly": True},
                },
            },
        }
    },
}


@respx.mock
async def test_describe_resolves_refs_unwraps_pagination_and_marks_required() -> None:
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json=SCHEMA))

    described = json.loads(await secobserve_describe_resource(resource="observations", include_detail_path=False))

    get = described["operations"]["/observations/"]["GET"]
    severity = next(p for p in get["parameters"] if p["name"] == "current_severity")
    assert severity["enum"] == ["Critical", "High"]
    assert next(p for p in get["parameters"] if p["name"] == "product")["required"] is True
    # The row schema, not the pagination wrapper.
    assert get["response_fields"] == ["current_severity", "id", "title"]

    post = described["operations"]["/observations/"]["POST"]["body_fields"]
    assert post["title"] == {"type": "string", "required": True, "max_length": 255}
    assert post["id"]["read_only"] is True

    assert {a["name"] for a in described["actions"]} >= {"assessment", "bulk_assessment"}


@respx.mock
async def test_schema_is_fetched_once_per_process() -> None:
    schema._schema = None
    route = respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json=SCHEMA))

    await secobserve_describe_resource(resource="observations")
    await secobserve_describe_resource(resource="products")

    assert route.call_count == 1


@respx.mock
async def test_schema_is_refetched_once_the_ttl_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    schema._schema = None
    route = respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json=SCHEMA))

    # A stub on the module, not on time.monotonic itself: httpx uses the real
    # clock for its own timeouts and must keep seeing it.
    clock = {"now": 1000.0}
    monkeypatch.setattr(schema, "time", SimpleNamespace(monotonic=lambda: clock["now"]))

    await secobserve_describe_resource(resource="observations")
    clock["now"] += schema.SCHEMA_TTL_SECONDS - 1
    await secobserve_describe_resource(resource="products")
    assert route.call_count == 1

    clock["now"] += 2
    await secobserve_describe_resource(resource="products")
    assert route.call_count == 2


@respx.mock
async def test_missing_schema_entry_falls_back_to_the_static_catalogue() -> None:
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json={"paths": {}}))

    result = await secobserve_describe_resource(resource="products")

    assert "Static catalogue" in result
    assert "security_gate_passed" in result


@respx.mock
async def test_unknown_filter_is_rejected_instead_of_silently_ignored() -> None:
    """django-filter drops unknown parameters, which would return an unfiltered list."""
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json=SCHEMA))
    listing = respx.get(f"{API}/observations/").mock(return_value=httpx.Response(200, json={"count": 0, "results": []}))

    result = await secobserve_list(resource="observations", filters={"vulnerability_id": "CVE-2021-44228"})

    assert "is not a filter" in result
    assert "current_severity" in result, "the error must name the filters that do exist"
    assert not listing.called, "the request must not be sent at all"


@respx.mock
async def test_known_filters_pass_through() -> None:
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json=SCHEMA))
    listing = respx.get(f"{API}/observations/").mock(return_value=httpx.Response(200, json={"count": 0, "results": []}))

    await secobserve_list(resource="observations", filters={"product": 12})

    assert listing.called


@respx.mock
async def test_filters_pass_through_when_the_schema_is_unavailable() -> None:
    """A missing schema must not block work; the API stays the authority."""
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(503))
    listing = respx.get(f"{API}/observations/").mock(return_value=httpx.Response(200, json={"count": 0, "results": []}))

    await secobserve_list(resource="observations", filters={"anything": 1})

    assert listing.called


@respx.mock
async def test_metrics_falls_back_to_the_static_catalogue() -> None:
    """The metrics exports are separate schema paths, so /metrics/ itself is never in the schema."""
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json=SCHEMA))

    result = await secobserve_describe_resource(resource="metrics")

    assert "Static catalogue" in result
    assert "none, actions only" in result
    assert "export_codecharta" in result


@respx.mock
async def test_a_list_passes_on_a_filter_typed_as_an_array() -> None:
    """current_severity is a MultipleChoiceFilter: repeated values are an OR and must keep working."""
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json=SCHEMA))
    listing = respx.get(f"{API}/observations/").mock(return_value=httpx.Response(200, json={"count": 0, "results": []}))

    await secobserve_list(resource="observations", filters={"current_severity": ["Critical", "High"]})

    sent = str(listing.calls.last.request.url)
    assert "current_severity=Critical" in sent and "current_severity=High" in sent


@respx.mock
async def test_a_list_on_a_single_valued_filter_is_rejected() -> None:
    """The endpoint would keep the last value only and answer 200, so the count would be wrong."""
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json=SCHEMA))
    listing = respx.get(f"{API}/observation_logs/").mock(
        return_value=httpx.Response(200, json={"count": 0, "results": []})
    )

    result = await secobserve_list(resource="observation_logs", filters={"severity": ["Critical", "High"]})

    assert "severity takes a single value" in result
    assert "once per value" in result, "the error must say what to do instead"
    assert not listing.called, "the request must not be sent at all"


@respx.mock
async def test_a_single_value_passes_on_a_single_valued_filter() -> None:
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json=SCHEMA))
    listing = respx.get(f"{API}/observation_logs/").mock(
        return_value=httpx.Response(200, json={"count": 0, "results": []})
    )

    await secobserve_list(resource="observation_logs", filters={"severity": "Critical"})
    # One value in a list loses nothing, so it is not worth refusing.
    await secobserve_list(resource="observation_logs", filters={"severity": ["Critical"]})

    assert listing.call_count == 2


@respx.mock
async def test_a_list_passes_on_a_parameter_the_schema_does_not_type() -> None:
    """age is a method filter with no type: the schema does not say it is single-valued, so it is not blocked."""
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(200, json=SCHEMA))
    listing = respx.get(f"{API}/observation_logs/").mock(
        return_value=httpx.Response(200, json={"count": 0, "results": []})
    )

    await secobserve_list(resource="observation_logs", filters={"age": ["Today", "Past 7 days"]})

    assert listing.called


@respx.mock
async def test_a_list_passes_when_the_schema_is_unavailable() -> None:
    schema._schema = None
    respx.get(f"{API}/oa3/schema/").mock(return_value=httpx.Response(503))
    listing = respx.get(f"{API}/observation_logs/").mock(
        return_value=httpx.Response(200, json={"count": 0, "results": []})
    )

    await secobserve_list(resource="observation_logs", filters={"severity": ["Critical", "High"]})

    assert listing.called

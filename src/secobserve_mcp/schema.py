"""Read the deployed instance's OpenAPI schema so tool help cannot drift.

SecObserve serves a drf-spectacular schema at /api/oa3/schema/. It is large, so
it is fetched once and sliced per resource on demand, then refetched once the
cached copy passes its TTL.
"""

from __future__ import annotations

import time
from typing import Any

from .client import request

#: How long a fetched schema is trusted. A stdio server is short-lived and would
#: not care, but an HTTP deployment outlives backend upgrades, and a stale schema
#: rejects filters the running backend now accepts.
SCHEMA_TTL_SECONDS = 300.0

_schema: dict[str, Any] | None = None
_schema_fetched_at = 0.0


async def get_schema() -> dict[str, Any]:
    global _schema, _schema_fetched_at
    # monotonic, so a clock adjustment cannot pin the cache as fresh forever.
    now = time.monotonic()
    if _schema is None or now - _schema_fetched_at >= SCHEMA_TTL_SECONDS:
        _schema = await request("GET", "/oa3/schema/", params={"format": "json"})
        _schema_fetched_at = now
    return _schema or {}


def _resolve(schema: dict[str, Any], node: Any, depth: int = 0) -> Any:
    """Follow a single $ref into components/schemas. Bounded, so recursion is safe."""
    if depth > 4 or not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if not ref or not ref.startswith("#/components/schemas/"):
        return node
    target = schema.get("components", {}).get("schemas", {}).get(ref.rsplit("/", 1)[-1], {})
    return _resolve(schema, target, depth + 1)


def _describe_parameter(param: dict[str, Any]) -> dict[str, Any]:
    param_schema = param.get("schema") or {}
    described: dict[str, Any] = {"name": param.get("name"), "in": param.get("in")}
    if param.get("required"):
        described["required"] = True
    if param_schema.get("type"):
        described["type"] = param_schema["type"]
    enum = param_schema.get("enum") or (param_schema.get("items") or {}).get("enum")
    if enum:
        described["enum"] = enum
    if param.get("description"):
        described["description"] = param["description"][:200]
    return described


def _body_fields(schema: dict[str, Any], operation: dict[str, Any]) -> dict[str, Any]:
    content = ((operation.get("requestBody") or {}).get("content")) or {}
    for media in ("application/json", "multipart/form-data", "application/x-www-form-urlencoded"):
        media_schema = (content.get(media) or {}).get("schema")
        if not media_schema:
            continue
        resolved = _resolve(schema, media_schema)
        if not isinstance(resolved, dict):
            continue
        required = set(resolved.get("required") or [])
        fields = {}
        for name, prop in (resolved.get("properties") or {}).items():
            prop = _resolve(schema, prop)
            entry: dict[str, Any] = {"type": prop.get("type", "any")}
            if prop.get("enum"):
                entry["enum"] = prop["enum"]
            if prop.get("readOnly"):
                entry["read_only"] = True
            if name in required:
                entry["required"] = True
            if prop.get("maxLength"):
                entry["max_length"] = prop["maxLength"]
            fields[name] = entry
        if fields:
            return fields
    return {}


def _response_fields(schema: dict[str, Any], operation: dict[str, Any]) -> list[str]:
    for status in ("200", "201"):
        media = (((operation.get("responses") or {}).get(status) or {}).get("content") or {}).get("application/json")
        if not media:
            continue
        resolved = _resolve(schema, media.get("schema") or {})
        if not isinstance(resolved, dict):
            continue
        # Paginated list responses wrap the rows under "results".
        results = (resolved.get("properties") or {}).get("results")
        if results:
            resolved = _resolve(schema, _resolve(schema, results).get("items") or {})
        if isinstance(resolved, dict) and resolved.get("properties"):
            return sorted(resolved["properties"].keys())
    return []


async def describe_path(path: str) -> dict[str, Any]:
    """Describe every operation on one API path from the live schema.

    Args:
        path: API path relative to /api, e.g. "/observations/".

    Returns:
        {"<METHOD>": {"summary": str, "parameters": [...], "body_fields": {...},
        "response_fields": [...]}} -- empty if the schema does not expose the path.
    """
    schema = await get_schema()
    wanted = f"/api{path}"
    paths = schema.get("paths") or {}
    raw = paths.get(wanted) or paths.get(path) or {}

    described: dict[str, Any] = {}
    for method, operation in raw.items():
        if method.lower() not in {"get", "post", "put", "patch", "delete"} or not isinstance(operation, dict):
            continue
        entry: dict[str, Any] = {}
        if operation.get("summary") or operation.get("description"):
            entry["summary"] = (operation.get("summary") or operation.get("description", ""))[:300]
        parameters = [_describe_parameter(p) for p in operation.get("parameters") or [] if isinstance(p, dict)]
        if parameters:
            entry["parameters"] = parameters
        body = _body_fields(schema, operation)
        if body:
            entry["body_fields"] = body
        if method.lower() == "get":
            response_fields = _response_fields(schema, operation)
            if response_fields:
                entry["response_fields"] = response_fields
        described[method.upper()] = entry
    return described


async def query_parameters(path: str) -> set[str]:
    """Names of the query parameters the instance accepts on GET <path>.

    Empty when the schema is unavailable, which callers must read as "cannot
    validate" rather than "nothing is allowed".
    """
    try:
        described = await describe_path(path)
    except Exception:  # noqa: BLE001 - validation is best-effort; the API stays the authority
        return set()
    get = described.get("GET") or {}
    return {p["name"] for p in get.get("parameters", []) if p.get("name")}

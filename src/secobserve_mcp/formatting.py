"""Field projection and response rendering.

SecObserve serializers return every model column, so projection is not a nicety:
an unprojected page of 25 observations is tens of thousands of tokens. Every
list tool projects by default and says which fields it dropped.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import Any


class ResponseFormat(str, Enum):
    """Output format for tool responses."""

    MARKDOWN = "markdown"
    JSON = "json"


MAX_VALUE_CHARS = 400


def pluck(obj: dict[str, Any], path: str) -> Any:
    """Read a possibly dotted path out of a nested dict (e.g. 'product_data.name')."""
    current: Any = obj
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def project(obj: dict[str, Any], fields: tuple[str, ...] | list[str] | None) -> dict[str, Any]:
    """Reduce one object to the requested fields, keeping the requested order."""
    if not fields:
        return obj
    return {path: pluck(obj, path) for path in fields}


def _truncate(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
        return f"{value[:MAX_VALUE_CHARS]}... [{len(value)} chars, fetch with secobserve_get for the full text]"
    return value


def _render_value(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def render_items(
    items: list[dict[str, Any]],
    *,
    title: str,
    label: str,
    envelope: dict[str, Any],
    response_format: ResponseFormat,
    dropped_note: str | None = None,
) -> str:
    """Render a projected list as markdown or JSON, including pagination metadata."""
    if response_format is ResponseFormat.JSON:
        return json.dumps({**envelope, "items": items}, indent=2, ensure_ascii=False, default=str)

    lines = [f"# {title}", ""]
    lines.append(
        f"{envelope.get('count', len(items))} of {envelope.get('total', '?')} "
        f"(page {envelope.get('page', 1)}, page_size {envelope.get('page_size', len(items))})"
    )
    if envelope.get("has_more"):
        lines.append(f"More results available: request page {envelope.get('next_page')}.")
    if dropped_note:
        lines.append(dropped_note)
    lines.append("")

    if not items:
        lines.append("_No matching records._")
        return "\n".join(lines)

    for item in items:
        headline = _render_value(item.get(label) or item.get("id"))
        identifier = item.get("id")
        lines.append(f"## {headline}" + (f"  (id {identifier})" if identifier is not None else ""))
        for key, value in item.items():
            if key in {label, "id"}:
                continue
            lines.append(f"- **{key}**: {_render_value(_truncate(value))}")
        lines.append("")

    return "\n".join(lines)


def render_object(
    obj: dict[str, Any],
    *,
    title: str,
    response_format: ResponseFormat,
) -> str:
    """Render one object as markdown or JSON."""
    if response_format is ResponseFormat.JSON:
        return json.dumps(obj, indent=2, ensure_ascii=False, default=str)

    lines = [f"# {title}", ""]
    for key, value in obj.items():
        lines.append(f"- **{key}**: {_render_value(_truncate(value))}")
    return "\n".join(lines)


def paging_envelope(payload: dict[str, Any], page: int, page_size: int, count: int) -> dict[str, Any]:
    """Build the pagination metadata block from a DRF page response."""
    total = payload.get("count")
    has_more = bool(payload.get("next"))
    return {
        "total": total,
        "count": count,
        "page": page,
        "page_size": page_size,
        "has_more": has_more,
        "next_page": page + 1 if has_more else None,
    }

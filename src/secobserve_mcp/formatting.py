"""Field projection and response rendering.

SecObserve serializers return every model column, so projection is not a nicety:
an unprojected page of 25 observations is tens of thousands of tokens. Every
list tool projects by default and says which fields it dropped.

Projection bounds how wide a row is, never how many rows a caller asks for, so
rendering also stops at a character budget and reports what it cut.
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

#: Character budget for the rows of one list result, in both formats.
#: Clients cap a tool result in tokens, and rows of ids and ISO timestamps run near two characters per token, so this is around 12k tokens -- half of a real 52,082-character result that a client refused.
MAX_RESULT_CHARS = 25_000


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


def _markdown_item(item: dict[str, Any], label: str) -> str:
    headline = _render_value(item.get(label) or item.get("id"))
    identifier = item.get("id")
    lines = [f"## {headline}" + (f"  (id {identifier})" if identifier is not None else "")]
    for key, value in item.items():
        if key in {label, "id"}:
            continue
        lines.append(f"- **{key}**: {_render_value(_truncate(value))}")
    lines.append("")
    return "\n".join(lines)


def _row_blocks(items: list[dict[str, Any]], label: str, response_format: ResponseFormat) -> list[str]:
    """Render every row on its own, so a row can be measured at what it costs in the result."""
    if response_format is ResponseFormat.MARKDOWN:
        return [_markdown_item(item, label) for item in items]
    return [json.dumps(item, indent=2, ensure_ascii=False, default=str) for item in items]


def _fit_to_budget(blocks: list[str], nesting: int) -> int:
    """How many leading rows stay inside MAX_RESULT_CHARS, never fewer than one."""
    used = 0
    for index, block in enumerate(blocks):
        used += len(block) + nesting * block.count("\n")
        if used > MAX_RESULT_CHARS:
            return max(index, 1)
    return len(blocks)


def _largest_divisor(value: int, limit: int) -> int:
    return next(size for size in range(min(limit, value), 0, -1) if value % size == 0)


def _aligned_window(start: int, fits: int) -> tuple[int, int, int]:
    """Rows to return, then the page and page_size whose window begins exactly at the first row cut.

    Page numbering only reaches offsets that are a multiple of some page_size, so the cut is aligned either by
    returning every row that fits, or by returning a few fewer -- whichever leaves the larger page_size to continue
    with, since a page_size of 1 is exact and useless.
    """
    windows = [(_largest_divisor(start + fits, fits), fits)]
    if start:
        divisor = _largest_divisor(start, fits)
        windows.append((divisor, divisor))
    page_size, rows = max(windows)
    return rows, (start + rows) // page_size + 1, page_size


def _trim_envelope(envelope: dict[str, Any], *, fetched: int, fits: int) -> tuple[dict[str, Any], int, str]:
    page, page_size = envelope.get("page"), envelope.get("page_size")
    if isinstance(page, int) and isinstance(page_size, int):
        kept, next_page, next_page_size = _aligned_window((page - 1) * page_size, fits)
        follow = (
            f"The {fetched - kept} rows cut here begin page {next_page} at page_size {next_page_size}: "
            f"ask for exactly that pair, because page {page + 1} at page_size {page_size} would skip them."
        )
    else:
        kept, next_page, next_page_size = fits, None, None
        follow = f"This result is not paginated, so the {fetched - kept} rows cut here are reachable only by narrowing the request."
    note = (
        f"Trimmed to {kept} of {fetched} fetched rows by the {MAX_RESULT_CHARS}-character result budget. {follow} "
        "A narrower filter or a shorter fields list fits more rows per call."
    )
    trimmed = {
        **envelope,
        "count": kept,
        "has_more": True,
        "next_page": next_page,
        "next_page_size": next_page_size,
        "trimmed": {"fetched": fetched, "returned": kept, "budget_chars": MAX_RESULT_CHARS, "note": note},
    }
    return trimmed, kept, note


def render_items(
    items: list[dict[str, Any]],
    *,
    title: str,
    label: str,
    envelope: dict[str, Any],
    response_format: ResponseFormat,
    dropped_note: str | None = None,
) -> str:
    """Render a projected list as markdown or JSON, including pagination metadata.

    Rows past MAX_RESULT_CHARS are cut instead of being handed to a client that cannot accept the result.
    A cut is never silent: the envelope carries a `trimmed` block, and `next_page` / `next_page_size` move to the first row that was cut, so paging still reaches every record.
    """
    blocks = _row_blocks(items, label, response_format)
    fits = _fit_to_budget(blocks, nesting=0 if response_format is ResponseFormat.MARKDOWN else 4)
    trim_note: str | None = None
    if fits < len(items):
        envelope, kept, trim_note = _trim_envelope(envelope, fetched=len(items), fits=fits)
        items, blocks = items[:kept], blocks[:kept]

    if response_format is ResponseFormat.JSON:
        return json.dumps({**envelope, "items": items}, indent=2, ensure_ascii=False, default=str)

    lines = [f"# {title}", ""]
    lines.append(
        f"{envelope.get('count', len(items))} of {envelope.get('total', '?')} "
        f"(page {envelope.get('page', 1)}, page_size {envelope.get('page_size', len(items))})"
    )
    if envelope.get("has_more") and envelope.get("next_page"):
        next_page_size = envelope.get("next_page_size")
        with_page_size = f" with page_size {next_page_size}" if next_page_size else ""
        lines.append(f"More results available: request page {envelope.get('next_page')}{with_page_size}.")
    if trim_note:
        lines.append(trim_note)
    if dropped_note:
        lines.append(dropped_note)
    lines.append("")

    if not items:
        lines.append("_No matching records._")
        return "\n".join(lines)

    lines.extend(blocks)
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
        "next_page_size": page_size if has_more else None,
    }

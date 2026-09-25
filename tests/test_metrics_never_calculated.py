"""An instance whose metrics job never ran reports a fresh timestamp, so the counts have to be judged another way."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import respx

from secobserve_mcp.app import mcp

API = "http://secobserve.test/api"
ZEROS = {"active_critical": 0, "active_high": 0, "open": 0, "risk_accepted": 0}
# Computed, not literal: a fixed "now" turns stale days later and silently tests the other branch.
JUST_NOW = {"last_calculated": datetime.now(UTC).isoformat(), "calculation_interval": 5}


def _mock_current_and_status(timeline: dict[str, object]) -> respx.Route:
    respx.get(f"{API}/metrics/product_metrics_current/").mock(return_value=httpx.Response(200, json=ZEROS))
    respx.get(f"{API}/metrics/product_metrics_status/").mock(return_value=httpx.Response(200, json=JUST_NOW))
    return respx.get(f"{API}/metrics/product_metrics_timeline/").mock(return_value=httpx.Response(200, json=timeline))


async def _current() -> dict[str, object]:
    result = await mcp.call_tool("secobserve_product_metrics", {"kind": "current"})
    return dict(json.loads(result.content[0].text))


@respx.mock
async def test_an_empty_timeline_means_the_job_never_ran() -> None:
    """`last_calculated` says now because reading the singleton is what created it, not because anything ran."""
    timeline = _mock_current_and_status({})

    payload = await _current()

    assert timeline.called
    assert "never run on this instance" in str(payload["stale"]["warning"])  # type: ignore[index]
    assert payload["stale"]["last_calculated"] is None  # type: ignore[index]


@respx.mock
async def test_zeros_on_an_instance_that_has_calculated_are_left_alone() -> None:
    """A backend with nothing to count is entitled to report zeros, and the timeline is what says so."""
    _mock_current_and_status({"2026-09-21": ZEROS})

    payload = await _current()

    assert "stale" not in payload


@respx.mock
async def test_a_count_that_is_not_zero_never_costs_the_extra_call() -> None:
    """The timeline read only pays for itself on the ambiguous payload, so the common case is unchanged."""
    respx.get(f"{API}/metrics/product_metrics_current/").mock(
        return_value=httpx.Response(200, json={**ZEROS, "active_critical": 1})
    )
    respx.get(f"{API}/metrics/product_metrics_status/").mock(return_value=httpx.Response(200, json=JUST_NOW))
    timeline = respx.get(f"{API}/metrics/product_metrics_timeline/").mock(return_value=httpx.Response(200, json={}))

    payload = await _current()

    assert not timeline.called
    assert "stale" not in payload


@respx.mock
async def test_a_job_that_died_is_still_reported_as_stale_not_as_never_run() -> None:
    """The two failures need different fixes, so the warning has to name the right one."""
    respx.get(f"{API}/metrics/product_metrics_current/").mock(return_value=httpx.Response(200, json=ZEROS))
    respx.get(f"{API}/metrics/product_metrics_status/").mock(
        return_value=httpx.Response(
            200, json={"last_calculated": "2020-01-01T00:00:00+00:00", "calculation_interval": 5}
        )
    )
    timeline = respx.get(f"{API}/metrics/product_metrics_timeline/").mock(
        return_value=httpx.Response(200, json={"2020-01-01": ZEROS})
    )

    payload = await _current()

    assert not timeline.called
    assert "last ran" in str(payload["stale"]["warning"])  # type: ignore[index]

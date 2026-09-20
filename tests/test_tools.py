"""Tool-level behaviour: projection, guards, and the payload rules the API enforces."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from mcp.server.mcpserver.exceptions import ToolError

from secobserve_mcp import config
from secobserve_mcp.app import mcp
from secobserve_mcp.formatting import ResponseFormat, _aligned_window
from secobserve_mcp.tools_crud import (
    secobserve_call_action,
    secobserve_delete,
    secobserve_list,
    secobserve_list_resources,
)
from secobserve_mcp.tools_workflows import (
    _elapsed_since,
    secobserve_upload_file,
)

from .conftest import BASE_URL

API = f"{BASE_URL}/api"


async def call(name: str, **arguments: object) -> str:
    """Go through the protocol, so argument coercion and schema validation are exercised too."""
    result = await mcp.call_tool(name, arguments)
    return str(result.content[0].text)


FAT_OBSERVATION = {
    "id": 8123,
    "title": "CVE-2024-3094 in xz-utils",
    "current_severity": "Critical",
    "current_status": "Open",
    "current_priority": None,
    "product_data": {"id": 12, "name": "Portal", "product_group_name": "Platform"},
    "branch_name": "main",
    "vulnerability_id": "CVE-2024-3094",
    "origin_component_name_version": "xz-utils:5.6.0",
    "scanner_name": "Trivy",
    "epss_score": 91.2,
    "fix_available": True,
    "has_potential_duplicates": False,
    "last_observation_log": "2026-09-10T08:00:00Z",
    # Columns the default projection must drop.
    "description": "x" * 5000,
    "recommendation": "y" * 3000,
    "origin_component_dependencies": "z" * 2000,
    "parser_severity": "Critical",
    "rule_severity": "",
}


@respx.mock
async def test_list_projects_away_the_bulk_of_each_row() -> None:
    respx.get(f"{API}/observations/").mock(
        return_value=httpx.Response(200, json={"count": 1, "next": None, "results": [FAT_OBSERVATION]})
    )

    result = await secobserve_list(resource="observations", response_format=ResponseFormat.JSON)
    payload = json.loads(result)

    assert payload["items"][0]["product_data.name"] == "Portal"
    assert "description" not in payload["items"][0]
    assert len(result) < 1500, "projection must keep a row far below its raw size"


@respx.mock
async def test_list_star_fields_returns_everything() -> None:
    respx.get(f"{API}/observations/").mock(
        return_value=httpx.Response(200, json={"count": 1, "next": None, "results": [FAT_OBSERVATION]})
    )

    payload = json.loads(
        await secobserve_list(resource="observations", fields=["*"], response_format=ResponseFormat.JSON)
    )

    assert "description" in payload["items"][0]


@respx.mock
async def test_list_reports_pagination_so_the_agent_can_continue() -> None:
    respx.get(f"{API}/observations/").mock(
        return_value=httpx.Response(
            200, json={"count": 120, "next": f"{API}/observations/?page=3", "results": [FAT_OBSERVATION]}
        )
    )

    payload = json.loads(
        await secobserve_list(resource="observations", page=2, page_size=50, response_format=ResponseFormat.JSON)
    )

    assert payload["total"] == 120
    assert payload["has_more"] is True
    assert payload["next_page"] == 3


@respx.mock
async def test_markdown_truncates_long_values_and_says_so() -> None:
    respx.get(f"{API}/observations/").mock(
        return_value=httpx.Response(200, json={"count": 1, "next": None, "results": [FAT_OBSERVATION]})
    )

    result = await secobserve_list(resource="observations", fields=["id", "description"])

    assert "secobserve_get for the full text" in result
    assert len(result) < 1500


#: The shape that overflowed a client: observation_logs, 11 fields, ~500 characters per row.
LOG_FIELDS = [
    "id",
    "observation",
    "user_full_name",
    "severity",
    "status",
    "priority",
    "assessment_status",
    "comment",
    "created",
    "observation_data.origin_component_name_version",
    "product_data.name",
]


def log_row(index: int) -> dict[str, object]:
    return {
        "id": 9000 + index,
        "observation": 8000 + index,
        "user_full_name": "Nguyen Thanh Truong",
        "severity": "Critical",
        "status": "Risk accepted",
        "priority": None,
        "assessment_status": "Approved",
        "comment": "Accepted for release 2026.09, tracked in PORTAL-1421",
        "created": "2026-09-20T14:41:35.851824+02:00",
        "observation_data": {"origin_component_name_version": "org.apache.logging.log4j:log4j-core:2.17.1"},
        "product_data": {"name": "Portal"},
        "description": "x" * 400,
    }


LOG_DATASET = [log_row(index) for index in range(250)]


def serve_logs(request: httpx.Request) -> httpx.Response:
    """A DRF page of LOG_DATASET, so page and page_size mean what the backend makes them mean."""
    page = int(request.url.params.get("page", 1))
    page_size = int(request.url.params.get("page_size", 25))
    start = (page - 1) * page_size
    rows = LOG_DATASET[start : start + page_size]
    has_next = start + page_size < len(LOG_DATASET)
    return httpx.Response(
        200,
        json={
            "count": len(LOG_DATASET),
            "next": f"{API}/observation_logs/?page={page + 1}" if has_next else None,
            "results": rows,
        },
    )


async def list_logs(**arguments: object) -> dict[str, Any]:
    return json.loads(
        await secobserve_list(
            resource="observation_logs", fields=LOG_FIELDS, response_format=ResponseFormat.JSON, **arguments
        )
    )


@respx.mock
async def test_a_page_inside_the_budget_is_returned_whole() -> None:
    respx.get(f"{API}/observation_logs/").mock(side_effect=serve_logs)

    payload = await list_logs(page=1, page_size=25)

    assert "trimmed" not in payload
    assert payload["count"] == 25
    assert payload["next_page"] == 2
    assert payload["next_page_size"] == 25


@respx.mock
async def test_a_page_over_the_budget_is_cut_and_the_envelope_says_so() -> None:
    respx.get(f"{API}/observation_logs/").mock(side_effect=serve_logs)

    payload = await list_logs(page=1, page_size=100)

    assert payload["trimmed"]["fetched"] == 100
    assert payload["trimmed"]["returned"] == len(payload["items"]) < 100
    assert payload["count"] == len(payload["items"])
    assert payload["has_more"] is True
    assert "page_size" in payload["trimmed"]["note"]


@respx.mock
async def test_the_cut_result_fits_where_the_untrimmed_one_did_not() -> None:
    respx.get(f"{API}/observation_logs/").mock(side_effect=serve_logs)

    result = await secobserve_list(
        resource="observation_logs", page=1, page_size=100, fields=LOG_FIELDS, response_format=ResponseFormat.JSON
    )

    assert len(result) < 27_000, "the incident returned 52,082 characters for this exact call"


@respx.mock
async def test_markdown_is_cut_by_the_same_budget() -> None:
    respx.get(f"{API}/observation_logs/").mock(side_effect=serve_logs)

    result = await secobserve_list(resource="observation_logs", page=1, page_size=100, fields=LOG_FIELDS)

    assert "Trimmed to" in result
    assert result.count("\n## ") < 100
    assert len(result) < 27_000


@respx.mock
async def test_paging_by_what_the_result_says_reaches_every_record() -> None:
    respx.get(f"{API}/observation_logs/").mock(side_effect=serve_logs)

    seen: list[int] = []
    page, page_size = 1, 100
    for _ in range(50):
        payload = await list_logs(page=page, page_size=page_size)
        seen.extend(int(item["id"]) for item in payload["items"])
        if not payload["has_more"]:
            break
        page, page_size = payload["next_page"], payload["next_page_size"]
    else:  # pragma: no cover - only reached if paging stops converging
        pytest.fail("paging did not terminate")

    assert seen == [row["id"] for row in LOG_DATASET], "every record exactly once, in order"


@respx.mock
async def test_a_cut_on_a_later_page_points_at_the_first_record_it_dropped() -> None:
    respx.get(f"{API}/observation_logs/").mock(side_effect=serve_logs)

    payload = await list_logs(page=2, page_size=100)
    kept = payload["trimmed"]["returned"]

    assert (payload["next_page"] - 1) * payload["next_page_size"] == 100 + kept

    follow_up = await list_logs(page=payload["next_page"], page_size=payload["next_page_size"])

    assert follow_up["items"][0]["id"] == LOG_DATASET[100 + kept]["id"]


def test_every_aligned_window_starts_exactly_where_the_cut_did() -> None:
    for start in range(401):
        for fits in (1, 2, 3, 7, 13, 37, 50, 51, 97, 100):
            rows, page, page_size = _aligned_window(start, fits)

            assert 1 <= rows <= fits
            assert (page - 1) * page_size == start + rows, "the next page must begin at the first row cut"


@respx.mock
async def test_the_trim_is_visible_over_the_protocol() -> None:
    respx.get(f"{API}/observation_logs/").mock(side_effect=serve_logs)

    result = await call("secobserve_list", resource="observation_logs", page_size=100, fields=LOG_FIELDS)

    assert "Trimmed to" in result
    assert "would skip them" in result


@respx.mock
async def test_an_unpaginated_action_list_is_cut_and_says_it_cannot_be_paged() -> None:
    respx.get(f"{API}/observation_logs/count_approvals/").mock(
        return_value=httpx.Response(200, json=[log_row(index) for index in range(200)])
    )

    payload = json.loads(
        await secobserve_call_action(
            resource="observation_logs", action="count_approvals", response_format=ResponseFormat.JSON
        )
    )

    assert payload["trimmed"]["returned"] < 200
    assert payload["next_page"] is None
    assert "not paginated" in payload["trimmed"]["note"]


async def test_unknown_resource_names_close_matches() -> None:
    result = await secobserve_list(resource="observation")

    assert result.startswith("Error:")
    assert "secobserve_list_resources" in result


async def test_unsupported_operation_lists_what_is_supported() -> None:
    result = await secobserve_list(resource="settings")

    assert "does not support 'list'" in result
    assert "get, update" in result


async def test_catalogue_covers_every_resource_and_its_actions() -> None:
    catalogue = await secobserve_list_resources()

    assert "## observations" in catalogue
    assert "action `assessment`" in catalogue
    assert "action `apply_rules`: POST, detail (needs id)" in catalogue


async def test_delete_is_off_until_explicitly_enabled() -> None:
    result = await secobserve_delete(resource="license_policy_items", id=1)

    assert "SECOBSERVE_ALLOW_DELETE" in result


async def test_product_delete_demands_the_exact_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.ENV_ALLOW_DELETE, "true")
    config.get_config.cache_clear()

    result = await secobserve_delete(resource="products", id=12)

    assert "confirm_name" in result


@respx.mock
async def test_product_delete_passes_the_name_through(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.ENV_ALLOW_DELETE, "true")
    config.get_config.cache_clear()
    route = respx.delete(f"{API}/products/12/").mock(return_value=httpx.Response(204))

    await secobserve_delete(resource="products", id=12, confirm_name="Portal")

    assert route.calls.last.request.url.params["name"] == "Portal"


async def test_action_must_exist_on_the_resource() -> None:
    result = await secobserve_call_action(resource="products", action="nope", id=1)

    assert "has no action 'nope'" in result
    assert "apply_rules" in result, "the error must list the actions that do exist"


async def test_detail_action_requires_an_id() -> None:
    result = await secobserve_call_action(resource="products", action="apply_rules")

    assert "works on one record" in result


async def test_collection_action_rejects_an_id() -> None:
    result = await secobserve_call_action(resource="observations", action="count_reviews", id=1)

    assert "works on the collection" in result


@respx.mock
async def test_binary_action_is_written_to_the_export_directory() -> None:
    respx.get(f"{API}/products/12/export_observations_excel/").mock(
        return_value=httpx.Response(200, content=b"PK\x03\x04excel-bytes")
    )

    result = await secobserve_call_action(resource="products", action="export_observations_excel", id=12)

    written = Path(config.get_config().export_dir) / "products-export_observations_excel-12.xlsx"
    assert written.exists()
    assert str(written) in result


@respx.mock
async def test_metrics_export_is_written_to_the_export_directory() -> None:
    respx.get(f"{API}/metrics/export_excel/").mock(return_value=httpx.Response(200, content=b"PK\x03\x04metrics"))

    result = await secobserve_call_action(resource="metrics", action="export_excel")

    written = Path(config.get_config().export_dir) / "metrics-export_excel.xlsx"
    assert written.exists()
    assert str(written) in result


async def test_listing_an_actions_only_resource_points_at_the_tool_that_reads_it() -> None:
    result = await secobserve_list(resource="metrics")

    assert "no CRUD operations" in result
    assert "secobserve_product_metrics" in result
    assert "export_codecharta" in result


@respx.mock
async def test_export_filename_cannot_escape_the_export_directory() -> None:
    respx.get(f"{API}/products/12/export_observations_csv/").mock(return_value=httpx.Response(200, content=b"a,b"))

    await secobserve_call_action(resource="products", action="export_observations_csv", id=12, filename="../../escaped")

    export_dir = Path(config.get_config().export_dir)
    assert [p.name for p in export_dir.iterdir()] == ["escaped.csv"]


@respx.mock
async def test_assessment_sends_only_the_fields_that_changed() -> None:
    route = respx.patch(f"{API}/observations/8123/assessment/").mock(return_value=httpx.Response(200))

    await call(
        "secobserve_assess_observation",
        observation_id=8123,
        status="Not affected",
        vex_justification="vulnerable_code_not_in_execute_path",
        comment="The parser is never reached from our entry points.",
    )

    body = json.loads(route.calls.last.request.content)
    assert body == {
        "comment": "The parser is never reached from our entry points.",
        "status": "Not affected",
        "vex_justification": "vulnerable_code_not_in_execute_path",
    }
    assert "severity" not in body, "an omitted field must not be sent as null"


@respx.mock
async def test_clear_priority_sends_an_explicit_null() -> None:
    route = respx.patch(f"{API}/observations/8123/assessment/").mock(return_value=httpx.Response(200))

    await call("secobserve_assess_observation", observation_id=8123, clear_priority=True, comment="No longer applies.")

    assert json.loads(route.calls.last.request.content)["priority"] is None


async def test_assessment_without_a_comment_is_refused_by_the_schema() -> None:
    with pytest.raises(ToolError, match="comment"):
        await call("secobserve_assess_observation", observation_id=1, status="Resolved")


async def test_assessment_that_changes_nothing_is_refused() -> None:
    assert "at least one of severity" in await call(
        "secobserve_assess_observation", observation_id=1, comment="just a note"
    )


async def test_invalid_status_is_refused_before_any_request() -> None:
    with pytest.raises(ToolError):
        await call("secobserve_assess_observation", observation_id=1, status="Mitigated", comment="c")


@respx.mock
async def test_bulk_assessment_uses_the_product_endpoint_when_scoped() -> None:
    route = respx.post(f"{API}/products/12/observations_bulk_assessment/").mock(return_value=httpx.Response(204))

    await call(
        "secobserve_bulk_assess_observations",
        observation_ids=[1, 2, 3],
        product_id=12,
        status="Resolved",
        comment="Branch decommissioned.",
    )

    assert json.loads(route.calls.last.request.content)["observations"] == [1, 2, 3]


async def test_bulk_assessment_is_capped_at_the_api_limit() -> None:
    with pytest.raises(ToolError):
        await call(
            "secobserve_bulk_assess_observations",
            observation_ids=list(range(1, 252)),
            status="Resolved",
            comment="c",
        )


async def test_rejection_requires_a_remark() -> None:
    assert "rejection_remark" in await call(
        "secobserve_approve_observation_log", observation_log_ids=[1], assessment_status="Rejected"
    )


@respx.mock
async def test_single_approval_uses_the_detail_endpoint() -> None:
    route = respx.patch(f"{API}/observation_logs/991/approval/").mock(return_value=httpx.Response(200))

    await call("secobserve_approve_observation_log", observation_log_ids=[991], assessment_status="Approved")

    assert json.loads(route.calls.last.request.content) == {"assessment_status": "Approved"}


@respx.mock
async def test_several_approvals_use_the_bulk_endpoint() -> None:
    route = respx.post(f"{API}/observation_logs/bulk_approval/").mock(return_value=httpx.Response(204))

    await call(
        "secobserve_approve_observation_log",
        observation_log_ids=[991, 992],
        assessment_status="Rejected",
        rejection_remark="Evidence missing.",
    )

    body = json.loads(route.calls.last.request.content)
    assert body["observation_logs"] == [991, 992]
    assert body["rejection_remark"] == "Evidence missing."


CURRENT_METRICS = {"active_critical": 0, "active_high": 0, "open": 0, "risk_accepted": 0}


def metrics_status_route(last_calculated: datetime | None, interval: object = 60) -> respx.Route:
    return respx.get(f"{API}/metrics/product_metrics_status/").mock(
        return_value=httpx.Response(
            200,
            json={
                "last_calculated": last_calculated.isoformat() if last_calculated else None,
                "calculation_interval": interval,
            },
        )
    )


def product_lookup_routes(product_id: int, *, is_group: bool = False) -> tuple[respx.Route, respx.Route]:
    """product_names holds products only, so a product group answers 404 there and 200 on product_group_names."""
    missing = httpx.Response(404, json={"detail": "Not found."})
    found = httpx.Response(200, json={"id": product_id, "name": "Portal"})
    return (
        respx.get(f"{API}/product_names/{product_id}/").mock(return_value=missing if is_group else found),
        respx.get(f"{API}/product_group_names/{product_id}/").mock(return_value=found if is_group else missing),
    )


@respx.mock
async def test_current_metrics_calculated_recently_carry_no_stale_block() -> None:
    respx.get(f"{API}/metrics/product_metrics_current/").mock(return_value=httpx.Response(200, json=CURRENT_METRICS))
    status = metrics_status_route(datetime.now(UTC).astimezone())

    payload = json.loads(await call("secobserve_product_metrics", kind="current"))

    assert "stale" not in payload
    assert status.call_count == 1


@respx.mock
async def test_current_metrics_are_flagged_when_the_job_stopped_hours_ago() -> None:
    """The endpoint answers 200 with fifteen zeros when the backend's day has no rows, so only the status call catches it."""
    respx.get(f"{API}/metrics/product_metrics_current/").mock(return_value=httpx.Response(200, json=CURRENT_METRICS))
    product, group = product_lookup_routes(12)
    stopped = datetime.now(UTC).astimezone() - timedelta(hours=19)
    metrics_status_route(stopped)

    payload = json.loads(await call("secobserve_product_metrics", kind="current", product_id=12))

    assert payload["stale"]["last_calculated"] == stopped.isoformat()
    assert "19h 0m ago" in payload["stale"]["warning"]
    assert "not a measurement" in payload["stale"]["warning"]
    assert {k: v for k, v in payload.items() if k != "stale"} == CURRENT_METRICS
    assert (product.call_count, group.call_count) == (1, 0)


@pytest.mark.parametrize(
    ("minutes_ago", "interval", "stale"),
    [
        (10, 5, False),  # inside the floor that absorbs a run outlasting its own interval
        (45, 5, True),
        (120, 60, False),  # two of three hourly intervals
        (200, 60, True),
        (45, 0, True),  # unusable interval falls back to the backend's default of 5
        (45, None, True),
        (240, 100000, True),  # capped at an hour, so a broken schedule cannot widen the guard to days
        (19 * 60, 5, True),  # the window the old calendar-date guard missed while the host ran ahead of the backend
    ],
)
@respx.mock
async def test_staleness_is_measured_in_elapsed_time_not_calendar_days(
    minutes_ago: int, interval: object, stale: bool
) -> None:
    respx.get(f"{API}/metrics/product_metrics_current/").mock(return_value=httpx.Response(200, json=CURRENT_METRICS))
    metrics_status_route(datetime.now(UTC).astimezone() - timedelta(minutes=minutes_ago), interval)

    payload = json.loads(await call("secobserve_product_metrics", kind="current"))

    assert ("stale" in payload) is stale


@respx.mock
async def test_a_last_calculation_that_cannot_be_read_is_stale() -> None:
    respx.get(f"{API}/metrics/product_metrics_current/").mock(return_value=httpx.Response(200, json=CURRENT_METRICS))
    metrics_status_route(None)

    assert "never" in json.loads(await call("secobserve_product_metrics", kind="current"))["stale"]["warning"]

    respx.get(f"{API}/metrics/product_metrics_status/").mock(
        return_value=httpx.Response(200, json={"last_calculated": "yesterday", "calculation_interval": 5})
    )

    payload = json.loads(await call("secobserve_product_metrics", kind="current"))
    assert "could not parse" in payload["stale"]["warning"]


def test_a_timestamp_with_a_trailing_z_and_microseconds_is_readable() -> None:
    assert _elapsed_since("2026-09-20T16:20:17.881966Z") is not None


@respx.mock
async def test_an_unknown_product_id_is_refused_instead_of_answering_for_the_instance() -> None:
    """The metrics endpoints read an unknown id as "no product" and return the whole estate's numbers with HTTP 200."""
    respx.get(f"{API}/product_names/99999999/").mock(return_value=httpx.Response(404, json={"detail": "Not found."}))
    respx.get(f"{API}/product_group_names/99999999/").mock(
        return_value=httpx.Response(404, json={"detail": "Not found."})
    )
    current = respx.get(f"{API}/metrics/product_metrics_current/").mock(
        return_value=httpx.Response(200, json=CURRENT_METRICS)
    )

    result = await call("secobserve_product_metrics", kind="current", product_id=99999999)

    assert "is not a product or a product group" in result
    assert "secobserve_list(resource='product_names'" in result
    assert current.call_count == 0


@respx.mock
async def test_a_product_group_id_is_accepted_through_the_second_lookup() -> None:
    product, group = product_lookup_routes(7, is_group=True)
    timeline = respx.get(f"{API}/metrics/product_metrics_timeline/").mock(
        return_value=httpx.Response(200, json={"2026-09-19": CURRENT_METRICS})
    )

    await call("secobserve_product_metrics", kind="timeline", product_id=7)

    assert (product.call_count, group.call_count) == (1, 1)
    assert timeline.calls.last.request.url.params["product_id"] == "7"


@respx.mock
async def test_timeline_and_status_ask_for_nothing_extra() -> None:
    timeline = respx.get(f"{API}/metrics/product_metrics_timeline/").mock(
        return_value=httpx.Response(200, json={"2026-09-19": CURRENT_METRICS})
    )
    status = metrics_status_route(datetime.now(UTC).astimezone() - timedelta(days=1))

    await call("secobserve_product_metrics", kind="timeline", age="Past 7 days")
    assert status.call_count == 0

    await call("secobserve_product_metrics", kind="status")
    assert status.call_count == 1
    assert timeline.call_count == 1


def day(offset: int) -> str:
    """An ISO date `offset` days back, so the expected window does not depend on when the test runs."""
    return (datetime.now(UTC).astimezone().date() - timedelta(days=offset)).isoformat()


DELTA_TIMELINE = {
    day(10): {"active_critical": 4, "open": 20},
    day(5): {"active_critical": 6, "open": 18},
    day(1): {"active_critical": 2, "open": 11, "risk_accepted": 3},
}


@respx.mock
async def test_delta_reports_the_dates_it_actually_used() -> None:
    route = respx.get(f"{API}/metrics/product_metrics_timeline/").mock(
        return_value=httpx.Response(200, json=DELTA_TIMELINE)
    )

    payload = json.loads(await call("secobserve_product_metrics", kind="delta", since=day(8)))

    assert payload["since"] == {"requested": day(8), "used": day(10)}
    assert payload["until"] == {"requested": day(0), "used": day(1)}
    assert payload["delta"] == {"active_critical": -2, "open": -9, "risk_accepted": 3}
    assert payload["missing_days"] == 7
    assert route.calls.last.request.url.params["age"] == "Past 30 days"
    assert route.call_count == 1


@respx.mock
async def test_delta_refuses_a_since_the_instance_no_longer_retains() -> None:
    respx.get(f"{API}/metrics/product_metrics_timeline/").mock(return_value=httpx.Response(200, json=DELTA_TIMELINE))

    result = await call("secobserve_product_metrics", kind="delta", since=day(400), until=day(2))

    assert f"the earliest date with metrics is {day(10)}" in result


async def test_delta_refuses_a_range_that_runs_backwards() -> None:
    result = await call("secobserve_product_metrics", kind="delta", since="2026-08-31", until="2026-08-01")

    assert "is after until=2026-08-01" in result


async def test_delta_needs_a_since() -> None:
    assert "needs since=" in await call("secobserve_product_metrics", kind="delta")


async def test_a_date_range_is_refused_on_the_other_kinds() -> None:
    result = await call("secobserve_product_metrics", kind="timeline", since="2026-08-01")

    assert "belong to kind='delta'" in result


async def test_upload_refuses_a_path_outside_the_import_directory(tmp_path: Path) -> None:
    outside = tmp_path / "secret.json"
    outside.write_text("{}")

    result = await secobserve_upload_file(kind="observations", file_path=str(outside), product_id=12)

    assert "uploads are confined to" in result
    assert "SECOBSERVE_IMPORT_DIR" in result


async def test_upload_refuses_an_empty_report() -> None:
    empty = Path(config.get_config().import_dir) / "empty.json"
    empty.write_text("")

    result = await secobserve_upload_file(kind="observations", file_path="empty.json", product_id=12)

    assert "is empty" in result


@respx.mock
async def test_upload_by_name_uses_the_by_name_endpoint() -> None:
    report = Path(config.get_config().import_dir) / "trivy.json"
    report.write_text('{"Results": []}')
    route = respx.post(f"{API}/import/file_upload_observations_by_name/").mock(
        return_value=httpx.Response(
            200,
            json={"observations_new": 4, "observations_updated": 1, "observations_resolved": 0},
        )
    )

    result = await secobserve_upload_file(
        kind="observations", file_path="trivy.json", product_name="Portal", branch_name="release-2.1"
    )

    assert b'name="product_name"' in route.calls.last.request.content
    assert "observations new: 4" in result


async def test_upload_requires_exactly_one_product_reference() -> None:
    assert "exactly one of product_id or product_name" in await call(
        "secobserve_upload_file", kind="observations", file_path="x.json", product_id=1, product_name="Portal"
    )


async def test_upload_rejects_mismatched_product_and_branch_reference() -> None:
    assert "branch_name goes with product_name" in await call(
        "secobserve_upload_file", kind="observations", file_path="x.json", product_id=1, branch_name="main"
    )


async def test_writes_are_blocked_in_read_only_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(config.ENV_READ_ONLY, "true")
    config.get_config.cache_clear()

    result = await call("secobserve_assess_observation", observation_id=1, status="Resolved", comment="c")

    assert "read-only mode" in result

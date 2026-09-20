"""Tool-level behaviour: projection, guards, and the payload rules the API enforces."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import respx
from mcp.server.mcpserver.exceptions import ToolError

from secobserve_mcp import config
from secobserve_mcp.app import mcp
from secobserve_mcp.formatting import ResponseFormat
from secobserve_mcp.tools_crud import (
    secobserve_call_action,
    secobserve_delete,
    secobserve_list,
    secobserve_list_resources,
)
from secobserve_mcp.tools_workflows import (
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


def metrics_status_route(last_calculated: datetime) -> respx.Route:
    return respx.get(f"{API}/metrics/product_metrics_status/").mock(
        return_value=httpx.Response(
            200, json={"last_calculated": last_calculated.isoformat(), "calculation_interval": 60}
        )
    )


@respx.mock
async def test_current_metrics_calculated_today_carry_no_stale_block() -> None:
    respx.get(f"{API}/metrics/product_metrics_current/").mock(return_value=httpx.Response(200, json=CURRENT_METRICS))
    status = metrics_status_route(datetime.now(UTC).astimezone())

    payload = json.loads(await call("secobserve_product_metrics", kind="current"))

    assert "stale" not in payload
    assert status.call_count == 1


@respx.mock
async def test_current_metrics_are_flagged_when_the_job_has_not_run_today() -> None:
    """The endpoint answers 200 with fifteen zeros when today's rows are missing, so only the status call catches it."""
    respx.get(f"{API}/metrics/product_metrics_current/").mock(return_value=httpx.Response(200, json=CURRENT_METRICS))
    yesterday = datetime.now(UTC).astimezone() - timedelta(days=1)
    metrics_status_route(yesterday)

    payload = json.loads(await call("secobserve_product_metrics", kind="current", product_id=12))

    assert payload["stale"]["last_calculated"] == yesterday.isoformat()
    assert "not a measurement" in payload["stale"]["warning"]
    assert {k: v for k, v in payload.items() if k != "stale"} == CURRENT_METRICS


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

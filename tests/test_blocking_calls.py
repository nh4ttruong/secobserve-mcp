"""What a scan or an API import answers when it outlasts the HTTP timeout.

The backend runs both inside the request, so a timeout leaves the work in flight and a retry starts a second
run. These pin the alternative: the counts on success, and on a timeout the vulnerability_checks row that the
work writes when it lands, anchored to that row's last_import from before the call.
"""

from __future__ import annotations

import httpx
import respx

from secobserve_mcp.app import mcp
from secobserve_mcp.tools_workflows import secobserve_trigger_scan  # noqa: F401  registers the tools

from .conftest import BASE_URL

API = f"{BASE_URL}/api"

COUNTS = {"observations_new": 3, "observations_updated": 1, "observations_resolved": 0}
CHECK_ROW = {
    "id": 77,
    "product": 12,
    "branch": 4,
    "scanner": "OSV (Open Source Vulnerabilities)",
    "api_configuration_name": "",
    "last_import": "2026-09-20T07:00:00Z",
}


async def call(name: str, **arguments: object) -> str:
    """Go through the protocol, so the timeout path is exercised the way a client reaches it."""
    result = await mcp.call_tool(name, arguments)
    return str(result.content[0].text)


def checks(*rows: dict[str, object]) -> httpx.Response:
    return httpx.Response(200, json={"count": len(rows), "next": None, "results": list(rows)})


TIMED_OUT = httpx.ReadTimeout("read timeout")


@respx.mock
async def test_scan_returns_counts_when_it_finishes() -> None:
    respx.get(f"{API}/vulnerability_checks/").mock(return_value=checks(CHECK_ROW))
    respx.post(f"{API}/products/12/scan_osv/").mock(return_value=httpx.Response(200, json=COUNTS))

    result = await call("secobserve_trigger_scan", scanner="osv", product_id=12)

    assert "observations new: 3" in result
    assert "Still running" not in result


@respx.mock
async def test_scan_baseline_query_targets_this_product_and_scanner() -> None:
    baseline = respx.get(f"{API}/vulnerability_checks/").mock(return_value=checks(CHECK_ROW))
    respx.post(f"{API}/products/12/4/scan_osv/").mock(return_value=httpx.Response(200, json=COUNTS))

    await call("secobserve_trigger_scan", scanner="osv", product_id=12, branch_id=4)

    params = baseline.calls[0].request.url.params
    assert params["product"] == "12"
    assert params["branch"] == "4"
    # icontains against the parser's own name, "OSV (Open Source Vulnerabilities)".
    assert params["scanner"] == "OSV"
    assert params["ordering"] == "-last_import"
    assert params["page_size"] == "1"


@respx.mock
async def test_scan_timeout_reports_work_in_flight_with_its_baseline() -> None:
    respx.get(f"{API}/vulnerability_checks/").mock(return_value=checks(CHECK_ROW))
    respx.post(f"{API}/products/12/scan_osv/").mock(side_effect=TIMED_OUT)

    result = await call("secobserve_trigger_scan", scanner="osv", product_id=12)

    assert result.startswith("Still running")
    assert "Do not call this tool again" in result
    assert "resource='vulnerability_checks'" in result
    assert "'product': 12" in result and "'scanner': 'OSV'" in result
    assert "last_import was 2026-09-20T07:00:00Z" in result
    assert "'last_import'" in result, "last_import is not in the default projection, so the query must ask for it"
    assert "no license components writes no row at all" in result


@respx.mock
async def test_scan_timeout_without_a_previous_row_says_the_first_row_is_this_run() -> None:
    respx.get(f"{API}/vulnerability_checks/").mock(return_value=checks())
    respx.post(f"{API}/products/12/scan_osv/").mock(side_effect=TIMED_OUT)

    result = await call("secobserve_trigger_scan", scanner="osv", product_id=12)

    assert "No such row existed before this call" in result


@respx.mock
async def test_scan_timeout_never_mistakes_an_unreadable_baseline_for_an_absent_row() -> None:
    respx.get(f"{API}/vulnerability_checks/").mock(return_value=httpx.Response(403, json={"detail": "forbidden"}))
    respx.post(f"{API}/products/12/scan_osv/").mock(side_effect=TIMED_OUT)

    result = await call("secobserve_trigger_scan", scanner="osv", product_id=12)

    assert "could not be read before this call" in result
    assert "No such row existed" not in result


@respx.mock
async def test_unreadable_baseline_does_not_stop_the_scan() -> None:
    respx.get(f"{API}/vulnerability_checks/").mock(return_value=httpx.Response(403, json={"detail": "forbidden"}))
    respx.post(f"{API}/products/12/scan_osv/").mock(return_value=httpx.Response(200, json=COUNTS))

    result = await call("secobserve_trigger_scan", scanner="osv", product_id=12)

    assert "observations new: 3" in result


@respx.mock
async def test_scan_rejection_is_still_reported_as_the_error_it_is() -> None:
    respx.get(f"{API}/vulnerability_checks/").mock(return_value=checks(CHECK_ROW))
    respx.post(f"{API}/products/12/scan_osv/").mock(
        return_value=httpx.Response(400, json={"detail": "OSV scan is not enabled for product Portal"})
    )

    result = await call("secobserve_trigger_scan", scanner="osv", product_id=12)

    assert result.startswith("Error:")
    assert "OSV scan is not enabled" in result
    assert "Still running" not in result


@respx.mock
async def test_api_import_timeout_names_the_row_keyed_by_the_configuration_name() -> None:
    respx.get(f"{API}/api_configurations/5/").mock(
        return_value=httpx.Response(200, json={"id": 5, "name": "dtrack-portal", "product": 12})
    )
    baseline = respx.get(f"{API}/vulnerability_checks/").mock(
        return_value=checks({**CHECK_ROW, "api_configuration_name": "dtrack-portal", "scanner": "Dependency Track"})
    )
    respx.post(f"{API}/import/api_import_observations_by_id/").mock(side_effect=TIMED_OUT)

    result = await call("secobserve_api_import", api_configuration_id=5, branch_id=4)

    assert baseline.calls[0].request.url.params["api_configuration_name"] == "dtrack-portal"
    assert result.startswith("Still running")
    assert "'api_configuration_name': 'dtrack-portal'" in result
    assert "'product': 12" in result and "'branch': 4" in result
    assert "last_import was 2026-09-20T07:00:00Z" in result
    assert "writes exactly one row" in result


@respx.mock
async def test_api_import_timeout_falls_back_when_the_configuration_cannot_be_read() -> None:
    # The Upload role carries Product_Import_Observations and nothing else, so it cannot read this endpoint.
    respx.get(f"{API}/api_configurations/5/").mock(return_value=httpx.Response(403, json={"detail": "forbidden"}))
    baseline = respx.get(f"{API}/vulnerability_checks/").mock(return_value=checks(CHECK_ROW))
    respx.post(f"{API}/import/api_import_observations_by_id/").mock(side_effect=TIMED_OUT)

    result = await call("secobserve_api_import", api_configuration_id=5)

    assert not baseline.calls, "an unidentified row must not be anchored to somebody else's timestamp"
    assert result.startswith("Still running")
    assert "secobserve_get(resource='api_configurations', id=" in result


@respx.mock
async def test_api_import_returns_counts_when_it_finishes() -> None:
    respx.get(f"{API}/api_configurations/5/").mock(
        return_value=httpx.Response(200, json={"id": 5, "name": "dtrack-portal", "product": 12})
    )
    respx.get(f"{API}/vulnerability_checks/").mock(return_value=checks(CHECK_ROW))
    respx.post(f"{API}/import/api_import_observations_by_id/").mock(return_value=httpx.Response(200, json=COUNTS))

    result = await call("secobserve_api_import", api_configuration_id=5)

    assert "observations new: 3" in result
    assert "Still running" not in result

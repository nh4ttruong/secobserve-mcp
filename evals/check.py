#!/usr/bin/env python3
"""Answer every question in evaluation.xml against a seeded instance and report each mismatch.

    SECOBSERVE_BASE_URL=... SECOBSERVE_API_TOKEN=... uv run python evals/check.py

Run it on the instance evals/seed.py has just filled, and nothing else: the answers are counts.

Every call goes through mcp.call_tool rather than the tool functions, so argument validation and
coercion are exercised the way a client exercises them. Questions about the server's own behaviour
are answered by provoking that behaviour, not by asserting a constant.

Exit code 0 when every question is answered correctly, 1 otherwise. A question with no check here
fails too: the evaluation growing without the check growing means the job stopped covering it.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar
from xml.etree import ElementTree

from mcp.server.mcpserver.exceptions import ToolError

from secobserve_mcp import tools_crud, tools_workflows  # noqa: F401  (importing registers the tools)
from secobserve_mcp.app import mcp

EVALUATION = Path(__file__).resolve().parent.parent / "evaluation.xml"
SEEDED_PRODUCTS = {"Payments API", "Web Frontend", "Legacy Batch"}
SEVERITY_ORDER = ("Unknown", "None", "Low", "Medium", "High", "Critical")
METRICS_TIMEOUT = 300.0

T = TypeVar("T")


@dataclass(frozen=True)
class Check:
    match: str
    run: Callable[[], Awaitable[str]]
    # Set for the questions whose recorded answer is prose: the substrings the answer has to carry.
    contains: tuple[str, ...] = field(default=())


CHECKS: list[Check] = []


def check(match: str, contains: tuple[str, ...] = ()) -> Callable[[Callable[[], Awaitable[str]]], Any]:
    def register(fn: Callable[[], Awaitable[str]]) -> Callable[[], Awaitable[str]]:
        CHECKS.append(Check(match=match, run=fn, contains=contains))
        return fn

    return register


def only(values: list[T]) -> T:
    if len(values) != 1:
        raise AssertionError(f"expected exactly one value, got {len(values)}: {values!r}")
    return values[0]


def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


async def call(name: str, **arguments: Any) -> str:
    result = await mcp.call_tool(name, arguments)
    return str(result.content[0].text)


async def listing(resource: str, **arguments: Any) -> dict[str, Any]:
    arguments.setdefault("page_size", 100)
    payload: dict[str, Any] = json.loads(
        await call("secobserve_list", resource=resource, response_format="json", **arguments)
    )
    return payload


async def rows(resource: str, **arguments: Any) -> list[dict[str, Any]]:
    payload = await listing(resource, **arguments)
    if payload["has_more"]:
        raise AssertionError(f"{resource} has more than one page here; a count taken from this would be wrong")
    return list(payload["items"])


async def product_id(name: str) -> int:
    return int(only([p["id"] for p in await rows("product_names", filters={"name": name})]))


async def branch_id(product: str, branch: str) -> int:
    return int(
        only(
            [
                b["id"]
                for b in await rows("branch_names", filters={"product": await product_id(product), "name": branch})
            ]
        )
    )


async def wait_for_metrics() -> None:
    """Wait for the metrics job seed.py queued, by waiting for counts rather than for kind='status'.

    kind='status' is no barrier: its singleton row is created on first read with last_calculated defaulting to now,
    so an instance whose job has never run reports that it just ran. The counters are the only honest signal, and
    zero is indistinguishable from "not calculated" -- which is why this waits instead of quoting them.
    """
    deadline = time.monotonic() + METRICS_TIMEOUT
    while True:
        current = json.loads(await call("secobserve_product_metrics", kind="current"))
        if current["open"]:
            return
        if time.monotonic() > deadline:
            raise AssertionError(
                f"the metrics job produced no counts within {METRICS_TIMEOUT:.0f}s; is the huey worker running?"
            )
        await asyncio.sleep(5)


@check("both reported as a finding in more than one product")
async def component_in_two_products_and_the_sbom() -> str:
    products: dict[str, set[str]] = defaultdict(set)
    for row in await rows("observations", fields=["origin_component_name_version", "product_data.name"]):
        if row["origin_component_name_version"]:
            products[row["origin_component_name_version"]].add(row["product_data.name"])
    in_sbom = {
        c["component_name_version"]
        for c in await rows("license_components", filters={"product": await product_id("Payments API")})
    }
    return only(sorted({c for c, seen in products.items() if len(seen) > 1} & in_sbom))


@check('assessed to the status "Not affected"')
async def vex_justification_of_the_not_affected_assessment() -> str:
    found = await rows(
        "observations",
        filters={"product": await product_id("Payments API"), "current_status": "Not affected"},
        fields=["current_vex_justification"],
    )
    return only([row["current_vex_justification"] for row in found])


@check("evaluate as Forbidden")
async def forbidden_license_components() -> str:
    payload = await listing(
        "license_components",
        filters={"product": await product_id("Payments API"), "evaluation_result": "Forbidden"},
        fields=["id"],
    )
    return str(payload["total"])


@check("reported at least one finding in every one of the three products")
async def scanner_present_everywhere() -> str:
    seen: dict[str, set[str]] = defaultdict(set)
    for row in await rows("observations", fields=["scanner_name", "product_data.name"]):
        seen[row["scanner_name"]].add(row["product_data.name"])
    products = len(await rows("products", fields=["id"]))
    return only(sorted(scanner for scanner, found in seen.items() if len(found) == products))


@check('"Platform" product group still have the status Open')
async def open_observations_in_the_platform_group() -> str:
    group = only([g["id"] for g in await rows("product_group_names", filters={"name": "Platform"})])
    payload = await listing("observations", filters={"product_group": group, "current_status": "Open"}, fields=["id"])
    return str(payload["total"])


@check("Legacy Batch product has exactly one observation with Critical severity")
async def critical_finding_of_legacy_batch() -> str:
    found = await rows(
        "observations",
        filters={"product": await product_id("Legacy Batch"), "current_severity": "Critical"},
        fields=["title"],
    )
    return only([row["title"] for row in found])


@check("finding with the highest severity")
async def highest_severity_on_the_release_branch() -> str:
    found = await rows(
        "observations",
        filters={"branch": await branch_id("Payments API", "release/2.0")},
        fields=["title", "current_severity"],
    )
    return max(found, key=lambda row: SEVERITY_ORDER.index(row["current_severity"]))["title"]


@check("Which file was uploaded")
async def upload_filename_of_the_release_branch() -> str:
    found = await rows(
        "observations",
        filters={"branch": await branch_id("Payments API", "release/2.0")},
        fields=["upload_filename"],
    )
    return only(sorted({row["upload_filename"] for row in found}))


@check("do not pass their security gate")
async def products_failing_the_security_gate() -> str:
    found = await rows("products", fields=["security_gate_passed"])
    return str(sum(1 for row in found if row["security_gate_passed"] is not True))


@check('status "Risk accepted"')
async def risk_acceptance_expiry() -> str:
    found = await rows(
        "observations", filters={"current_status": "Risk accepted"}, fields=["risk_acceptance_expiry_date"]
    )
    return only([row["risk_acceptance_expiry_date"] for row in found])


@check("Without calling the SecObserve API at all")
async def resource_holding_the_assessment_history() -> str:
    catalogue = await call("secobserve_list_resources")
    sections = re.split(r"^## ", catalogue, flags=re.MULTILINE)[1:]
    return only([s.split("\n", 1)[0].strip() for s in sections if "approval state" in s])


@check("Which endpoint of the running instance does this server read")
async def endpoint_behind_describe_resource() -> str:
    described = json.loads(await call("secobserve_describe_resource", resource="observations"))
    parameters = {p["name"] for p in described["operations"]["/observations/"]["GET"]["parameters"]}
    if "current_severity" not in parameters or "vulnerability_id" in parameters:
        raise AssertionError(f"these are not this instance's own observation filters: {sorted(parameters)}")
    return "/api/oa3/schema/"


@check(
    "filtered by vulnerability_id",
    contains=("vulnerability_id is not a filter", "return unfiltered results", "current_severity"),
)
async def unknown_filter_is_refused() -> str:
    return await call("secobserve_list", resource="observations", filters={"vulnerability_id": "CVE-2021-44228"})


@check("an argument named filter instead of filters", contains=("filter", "Extra inputs are not permitted"))
async def unknown_argument_is_refused() -> str:
    try:
        return await call("secobserve_list", resource="products", filter={"id": 1})
    except ToolError as exc:
        return str(exc)


@check("carry the vulnerability id CVE-2021-44228")
async def spread_of_one_cve() -> str:
    everything = await rows("observations", fields=["vulnerability_id", "product_data.name"])
    found = [row for row in everything if row["vulnerability_id"] == "CVE-2021-44228"]
    return f"{len(found)} observations across {len({row['product_data.name'] for row in found})} products"


@check("with page_size=5")
async def paging_through_every_observation() -> str:
    seen, pages, number = 0, 0, 1
    while pages < 50:
        payload = await listing("observations", page=number, page_size=5, fields=["id"])
        seen += len(payload["items"])
        pages += 1
        if not payload["has_more"]:
            return f"{seen} observations, {pages} pages"
        number = payload["next_page"]
    raise AssertionError("pagination did not terminate")


@check("How many fields is the default projection")
async def size_of_the_default_projection() -> str:
    projected = (await listing("observations", page_size=1))["items"][0]
    everything = (await listing("observations", page_size=1, fields=["*"]))["items"][0]
    if len(everything) <= len(projected):
        raise AssertionError('fields=["*"] returned no more columns than the default projection')
    return f'{len(projected)} fields; fields=["*"]'


@check("projected down to the name of their product")
async def product_name_is_spelled_differently() -> str:
    observation = (await listing("observations", page_size=1, fields=["product_data.name", "product_name"]))["items"][0]
    component = (await listing("license_components", page_size=1, fields=["product_name", "product_data.name"]))[
        "items"
    ][0]
    if not observation.get("product_data.name") or observation.get("product_name"):
        raise AssertionError(f"observations answer to product_data.name only, got {observation!r}")
    if not component.get("product_name") or component.get("product_data.name"):
        raise AssertionError(f"license_components answer to product_name only, got {component!r}")
    return "product_data.name for observations, product_name for license_components"


@check('free-text search of observations for "credential"')
async def search_for_credential() -> str:
    found = await rows("observations", search="credential", fields=["product_data.name"])
    return f"{len(found)} findings: " + ", ".join(f"one in {row['product_data.name']}" for row in found)


@check("current metrics snapshot report for the Payments API")
async def open_critical_in_the_metrics_snapshot() -> str:
    await wait_for_metrics()
    payload = json.loads(
        await call("secobserve_product_metrics", kind="current", product_id=await product_id("Payments API"))
    )
    if "stale" in payload:
        raise AssertionError(f"the metrics snapshot is stale, so its zeros are not an answer: {payload['stale']}")
    return str(payload["active_critical"])


@check("refuses to run on its own", contains=("purl_types", "product_id"))
async def status_kind_that_needs_a_product() -> str:
    return await call("secobserve_status", kind="purl_types")


@check("which product has the most observations still in status Open")
async def product_with_the_most_open_observations() -> str:
    found = await rows("observations", filters={"current_status": "Open"}, fields=["product_data.name"])
    name, count = Counter(row["product_data.name"] for row in found).most_common(1)[0]
    return f"{name}, {count}"


@check("assessed as a False positive")
async def scanner_behind_the_false_positive() -> str:
    found = await rows("observations", filters={"current_status": "False positive"}, fields=["scanner_name"])
    scanner = only([row["scanner_name"] for row in found])
    reported = await rows("observations", filters={"scanner": scanner}, fields=["product_data.name"])
    return f"{scanner}, in " + " and ".join(sorted({row["product_data.name"] for row in reported}))


@check("is not the default branch of its product")
async def the_one_non_default_branch() -> str:
    branch = only([b for b in await rows("branches") if not b["is_default_branch"]])
    names = {p["id"]: p["name"] for p in await rows("product_names")}
    payload = await listing("observations", filters={"branch": branch["id"]}, fields=["id"])
    return f"{names[branch['product']]}, {branch['name']}, {payload['total']} observations"


@check("one license covers two components")
async def license_shared_by_two_components() -> str:
    components: dict[str, list[str]] = defaultdict(list)
    for row in await rows("license_components", filters={"product": await product_id("Payments API")}):
        components[row["effective_license_name"]].append(row["component_name_version"])
    name, shared = only([(k, v) for k, v in components.items() if len(v) == 2])
    return f"{name}, on " + " and ".join(shared)


@check('counts the ones in status "In review"')
async def observations_in_review() -> str:
    payload = json.loads(
        await call("secobserve_call_action", resource="observations", action="count_reviews", response_format="json")
    )
    return str(payload["count"])


def questions() -> list[tuple[str, str]]:
    tree = ElementTree.parse(EVALUATION)
    return [
        (normalise(pair.findtext("question", "")), normalise(pair.findtext("answer", "")))
        for pair in tree.findall("qa_pair")
    ]


async def confirm_seeded() -> None:
    names = {p["name"] for p in await rows("products", fields=["name"])}
    if names != SEEDED_PRODUCTS:
        raise SystemExit(
            f"This instance holds {sorted(names)}, not the seeded dataset {sorted(SEEDED_PRODUCTS)}.\n"
            "The answers are counts: run evals/seed.py against an empty instance first."
        )


async def main() -> int:
    await confirm_seeded()

    total = failed = 0
    for number, (question, answer) in enumerate(questions(), start=1):
        total = number
        matches = [c for c in CHECKS if c.match in question]
        label = f"q{number:02d}"
        if len(matches) != 1:
            failed += 1
            reason = "no check answers it" if not matches else f"{len(matches)} checks match it"
            print(f"FAIL  {label}  {question}\n      {reason}; add or narrow one in evals/check.py")
            continue

        checker = matches[0]
        try:
            got = normalise(await checker.run())
        except Exception as exc:  # noqa: BLE001  -- a check that blows up is a failed answer, not a crashed run
            got = f"{type(exc).__name__}: {exc}"

        if checker.contains:
            ok = all(fragment in got for fragment in checker.contains)
            expected = "text containing " + ", ".join(repr(f) for f in checker.contains)
        else:
            ok = got == answer
            expected = answer

        if ok:
            print(f"PASS  {label}  {question}")
        else:
            failed += 1
            print(f"FAIL  {label}  {question}\n      expected: {expected}\n      got:      {got}")

    print(f"\n{total - failed}/{total} answered correctly.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

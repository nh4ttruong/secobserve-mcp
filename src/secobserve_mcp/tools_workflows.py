"""Validated tools for the SecObserve workflows that are worth getting right.

Everything here is reachable through secobserve_call_action, but these endpoints
carry rules an agent cannot infer from a path -- an assessment needs a comment,
it is refused while a previous one awaits approval, "Not affected" wants a VEX
justification, imports are multipart, scans block until they finish. Encoding
that in the schema and the docstring turns a class of 400s into a schema error.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from typing import Annotated, Any, Literal

from mcp.types import ToolAnnotations
from pydantic import Field

from .app import mcp
from .client import SecObserveError, request, tool_errors
from .exports import read_upload, write_export
from .formatting import ResponseFormat, render_object
from .types import ApprovalStatus, MetricsAge, Severity, Status, VexJustification

MAX_BULK = 250


SeverityArg = Annotated[Severity | None, Field(description="New severity. Omit to leave it as it is.")]
StatusArg = Annotated[Status | None, Field(description="New status. Omit to leave it as it is.")]
PriorityArg = Annotated[
    int | None, Field(description="New priority, 1 (most urgent) to 99. Use clear_priority to remove one.", ge=1, le=99)
]
ClearPriorityArg = Annotated[bool, Field(description="Remove the existing priority. Cannot be combined with priority.")]
VexJustificationArg = Annotated[
    VexJustification | None,
    Field(
        description=(
            "Why the finding does not apply. Expected with status 'Not affected' or 'False positive' so that "
            "generated VEX documents carry a machine-readable reason."
        )
    ),
]
RiskExpiryArg = Annotated[
    str | None,
    Field(
        description="ISO date (YYYY-MM-DD) when a 'Risk accepted' status lapses back to open.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    ),
]
CommentArg = Annotated[
    str,
    Field(
        description=(
            "Why this assessment was made. Mandatory -- it is the audit record, and approvers see only this. "
            "State the evidence, not just the verdict."
        ),
        min_length=1,
        max_length=4096,
    ),
]


def _assessment_payload(
    comment: str,
    severity: Severity | None,
    status: Status | None,
    priority: int | None,
    clear_priority: bool,
    vex_justification: VexJustification | None,
    risk_acceptance_expiry_date: str | None,
) -> dict[str, Any]:
    if priority is not None and clear_priority:
        raise ValueError("Give priority or clear_priority, not both.")
    if not any((severity, status, priority, clear_priority, vex_justification, risk_acceptance_expiry_date)):
        raise ValueError(
            "An assessment must change at least one of severity, status, priority, clear_priority, "
            "vex_justification or risk_acceptance_expiry_date. To record a comment without a change "
            "there is nothing to submit."
        )

    body: dict[str, Any] = {"comment": comment}
    if severity is not None:
        body["severity"] = severity.value
    if status is not None:
        body["status"] = status.value
    if vex_justification is not None:
        body["vex_justification"] = vex_justification.value
    if risk_acceptance_expiry_date is not None:
        body["risk_acceptance_expiry_date"] = risk_acceptance_expiry_date
    # An absent key leaves the priority alone; a present null clears it.
    if priority is not None or clear_priority:
        body["priority"] = priority
    return body


def _summarise_import(payload: Any, what: str) -> str:
    if not isinstance(payload, dict):
        return f"{what} accepted. The API returned no counts."
    parts = [f"{key.replace('_', ' ')}: {value}" for key, value in payload.items()]
    return f"{what}\n" + "\n".join(f"- {part}" for part in parts)


@mcp.tool(
    name="secobserve_assess_observation",
    title="Assess SecObserve Observation",
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True,
    ),
)
@tool_errors
async def secobserve_assess_observation(
    observation_id: Annotated[int, Field(description="Id of the observation to assess.", ge=1)],
    comment: CommentArg,
    severity: SeverityArg = None,
    status: StatusArg = None,
    priority: PriorityArg = None,
    clear_priority: ClearPriorityArg = False,
    vex_justification: VexJustificationArg = None,
    risk_acceptance_expiry_date: RiskExpiryArg = None,
) -> str:
    """Record a human assessment on one observation: change its severity, status, priority or VEX justification.

    This is how triage is done. It writes an observation log, so the change is
    attributable and reversible, and it is what later VEX documents are generated
    from. Never edit an observation's severity or status with secobserve_update --
    that bypasses the log and the approval workflow.

    Two rules the API enforces: a comment is mandatory, and a new assessment is
    refused while the previous one is still in 'Needs approval'.

    Args:
        observation_id (int): Observation to assess.
        severity (Optional[Severity]): Unknown/None/Low/Medium/High/Critical.
        status (Optional[Status]): Open/Affected/Resolved/Duplicate/False positive/
          In review/Not affected/Not security/Risk accepted.
        priority (Optional[int]): 1-99.
        clear_priority (bool): Remove the priority instead of setting one.
        vex_justification (Optional[VexJustification]): Machine-readable reason,
          expected with 'Not affected' and 'False positive'.
        risk_acceptance_expiry_date (Optional[str]): YYYY-MM-DD, for 'Risk accepted'.
        comment (str): Mandatory rationale, 1-4096 characters.

    Returns:
        str: A confirmation line naming the observation and the fields changed, plus
             a note when the instance's four-eyes setting leaves the assessment in
             'Needs approval' (the API returns an empty body on success).

    Examples:
        - Use when: "mark 8123 as not affected, the vulnerable function is never called" ->
          observation_id=8123, status="Not affected",
          vex_justification="vulnerable_code_not_in_execute_path", comment="..."
        - Use when: "accept the risk on 8123 until the end of the quarter" ->
          status="Risk accepted", risk_acceptance_expiry_date="2026-12-31", comment="..."
        - Don't use when: assessing many findings the same way (use
          secobserve_bulk_assess_observations).
        - Don't use when: approving someone else's assessment (use
          secobserve_approve_observation_log).

    Error Handling:
        400 "Cannot create new assessment while last assessment still needs approval"
        means the previous assessment must be approved or rejected first.
        403 means the token lacks Observation_Assessment on that product.
        The schema refuses a call that would change nothing.
    """
    body = _assessment_payload(
        comment, severity, status, priority, clear_priority, vex_justification, risk_acceptance_expiry_date
    )
    await request("PATCH", f"/observations/{observation_id}/assessment/", json_body=body)
    changed = ", ".join(k for k in body if k != "comment") or "nothing"
    return (
        f"Assessed observation {observation_id} ({changed}). "
        "If this instance requires four-eyes approval, the assessment is now in 'Needs approval' -- "
        "check with secobserve_list(resource='observation_logs', "
        f"filters={{'observation': {observation_id}}})."
    )


@mcp.tool(
    name="secobserve_bulk_assess_observations",
    title="Bulk Assess SecObserve Observations",
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True,
    ),
)
@tool_errors
async def secobserve_bulk_assess_observations(
    observation_ids: Annotated[
        list[int],
        Field(
            description=f"Ids to assess, 1 to {MAX_BULK} per call. Every id gets the same assessment.",
            min_length=1,
            max_length=MAX_BULK,
        ),
    ],
    comment: CommentArg,
    product_id: Annotated[
        int | None,
        Field(
            description=(
                "Scope the call to one product's endpoint. Omit for the instance-wide endpoint. "
                "Pass it when the token is a product API token, which cannot use the instance-wide one."
            ),
            ge=1,
        ),
    ] = None,
    severity: SeverityArg = None,
    status: StatusArg = None,
    priority: PriorityArg = None,
    clear_priority: ClearPriorityArg = False,
    vex_justification: VexJustificationArg = None,
    risk_acceptance_expiry_date: RiskExpiryArg = None,
) -> str:
    """Apply one identical assessment to up to 250 observations by id.

    The comment is stored on every one of them, so write it to be true of the whole
    set. Get the ids from secobserve_list with response_format="json" and
    fields=["id"]; a filter that matches more than 250 rows needs several calls.

    Args:
        observation_ids (List[int]): 1-250 observation ids.
        product_id (Optional[int]): Use the product-scoped endpoint instead of
          the instance-wide one; required for product API tokens.
        severity, status, priority, clear_priority, vex_justification,
          risk_acceptance_expiry_date: as in secobserve_assess_observation.
        comment (str): Mandatory rationale applied to every observation.

    Returns:
        str: A confirmation naming the number of observations submitted and the
             fields changed. The API returns 204 with no body, so per-observation
             outcomes are not reported; any id whose previous assessment awaits
             approval is skipped server-side.

    Examples:
        - Use when: "all 40 findings in this retired branch are resolved" ->
          observation_ids=[...], status="Resolved", comment="Branch decommissioned ..."
        - Use when: "these are all the same false positive from the secret scanner" ->
          status="False positive", vex_justification="component_not_present", comment="..."
        - Don't use when: the findings need different verdicts (assess them one by one).

    Error Handling:
        Over 250 ids is refused by the schema. 403 means the token lacks
        Observation_Assessment on one of the products involved -- narrow with
        product_id. Read-only mode blocks the call.
    """
    body = _assessment_payload(
        comment, severity, status, priority, clear_priority, vex_justification, risk_acceptance_expiry_date
    )
    if product_id:
        body["observations"] = observation_ids
        path = f"/products/{product_id}/observations_bulk_assessment/"
    else:
        body["observations"] = observation_ids
        path = "/observations/bulk_assessment/"

    await request("POST", path, json_body=body)
    changed = ", ".join(k for k in body if k not in {"comment", "observations"}) or "nothing"
    return (
        f"Submitted a bulk assessment for {len(observation_ids)} observations ({changed}) via {path}. "
        "Observations whose previous assessment still needs approval are skipped by the backend; "
        "re-list them to confirm."
    )


@mcp.tool(
    name="secobserve_approve_observation_log",
    title="Approve SecObserve Assessments",
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True,
    ),
)
@tool_errors
async def secobserve_approve_observation_log(
    observation_log_ids: Annotated[
        list[int],
        Field(
            description=(
                f"Observation log ids awaiting approval, 1 to {MAX_BULK}. Find them with "
                "secobserve_list(resource='observation_logs', filters={'assessment_status': 'Needs approval'})."
            ),
            min_length=1,
            max_length=MAX_BULK,
        ),
    ],
    assessment_status: Annotated[
        ApprovalStatus,
        Field(
            description=(
                "'Approved' accepts the assessment as submitted, 'Approved with edits' accepts it with "
                "the observation_log_* overrides below, 'Rejected' discards it."
            )
        ),
    ],
    rejection_remark: Annotated[
        str | None,
        Field(
            description="Why the assessment was rejected. Required when assessment_status is 'Rejected'.",
            max_length=255,
        ),
    ] = None,
    observation_log_comment: Annotated[
        str | None,
        Field(description="Replacement comment, only with 'Approved with edits'.", max_length=4096),
    ] = None,
    observation_log_vex_justification: Annotated[
        VexJustification | None,
        Field(description="Replacement VEX justification, only with 'Approved with edits' and a single id."),
    ] = None,
) -> str:
    """Approve or reject assessments waiting in 'Needs approval' (the four-eyes workflow).

    Only an approver other than the submitter can clear a pending assessment, and
    until it is cleared the observation accepts no further assessment. Rejection
    requires a remark, which is what the submitter sees.

    Args:
        observation_log_ids (List[int]): 1-250 pending observation log ids.
        assessment_status (ApprovalStatus): "Approved", "Approved with edits"
          or "Rejected".
        rejection_remark (Optional[str]): Required when rejecting.
        observation_log_comment (Optional[str]): Replacement comment, only with
          "Approved with edits".
        observation_log_vex_justification (Optional[VexJustification]):
          Replacement justification, only with "Approved with edits" and one id.

    Returns:
        str: A confirmation naming the verdict and how many logs it was applied to.
             Single-id calls use the per-log endpoint, several ids the bulk endpoint.

    Examples:
        - Use when: "approve the pending assessment on log 991" ->
          observation_log_ids=[991], assessment_status="Approved"
        - Use when: "reject 991, the justification does not match the evidence" ->
          assessment_status="Rejected", rejection_remark="..."
        - Use when: clearing a review queue -> list observation_logs filtered by
          assessment_status="Needs approval", then pass the ids here.
        - Don't use when: making the assessment itself (use secobserve_assess_observation).

    Error Handling:
        403 means the token may not approve, or is the submitter's own -- SecObserve
        refuses self-approval. 400 means the log is not in 'Needs approval' any more.
    """
    if assessment_status is ApprovalStatus.REJECTED and not rejection_remark:
        raise ValueError("Rejecting an assessment requires rejection_remark so the submitter knows why.")
    body: dict[str, Any] = {"assessment_status": assessment_status.value}
    if rejection_remark:
        body["rejection_remark"] = rejection_remark
    if observation_log_comment:
        body["observation_log_comment"] = observation_log_comment
    if observation_log_vex_justification:
        body["observation_log_vex_justification"] = observation_log_vex_justification.value

    if len(observation_log_ids) == 1:
        log_id = observation_log_ids[0]
        await request("PATCH", f"/observation_logs/{log_id}/approval/", json_body=body)
        return f"Recorded '{assessment_status.value}' on observation log {log_id}."

    if observation_log_vex_justification:
        raise SecObserveError(
            "observation_log_vex_justification applies to a single assessment. "
            "Call this tool once per log, or drop the justification override."
        )
    body["observation_logs"] = observation_log_ids
    await request("POST", "/observation_logs/bulk_approval/", json_body=body)
    return (
        f"Recorded '{assessment_status.value}' on {len(observation_log_ids)} observation logs. "
        "Logs that were no longer pending are skipped by the backend."
    )


async def _require_product(product_id: int) -> None:
    """Raise unless product_id is a product or a product group the token can read.

    The metrics endpoints resolve an unknown id to "no product" and then answer for the whole instance with HTTP 200,
    so a typo comes back as the entire estate's numbers presented as one product's. /product_names/ holds products
    only, which is why a product group needs the second lookup rather than a single one.
    """
    try:
        await request("GET", f"/product_names/{product_id}/")
    except SecObserveError as exc:
        try:
            await request("GET", f"/product_group_names/{product_id}/")
        except SecObserveError:
            raise ValueError(
                f"product_id={product_id} is not a product or a product group this token can read, and the metrics "
                "endpoints would have answered for the whole instance instead of failing. Resolve the id with "
                "secobserve_list(resource='product_names', search='<name>'), or omit product_id for the instance. "
                f"The lookup failed with: {exc}"
            ) from exc


# Three runs tolerate two missed ones. Never less than half an hour, because last_calculated is written when a run
# finishes and a run on a large instance can outlast its own interval, which would flag a job that is only slow.
_STALE_AFTER_RUNS = 3
_STALE_MINIMUM = timedelta(minutes=30)


def _metrics_staleness(status: Any) -> dict[str, Any] | None:
    """None when the metrics job ran recently, otherwise a block saying why the counts are not a measurement.

    Elapsed time, not calendar dates: the backend decides which day the counts come from in its own TIME_ZONE, so a
    host in another zone would keep reporting the numbers as current for as many hours as it runs ahead.
    """
    last_calculated = status.get("last_calculated") if isinstance(status, dict) else None
    interval = _calculation_interval(status)
    elapsed = _elapsed_since(last_calculated)
    if elapsed is not None and elapsed <= max(_STALE_AFTER_RUNS * interval, _STALE_MINIMUM):
        return None
    if elapsed is not None:
        when = f"{_format_elapsed(elapsed)} ago"
    elif last_calculated is None:
        when = "never"
    else:
        when = "at a timestamp this server could not parse"
    return {
        "last_calculated": last_calculated,
        "warning": (
            f"The metrics job last ran {when}, and the backend expects it every "
            f"{int(interval.total_seconds() // 60)} minutes. Once its own day rolls over without a run there are no "
            "rows for that day and every count below is a zero the backend filled in, not a measurement. "
            "Do not quote these numbers. Run secobserve_run_periodic_task(task='calculate_product_metrics'), "
            "or count the rows themselves with secobserve_list."
        ),
    }


def _calculation_interval(status: Any) -> timedelta:
    """How often the metrics job is meant to run, with anything unusable read as the backend's own default.

    Capped at an hour: the backend schedules the job on a minute crontab, so a larger number is a broken schedule
    rather than a longer wait, and taking it at face value would widen the guard to days.
    """
    raw = status.get("calculation_interval") if isinstance(status, dict) else None
    minutes = raw if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0 else 5
    return timedelta(minutes=min(minutes, 60))


def _elapsed_since(timestamp: Any) -> timedelta | None:
    """How long ago an ISO timestamp was, or None when it is absent or unreadable."""
    if not isinstance(timestamp, str):
        return None
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return None
    return datetime.now(UTC) - (parsed if parsed.tzinfo else parsed.astimezone())


def _format_elapsed(elapsed: timedelta) -> str:
    """Coarse elapsed time: the agent needs the order of magnitude, not the seconds."""
    hours, minutes = divmod(int(elapsed.total_seconds()) // 60, 60)
    days, hours = divmod(hours, 24)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


_AGE_DAYS: dict[MetricsAge, int] = {
    MetricsAge.WEEK: 7,
    MetricsAge.MONTH: 30,
    MetricsAge.QUARTER: 90,
    MetricsAge.YEAR: 365,
}


def _timeline_age(since: date, today: date) -> MetricsAge | None:
    """The smallest window that still reaches back to `since`, or None for the full retained history.

    A day of slack, because the backend cuts the window on its own clock and that may already be tomorrow.
    """
    needed = (today - since).days + 1
    for age, days in _AGE_DAYS.items():
        if needed <= days:
            return age
    return None


def _metrics_delta(timeline: Any, since: date, until: date) -> dict[str, Any]:
    """Subtract two days of the timeline, each taken from the nearest retained date at or before its bound."""
    dates = sorted(timeline) if isinstance(timeline, dict) else []
    at_or_before_since = [day for day in dates if day <= since.isoformat()]
    if not at_or_before_since:
        earliest = f"the earliest date with metrics is {dates[0]}" if dates else "the timeline came back empty"
        raise ValueError(
            f"No metrics are retained on or before since={since.isoformat()}: {earliest}. "
            "Move since forward, or read kind='timeline' to see what the instance still holds."
        )

    start_day = at_or_before_since[-1]
    end_day = max(day for day in dates if day <= until.isoformat())
    start = timeline[start_day]
    end = timeline[end_day]
    span = (date.fromisoformat(end_day) - date.fromisoformat(start_day)).days + 1
    return {
        "since": {"requested": since.isoformat(), "used": start_day},
        "until": {"requested": until.isoformat(), "used": end_day},
        "start": start,
        "end": end,
        "delta": {key: int(end.get(key, 0)) - int(start.get(key, 0)) for key in sorted(set(start) | set(end))},
        "missing_days": span - sum(1 for day in dates if start_day <= day <= end_day),
    }


@mcp.tool(
    name="secobserve_product_metrics",
    title="Read SecObserve Metrics",
    annotations=ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=True,
    ),
)
@tool_errors
async def secobserve_product_metrics(
    kind: Annotated[
        Literal["current", "timeline", "status", "delta"],
        Field(
            description=(
                "'current' = observation counts by severity and status as of the last calculation; "
                "'timeline' = one entry per day; 'delta' = the signed change between since and until; "
                "'status' = when metrics were last calculated "
                "and how often, which tells you how stale 'current' is."
            )
        ),
    ],
    product_id: Annotated[
        int | None,
        Field(
            description=(
                "Restrict to one product, or to every product in a product group when the id is a group. "
                "An id that matches neither is refused. Omit for the whole instance."
            ),
            ge=1,
        ),
    ] = None,
    age: Annotated[
        MetricsAge | None,
        Field(description="Time window, for kind='timeline' only. Omit for the full retained history."),
    ] = None,
    since: Annotated[
        str | None,
        Field(
            description=(
                "Start of the range for kind='delta', ISO YYYY-MM-DD. The nearest date with metrics at or before "
                "it is used, and the result names it."
            ),
            pattern=r"^\d{4}-\d{2}-\d{2}$",
        ),
    ] = None,
    until: Annotated[
        str | None,
        Field(
            description="End of the range for kind='delta', ISO YYYY-MM-DD. Defaults to today, resolved like since.",
            pattern=r"^\d{4}-\d{2}-\d{2}$",
        ),
    ] = None,
    response_format: Annotated[ResponseFormat, Field(description="Output format.")] = ResponseFormat.JSON,
) -> str:
    """Read pre-aggregated observation counts for a product, a group, or the whole instance.

    Far cheaper than counting rows with secobserve_list: these come from the
    metrics tables a background job maintains. That also means they are as old as
    the last calculation -- kind="status" tells you how old, and is worth reading
    before quoting a number as current.

    License counts are not in here: use secobserve_list("products") for the per-product `*_licenses_count` fields, or the `license_overview` action on `license_components` for counts grouped by license.

    kind="delta" answers "what changed between these two dates", which the API itself cannot: it offers relative windows only, has no delta endpoint, and its timeline skips the days the background job did not run.

    Args:
        kind (str): "current", "timeline", "delta" or "status".
        product_id (Optional[int]): One product, or every product in a group
          when the id is a product group. Resolved before the metrics are read,
          because the endpoints answer for the whole instance when the id
          matches nothing. Omit for the instance.
        age (Optional[MetricsAge]): Window for "timeline": "Past 7 days",
          "Past 30 days", "Past 90 days", "Past 365 days".
        since (Optional[str]): Start of the range for "delta", YYYY-MM-DD.
        until (Optional[str]): End of the range for "delta", YYYY-MM-DD, today when omitted.
        response_format (ResponseFormat): "json" (default) or "markdown".

    Returns:
        str: For kind="current", a JSON object of fifteen counts: six by severity (active_critical, active_high, active_medium, active_low, active_none, active_unknown) and nine by status (open, affected, resolved, duplicate, false_positive, in_review, not_affected, not_security, risk_accepted).
             It carries an extra "stale" block when the metrics job has not run for several of its own calculation intervals, because the endpoint then answers 200 with every count at zero instead of failing. The warning says how long ago it last ran.
             For kind="timeline", a JSON object keyed by ISO date, each value the counts for that day.
             For kind="delta", {"since": {"requested", "used"}, "until": {"requested", "used"}, "start": counts, "end": counts, "delta": signed change per counter, "missing_days": days in the range the job never wrote}.
             Quote "used" rather than "requested" whenever they differ, since the counts come from the dates that exist.
             For kind="status", {"last_calculated": ISO timestamp, "calculation_interval": minutes}.

    Examples:
        - Use when: "how many critical findings are open in product 12?" ->
          kind="current", product_id=12
        - Use when: "is our backlog growing?" -> kind="timeline", age="Past 90 days"
        - Use when: "what changed in August?" -> kind="delta", since="2026-08-01", until="2026-08-31"
        - Use when: a metric looks wrong -> kind="status", to check the job has run.
        - Don't use when: you need the findings themselves (use secobserve_list).
        - Don't use when: you need license counts, see above.

    Error Handling:
        403 means no view permission on the product, and an unknown product_id is refused rather than silently widened to the whole instance.
        An empty timeline usually means the metrics job has not run yet for that window -- check kind="status".
        A "stale" block on kind="current" is not an error, but the zeros under it are not an answer: report the staleness instead of the counts.
        kind="delta" refuses a since after until, a since older than everything the instance retains (the error names the earliest date it has), and since or until on another kind.
    """
    if (since or until) and kind != "delta":
        raise ValueError(
            f"since and until belong to kind='delta', not kind='{kind}'. "
            "Use kind='delta' to compare two dates, or kind='timeline' with age for a whole window."
        )

    if product_id is not None:
        await _require_product(product_id)

    if kind == "delta":
        if since is None:
            raise ValueError("kind='delta' needs since='YYYY-MM-DD'. until is optional and defaults to today.")
        today = datetime.now(UTC).astimezone().date()
        since_date = date.fromisoformat(since)
        until_date = date.fromisoformat(until) if until else today
        if since_date > until_date:
            raise ValueError(f"since={since_date.isoformat()} is after until={until_date.isoformat()}. Swap them.")
        window = _timeline_age(since_date, today)
        payload = _metrics_delta(
            await request(
                "GET",
                "/metrics/product_metrics_timeline/",
                params={"product_id": product_id, "age": window.value if window else None},
            ),
            since_date,
            until_date,
        )
    elif kind == "status":
        payload = await request("GET", "/metrics/product_metrics_status/")
    elif kind == "current":
        payload = await request("GET", "/metrics/product_metrics_current/", params={"product_id": product_id})
        stale = _metrics_staleness(await request("GET", "/metrics/product_metrics_status/"))
        if stale and isinstance(payload, dict):
            payload["stale"] = stale
    else:
        payload = await request(
            "GET",
            "/metrics/product_metrics_timeline/",
            params={"product_id": product_id, "age": age.value if age else None},
        )

    if response_format is ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    scope = f"product {product_id}" if product_id else "all products"
    if isinstance(payload, dict):
        return render_object(payload, title=f"Metrics ({kind}, {scope})", response_format=ResponseFormat.MARKDOWN)
    return json.dumps(payload, indent=2, default=str)


@mcp.tool(
    name="secobserve_upload_file",
    title="Import File Into SecObserve",
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True,
    ),
)
@tool_errors
async def secobserve_upload_file(
    kind: Annotated[
        Literal["observations", "sbom", "vex"],
        Field(
            description=(
                "'observations' = a scanner report (Trivy, Grype, Semgrep, ZAP, ...); "
                "'sbom' = a CycloneDX or SPDX SBOM, which creates license components; "
                "'vex' = a third-party VEX document whose statements assess existing observations."
            )
        ),
    ],
    file_path: Annotated[
        str,
        Field(description="Path to the file, absolute or relative to the server's import directory.", min_length=1),
    ],
    product_id: Annotated[
        int | None, Field(description="Target product by id. Give this or product_name.", ge=1)
    ] = None,
    product_name: Annotated[
        str | None,
        Field(
            description="Target product by exact name. The by-name endpoints can create the branch on the fly.",
            max_length=255,
        ),
    ] = None,
    branch_id: Annotated[int | None, Field(description="Target branch by id, with product_id.", ge=1)] = None,
    branch_name: Annotated[
        str | None,
        Field(description="Target branch by name; created if missing. Use with product_name.", max_length=255),
    ] = None,
    service: Annotated[str | None, Field(description="Service name to attach the findings to.", max_length=255)] = None,
    suppress_licenses: Annotated[
        bool | None,
        Field(description="For kind='observations': skip license component extraction from the report."),
    ] = None,
    docker_image_name_tag: Annotated[
        str | None,
        Field(description="Origin metadata: the scanned image, e.g. 'registry/app:1.2.3'.", max_length=513),
    ] = None,
    endpoint_url: Annotated[
        str | None, Field(description="Origin metadata: the scanned URL, for DAST reports.", max_length=2048)
    ] = None,
    kubernetes_cluster: Annotated[str | None, Field(description="Origin metadata: cluster.", max_length=255)] = None,
    kubernetes_namespace: Annotated[
        str | None, Field(description="Origin metadata: namespace.", max_length=255)
    ] = None,
) -> str:
    """Import a local scanner report, SBOM or VEX document into SecObserve.

    This is the correct way to get findings in: the import deduplicates against
    existing observations, applies rules, resolves findings that disappeared from
    the report, and records a vulnerability check. Creating observations by hand
    with secobserve_create does none of that.

    The file must live under the server's import directory (SECOBSERVE_IMPORT_DIR,
    the working directory by default) and be at most 64 MiB.

    Args:
        kind (str): "observations", "sbom" or "vex".
        file_path (str): Path to the report, absolute or relative to the import directory.
        product_id (Optional[int]) / product_name (Optional[str]): exactly one,
          ignored for kind="vex" which matches on the document's own product data.
        branch_id (Optional[int]) with product_id, or branch_name (Optional[str])
          with product_name; a named branch is created if missing.
        service (Optional[str]): Service to attach findings to.
        suppress_licenses (Optional[bool]): kind="observations" only.
        docker_image_name_tag / endpoint_url / kubernetes_cluster /
          kubernetes_namespace (Optional[str]): origin metadata recorded on each finding.

    Returns:
        str: The import counts as reported by the API, one per line -- for
             "observations": observations_new, observations_updated,
             observations_resolved plus license_components_new/updated/deleted; for
             "sbom": the license_components_* counts; for "vex": the API's summary.

    Examples:
        - Use when: "import trivy-results.json into product 12, branch main" ->
          kind="observations", file_path="trivy-results.json", product_id=12, branch_id=3
        - Use when: "load this SBOM for the release branch" -> kind="sbom",
          file_path="sbom.cdx.json", product_name="Portal", branch_name="release-2.1"
        - Use when: "apply the vendor's VEX" -> kind="vex", file_path="vendor.openvex.json"
        - Don't use when: the data is behind an API you have configured in SecObserve
          (use secobserve_api_import).

    Error Handling:
        A path outside the import directory, a missing, empty or oversized file is
        refused before any request is made. 400 usually means the parser could not
        read the format -- check the product's expected parser with
        secobserve_list(resource="parsers"). Read-only mode blocks the call.
    """
    if kind != "vex":
        if bool(product_id) == bool(product_name):
            raise ValueError("Give exactly one of product_id or product_name.")
        if product_id and branch_name:
            raise ValueError("branch_name goes with product_name; with product_id use branch_id.")
        if product_name and branch_id:
            raise ValueError("branch_id goes with product_id; with product_name use branch_name.")
    filename, content = read_upload(file_path)

    if kind == "vex":
        payload = await request("POST", "/vex/vex_import/", files={"file": (filename, content)})
        return _summarise_import(payload, f"Imported VEX document {filename}.")

    by_name = bool(product_name)
    if kind == "sbom":
        path = "/import/file_upload_sbom_by_name/" if by_name else "/import/file_upload_sbom_by_id/"
    else:
        path = "/import/file_upload_observations_by_name/" if by_name else "/import/file_upload_observations_by_id/"

    form: dict[str, Any] = {}
    if by_name:
        form["product_name"] = product_name
        if branch_name:
            form["branch_name"] = branch_name
    else:
        form["product"] = product_id
        if branch_id:
            form["branch"] = branch_id
    if service:
        form["service"] = service
    if kind == "observations" and suppress_licenses is not None:
        form["suppress_licenses"] = suppress_licenses
    for key, value in (
        ("docker_image_name_tag", docker_image_name_tag),
        ("endpoint_url", endpoint_url),
        ("kubernetes_cluster", kubernetes_cluster),
        ("kubernetes_namespace", kubernetes_namespace),
    ):
        if value:
            form[key] = value

    payload = await request("POST", path, files={"file": (filename, content)}, data=form)
    return _summarise_import(payload, f"Imported {filename} as {kind} via {path}.")


@mcp.tool(
    name="secobserve_api_import",
    title="Pull Findings From Configured API",
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True,
    ),
)
@tool_errors
async def secobserve_api_import(
    api_configuration_id: Annotated[
        int | None,
        Field(description="Id of the API configuration to pull from. Give this or api_configuration_name.", ge=1),
    ] = None,
    api_configuration_name: Annotated[
        str | None, Field(description="Name of the API configuration to pull from.", max_length=255)
    ] = None,
    branch_id: Annotated[int | None, Field(description="Target branch by id, with the id form.", ge=1)] = None,
    branch_name: Annotated[
        str | None,
        Field(description="Target branch by name, with the name form; created if missing.", max_length=255),
    ] = None,
    service: Annotated[str | None, Field(description="Service name to attach the findings to.", max_length=255)] = None,
    docker_image_name_tag: Annotated[str | None, Field(description="Origin metadata: image.", max_length=513)] = None,
    endpoint_url: Annotated[str | None, Field(description="Origin metadata: URL.", max_length=2048)] = None,
) -> str:
    """Pull findings into SecObserve from an upstream API it already has credentials for.

    The credentials, base URL and parser come from an API configuration stored on
    the product; list them with secobserve_list(resource="api_configurations").
    The call blocks while SecObserve fetches and parses, so it can take a while.

    Args:
        api_configuration_id (Optional[int]) or api_configuration_name
          (Optional[str]): exactly one.
        branch_id (Optional[int]) with the id form, or branch_name
          (Optional[str]) with the name form; a named branch is created if missing.
        service (Optional[str]): Service to attach findings to.
        docker_image_name_tag / endpoint_url (Optional[str]): origin metadata.

    Returns:
        str: observations_new, observations_updated and observations_resolved as
             reported by the API, one per line.

    Examples:
        - Use when: "refresh findings from our Dependency Track project" ->
          api_configuration_name="dtrack-portal", branch_name="main"
        - Use when: scripted re-import after an upstream scan -> api_configuration_id=5
        - Don't use when: you have the report file locally (use secobserve_upload_file).

    Error Handling:
        400 means the upstream call or parse failed -- the message carries the
        upstream error. A timeout does not mean the import failed: check
        secobserve_list(resource="vulnerability_checks") before retrying, or raise
        SECOBSERVE_TIMEOUT.
    """
    if bool(api_configuration_id) == bool(api_configuration_name):
        raise ValueError("Give exactly one of api_configuration_id or api_configuration_name.")
    by_name = bool(api_configuration_name)
    path = "/import/api_import_observations_by_name/" if by_name else "/import/api_import_observations_by_id/"

    body: dict[str, Any] = {}
    if by_name:
        body["api_configuration_name"] = api_configuration_name
        if branch_name:
            body["branch_name"] = branch_name
    else:
        body["api_configuration"] = api_configuration_id
        if branch_id:
            body["branch"] = branch_id
    if service:
        body["service"] = service
    if docker_image_name_tag:
        body["docker_image_name_tag"] = docker_image_name_tag
    if endpoint_url:
        body["endpoint_url"] = endpoint_url

    payload = await request("POST", path, json_body=body)
    target = api_configuration_name or api_configuration_id
    return _summarise_import(payload, f"Imported from API configuration {target}.")


@mcp.tool(
    name="secobserve_trigger_scan",
    title="Trigger SecObserve Built-In Scan",
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True,
    ),
)
@tool_errors
async def secobserve_trigger_scan(
    scanner: Annotated[
        Literal["osv", "vulnerablecode"],
        Field(
            description=(
                "'osv' queries osv.dev for the product's known components; 'vulnerablecode' queries a "
                "configured VulnerableCode instance. Each must be enabled on the product first."
            )
        ),
    ],
    product_id: Annotated[int, Field(description="Product to scan.", ge=1)],
    branch_id: Annotated[
        int | None,
        Field(description="Scan one branch only. Omit to scan every branch of the product.", ge=1),
    ] = None,
) -> str:
    """Run SecObserve's own OSV or VulnerableCode scan over a product's known components.

    These scanners need no report: they look up the components SecObserve already
    has, which is why they are the usual follow-up to an SBOM import. Each must be
    enabled on the product (osv_enabled / vulnerablecode_enabled) or the call is
    rejected. The request blocks until the scan finishes, so a product with many
    components can exceed the HTTP timeout.

    Args:
        scanner (str): "osv" or "vulnerablecode".
        product_id (int): Product to scan.
        branch_id (Optional[int]): One branch, or every branch when omitted.

    Returns:
        str: observations_new, observations_updated and observations_resolved for
             the scan, one per line.

    Examples:
        - Use when: "re-check product 12 against osv.dev" -> scanner="osv", product_id=12
        - Use when: right after importing an SBOM, to get findings for its components.
        - Don't use when: the product has no components yet (import an SBOM first).

    Error Handling:
        400 "OSV scan is not enabled for product X" means enable it on the product
        first (secobserve_update, data={"osv_enabled": true}). A timeout does not
        cancel the scan -- check secobserve_list(resource="vulnerability_checks")
        rather than retrying blind.
    """
    suffix = f"scan_{'osv' if scanner == 'osv' else 'vulnerablecode'}"
    path = f"/products/{product_id}/{branch_id}/{suffix}/" if branch_id else f"/products/{product_id}/{suffix}/"
    payload = await request("POST", path)
    scope = f"branch {branch_id}" if branch_id else "all branches"
    return _summarise_import(payload, f"{scanner} scan of product {product_id} ({scope}) finished.")


@mcp.tool(
    name="secobserve_run_periodic_task",
    title="Run SecObserve Background Task",
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True,
    ),
)
@tool_errors
async def secobserve_run_periodic_task(
    task: Annotated[
        str | None,
        Field(
            description=(
                "Registered task name. Omit to list the names this instance accepts instead of running anything."
            ),
            max_length=100,
        ),
    ] = None,
) -> str:
    """Trigger one of SecObserve's scheduled background jobs now, or list which jobs exist.

    Useful when a metric looks stale or housekeeping has not run. The task is
    queued, not executed inline: the call returns immediately and the outcome shows
    up in secobserve_list(resource="periodic_tasks"). Only one instance of a task
    runs at a time.

    Args:
        task (Optional[str]): Registered task name. Omit to list the accepted
          names without running anything.

    Returns:
        str: With no task, a JSON array of registered task names. With a task, a
             confirmation that it was queued and a pointer to the periodic_tasks
             resource for its outcome.

    Examples:
        - Use when: "what background jobs can I run?" -> task omitted
        - Use when: "recalculate the metrics now" -> task="calculate_product_metrics"
          (confirm the exact name from the listing first).
        - Don't use when: you want to know whether metrics are stale (use
          secobserve_product_metrics with kind="status").

    Error Handling:
        400 means the name is not registered -- call without 'task' for the list.
        409 means that task is already running; wait for it rather than retrying.
        Requires superuser; a product token gets 403.
    """
    if not task:
        payload = await request("GET", "/periodic_tasks/registered_tasks/")
        return json.dumps(payload, indent=2, ensure_ascii=False, default=str)

    await request("POST", "/periodic_tasks/run/", json_body={"task": task})
    return (
        f"Queued background task '{task}'. Watch it with "
        f"secobserve_list(resource='periodic_tasks', filters={{'task': '{task}'}}, ordering='-start_time')."
    )


@mcp.tool(
    name="secobserve_status",
    title="SecObserve Instance Status",
    annotations=ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=True,
    ),
)
@tool_errors
async def secobserve_status(
    kind: Annotated[
        Literal["version", "health", "settings", "background_tasks", "purl_types"],
        Field(
            description=(
                "'version' = SecObserve version; 'health' = liveness; 'settings' = the feature flags and "
                "intervals this instance exposes publicly; 'background_tasks' = queue statistics (superuser); "
                "'purl_types' = the package-URL types known to the instance."
            )
        ),
    ],
    product_id: Annotated[
        int | None,
        Field(description="Required for kind='purl_types': the product whose package-URL types to read.", ge=1),
    ] = None,
    purl_type: Annotated[
        str | None,
        Field(
            description="With kind='purl_types': look up one type (e.g. 'maven') instead of listing all.", max_length=50
        ),
    ] = None,
) -> str:
    """Read instance-level facts: version, health, public settings, queue statistics, PURL types.

    Worth calling once at the start of a session: the version decides which
    features exist, and the settings say whether four-eyes approval, license
    management or the built-in scanners are switched on at all.

    Args:
        kind (str): "version", "health", "settings", "background_tasks" or "purl_types".
        product_id (Optional[int]): Required for kind="purl_types".
        purl_type (Optional[str]): With kind="purl_types", look up one type.

    Returns:
        str: The endpoint's JSON response. "version" gives {"version": str};
             "health" gives a liveness object; "settings" gives the instance's
             public feature flags and intervals; "background_tasks" gives queue and
             worker statistics; "purl_types" gives the known package-URL types.

    Examples:
        - Use when: starting work against an unfamiliar instance -> kind="settings"
        - Use when: "is approval required here?" -> kind="settings"
        - Use when: "are background workers keeping up?" -> kind="background_tasks"
        - Don't use when: you need per-product numbers (use secobserve_product_metrics).

    Error Handling:
        "background_tasks" requires superuser and returns 403 for a product token.
        Everything else works for any authenticated caller.
    """
    if kind == "purl_types" and not product_id:
        raise ValueError("kind='purl_types' needs product_id; the endpoint reports 404 without it.")
    query: dict[str, Any] | None = None
    if kind == "purl_types":
        path = f"/purl_types/{purl_type}/" if purl_type else "/purl_types/"
        query = {"product": product_id}
    else:
        path = {
            "version": "/status/version/",
            "health": "/status/health/",
            "settings": "/status/settings/",
            "background_tasks": "/status/background_task_statistics/",
        }[kind]

    payload = await request("GET", path, params=query)
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


@mcp.tool(
    name="secobserve_vex_document",
    title="Generate SecObserve VEX Document",
    annotations=ToolAnnotations(
        read_only_hint=False,
        destructive_hint=False,
        idempotent_hint=False,
        open_world_hint=True,
    ),
)
@tool_errors
async def secobserve_vex_document(
    format: Annotated[Literal["csaf", "openvex", "cyclonedx"], Field(description="VEX document format to generate.")],
    document_id_prefix: Annotated[
        str | None,
        Field(
            description=(
                "Prefix of the document id. Required when creating, and to identify the document when updating."
            ),
            max_length=200,
        ),
    ] = None,
    document_base_id: Annotated[
        str | None,
        Field(description="The generated base id. Required only when updating an existing document.", max_length=200),
    ] = None,
    product_id: Annotated[
        int | None,
        Field(description="Cover one product. Give product_id or vulnerability_names (or both) when creating.", ge=1),
    ] = None,
    vulnerability_names: Annotated[
        list[str] | None,
        Field(description="Cover these vulnerabilities across products, e.g. ['CVE-2024-3094'].", max_length=20),
    ] = None,
    branch_ids: Annotated[
        list[int] | None, Field(description="Restrict to these branches of the product.", max_length=20)
    ] = None,
    fields: Annotated[
        dict[str, Any] | None,
        Field(
            description=(
                "Format-specific fields. CSAF create needs title, publisher_name, publisher_category, "
                "publisher_namespace, tracking_status, tlp_label; OpenVEX needs id_namespace and author; "
                "CycloneDX takes author and manufacturer. Read the exact set with "
                "secobserve_describe_resource on the matching vex_* resource, or from /api/oa3/swagger-ui."
            )
        ),
    ] = None,
    filename: Annotated[
        str | None,
        Field(description="Base filename for the generated document. No directory separators.", max_length=120),
    ] = None,
) -> str:
    """Generate a CSAF, OpenVEX or CycloneDX VEX document from assessed observations, or revise one.

    The document's content comes from the assessments already recorded: statuses
    like "Not affected" plus their VEX justification. Assess first, generate second.
    Passing document_base_id revises that document and bumps its version instead of
    creating a new one. The generated file is written to the server's export directory.

    Args:
        format (str): "csaf", "openvex" or "cyclonedx".
        document_id_prefix (Optional[str]): Required to create, and to identify
          a document to update.
        document_base_id (Optional[str]): Present only when updating.
        product_id (Optional[int]) and/or vulnerability_names (Optional[List[str]]):
          the scope when creating; at least one is required.
        branch_ids (Optional[List[int]]): Restrict to these branches.
        fields (Optional[dict]): Format-specific metadata (CSAF: title,
          publisher_name, publisher_category, publisher_namespace, tracking_status,
          tlp_label; OpenVEX: id_namespace, author, role; CycloneDX: author, manufacturer).
        filename (Optional[str]): Base filename for the written document.

    Returns:
        str: A line giving the absolute path and byte size of the document written
             to the export directory.

    Examples:
        - Use when: "publish an OpenVEX for product 12" -> format="openvex",
          document_id_prefix="acme-vex", product_id=12,
          fields={"id_namespace": "https://acme.example", "author": "Acme Security"}
        - Use when: "a CSAF advisory for CVE-2024-3094 across our products" ->
          format="csaf", vulnerability_names=["CVE-2024-3094"], fields={...}
        - Use when: reissuing after new assessments -> pass document_base_id.
        - Don't use when: importing someone else's VEX (use secobserve_upload_file,
          kind="vex").

    Error Handling:
        400 names the missing format-specific field; read the exact set with
        secobserve_describe_resource on the matching vex_* resource. A document with
        no qualifying assessments is generated but empty of statements.
    """
    updating = bool(document_base_id)
    if updating and not document_id_prefix:
        raise ValueError("Updating a document needs both document_id_prefix and document_base_id.")
    if not updating:
        if not document_id_prefix:
            raise ValueError("Creating a document needs document_id_prefix.")
        if not product_id and not vulnerability_names:
            raise ValueError("Creating a document needs product_id, vulnerability_names, or both.")
    body: dict[str, Any] = dict(fields or {})
    if product_id:
        body["product"] = product_id
    if vulnerability_names:
        body["vulnerability_names"] = vulnerability_names
    if branch_ids:
        body["branches"] = branch_ids

    stem = f"vex/{format}_document"
    if document_base_id:
        path = f"/{stem}/update/{document_id_prefix}/{document_base_id}/"
        body.pop("product", None)
        body.pop("vulnerability_names", None)
        body.pop("branches", None)
    else:
        body["document_id_prefix"] = document_id_prefix
        path = f"/{stem}/create/"

    content = await request("POST", path, json_body=body, expect_binary=True)
    default_name = f"{document_id_prefix}-{document_base_id or 'new'}-{format}"
    return write_export(filename or default_name, "json", content or b"")

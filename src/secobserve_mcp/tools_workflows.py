"""Validated tools for the SecObserve workflows that are worth getting right.

Everything here is reachable through secobserve_call_action, but these endpoints
carry rules an agent cannot infer from a path -- an assessment needs a comment,
it is refused while a previous one awaits approval, "Not affected" wants a VEX
justification, imports are multipart, scans block until they finish. Encoding
that in the schema and the docstring turns a class of 400s into a schema error.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .app import mcp
from .client import SecObserveError, request, tool_errors
from .exports import read_upload, write_export
from .formatting import ResponseFormat, render_object
from .types import ApprovalStatus, MetricsAge, Severity, Status, VexJustification

MAX_BULK = 250


class _Base(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")


class AssessmentFields(_Base):
    """The severity/status/priority/VEX changes an assessment may carry."""

    severity: Severity | None = Field(default=None, description="New severity. Omit to leave it as it is.")
    status: Status | None = Field(default=None, description="New status. Omit to leave it as it is.")
    priority: int | None = Field(
        default=None,
        description="New priority, 1 (most urgent) to 99. Send null to clear a priority.",
        ge=1,
        le=99,
    )
    vex_justification: VexJustification | None = Field(
        default=None,
        description=(
            "Why the finding does not apply. Expected with status 'Not affected' or "
            "'False positive' so that generated VEX documents carry a machine-readable reason."
        ),
    )
    risk_acceptance_expiry_date: str | None = Field(
        default=None,
        description="ISO date (YYYY-MM-DD) when a 'Risk accepted' status lapses back to open.",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    comment: str = Field(
        ...,
        description=(
            "Why this assessment was made. Mandatory -- it is the audit record, and "
            "approvers see only this. State the evidence, not just the verdict."
        ),
        min_length=1,
        max_length=4096,
    )

    def payload(self) -> dict[str, Any]:
        """Body for the assessment endpoints, dropping untouched fields.

        'priority' is kept when explicitly set to None, because the API reads a
        present-but-null priority as "clear it" and an absent key as "leave it".
        """
        body: dict[str, Any] = {"comment": self.comment}
        if self.severity is not None:
            body["severity"] = self.severity.value
        if self.status is not None:
            body["status"] = self.status.value
        if self.vex_justification is not None:
            body["vex_justification"] = self.vex_justification.value
        if self.risk_acceptance_expiry_date is not None:
            body["risk_acceptance_expiry_date"] = self.risk_acceptance_expiry_date
        if "priority" in self.model_fields_set:
            body["priority"] = self.priority
        return body

    @model_validator(mode="after")
    def _something_to_do(self) -> AssessmentFields:
        changed = {"severity", "status", "priority", "vex_justification", "risk_acceptance_expiry_date"}
        if not (changed & self.model_fields_set):
            raise ValueError(
                "An assessment must change at least one of severity, status, priority, "
                "vex_justification or risk_acceptance_expiry_date. To record a comment "
                "without a change there is nothing to submit."
            )
        return self


class AssessObservationInput(AssessmentFields):
    """Input model for assessing one observation."""

    observation_id: int = Field(..., description="Id of the observation to assess.", ge=1)


class BulkAssessInput(AssessmentFields):
    """Input model for assessing many observations at once."""

    observation_ids: list[int] = Field(
        ...,
        description=f"Ids to assess, 1 to {MAX_BULK} per call. Every id gets the same assessment.",
        min_length=1,
        max_length=MAX_BULK,
    )
    product_id: int | None = Field(
        default=None,
        description=(
            "Scope the call to one product's endpoint. Omit for the instance-wide endpoint. "
            "Pass it when the token is a product API token, which cannot use the instance-wide one."
        ),
        ge=1,
    )


class ApproveInput(_Base):
    """Input model for approving or rejecting pending assessments."""

    observation_log_ids: list[int] = Field(
        ...,
        description=(
            f"Observation log ids awaiting approval, 1 to {MAX_BULK}. Find them with "
            "secobserve_list(resource='observation_logs', filters={'assessment_status': 'Needs approval'})."
        ),
        min_length=1,
        max_length=MAX_BULK,
    )
    assessment_status: ApprovalStatus = Field(
        ...,
        description=(
            "'Approved' accepts the assessment as submitted, 'Approved with edits' accepts it with "
            "the observation_log_* overrides below, 'Rejected' discards it."
        ),
    )
    rejection_remark: str | None = Field(
        default=None,
        description="Why the assessment was rejected. Required when assessment_status is 'Rejected'.",
        max_length=255,
    )
    observation_log_comment: str | None = Field(
        default=None,
        description="Replacement comment, only with 'Approved with edits'.",
        max_length=4096,
    )
    observation_log_vex_justification: VexJustification | None = Field(
        default=None,
        description="Replacement VEX justification, only with 'Approved with edits' and a single id.",
    )

    @model_validator(mode="after")
    def _remark_required_for_rejection(self) -> ApproveInput:
        if self.assessment_status is ApprovalStatus.REJECTED and not self.rejection_remark:
            raise ValueError("Rejecting an assessment requires rejection_remark so the submitter knows why.")
        return self


class MetricsInput(_Base):
    """Input model for reading product metrics."""

    kind: Literal["current", "timeline", "status"] = Field(
        ...,
        description=(
            "'current' = severity and license counts as of the last calculation; "
            "'timeline' = one entry per day; 'status' = when metrics were last calculated "
            "and how often, which tells you how stale 'current' is."
        ),
    )
    product_id: int | None = Field(
        default=None,
        description=(
            "Restrict to one product, or to every product in a product group when the id is a group. "
            "Omit for the whole instance."
        ),
        ge=1,
    )
    age: MetricsAge | None = Field(
        default=None,
        description="Time window, for kind='timeline' only. Omit for the full retained history.",
    )
    response_format: ResponseFormat = Field(default=ResponseFormat.JSON, description="Output format.")


class UploadInput(_Base):
    """Input model for importing a local scan report, SBOM or VEX document."""

    kind: Literal["observations", "sbom", "vex"] = Field(
        ...,
        description=(
            "'observations' = a scanner report (Trivy, Grype, Semgrep, ZAP, ...); "
            "'sbom' = a CycloneDX or SPDX SBOM, which creates license components; "
            "'vex' = a third-party VEX document whose statements assess existing observations."
        ),
    )
    file_path: str = Field(
        ...,
        description="Path to the file, absolute or relative to the server's import directory.",
        min_length=1,
    )
    product_id: int | None = Field(default=None, description="Target product by id. Give this or product_name.", ge=1)
    product_name: str | None = Field(
        default=None,
        description="Target product by exact name. The by-name endpoints can create the branch on the fly.",
        max_length=255,
    )
    branch_id: int | None = Field(default=None, description="Target branch by id, with product_id.", ge=1)
    branch_name: str | None = Field(
        default=None,
        description="Target branch by name; created if missing. Use with product_name.",
        max_length=255,
    )
    service: str | None = Field(default=None, description="Service name to attach the findings to.", max_length=255)
    suppress_licenses: bool | None = Field(
        default=None,
        description="For kind='observations': skip license component extraction from the report.",
    )
    docker_image_name_tag: str | None = Field(
        default=None,
        description="Origin metadata: the scanned image, e.g. 'registry/app:1.2.3'.",
        max_length=513,
    )
    endpoint_url: str | None = Field(
        default=None,
        description="Origin metadata: the scanned URL, for DAST reports.",
        max_length=2048,
    )
    kubernetes_cluster: str | None = Field(default=None, description="Origin metadata: cluster.", max_length=255)
    kubernetes_namespace: str | None = Field(default=None, description="Origin metadata: namespace.", max_length=255)

    @model_validator(mode="after")
    def _one_target(self) -> UploadInput:
        if self.kind == "vex":
            return self
        if bool(self.product_id) == bool(self.product_name):
            raise ValueError("Give exactly one of product_id or product_name.")
        if self.product_id and self.branch_name:
            raise ValueError("branch_name goes with product_name; with product_id use branch_id.")
        if self.product_name and self.branch_id:
            raise ValueError("branch_id goes with product_id; with product_name use branch_name.")
        return self


class ApiImportInput(_Base):
    """Input model for pulling findings from a configured upstream API."""

    api_configuration_id: int | None = Field(
        default=None,
        description="Id of the API configuration to pull from. Give this or api_configuration_name.",
        ge=1,
    )
    api_configuration_name: str | None = Field(
        default=None,
        description="Name of the API configuration to pull from.",
        max_length=255,
    )
    branch_id: int | None = Field(default=None, description="Target branch by id, with the id form.", ge=1)
    branch_name: str | None = Field(
        default=None,
        description="Target branch by name, with the name form; created if missing.",
        max_length=255,
    )
    service: str | None = Field(default=None, description="Service name to attach the findings to.", max_length=255)
    docker_image_name_tag: str | None = Field(default=None, description="Origin metadata: image.", max_length=513)
    endpoint_url: str | None = Field(default=None, description="Origin metadata: URL.", max_length=2048)

    @model_validator(mode="after")
    def _one_configuration(self) -> ApiImportInput:
        if bool(self.api_configuration_id) == bool(self.api_configuration_name):
            raise ValueError("Give exactly one of api_configuration_id or api_configuration_name.")
        return self


class TriggerScanInput(_Base):
    """Input model for running a built-in scanner."""

    scanner: Literal["osv", "vulnerablecode"] = Field(
        ...,
        description=(
            "'osv' queries osv.dev for the product's known components; 'vulnerablecode' queries a "
            "configured VulnerableCode instance. Each must be enabled on the product first."
        ),
    )
    product_id: int = Field(..., description="Product to scan.", ge=1)
    branch_id: int | None = Field(
        default=None,
        description="Scan one branch only. Omit to scan every branch of the product.",
        ge=1,
    )


class RunPeriodicTaskInput(_Base):
    """Input model for triggering a background task."""

    task: str | None = Field(
        default=None,
        description=("Registered task name. Omit to list the names this instance accepts instead of running anything."),
        max_length=100,
    )


class StatusInput(_Base):
    """Input model for reading instance status."""

    kind: Literal["version", "health", "settings", "background_tasks", "purl_types"] = Field(
        ...,
        description=(
            "'version' = SecObserve version; 'health' = liveness; 'settings' = the feature flags and "
            "intervals this instance exposes publicly; 'background_tasks' = queue statistics (superuser); "
            "'purl_types' = the package-URL types known to the instance."
        ),
    )
    product_id: int | None = Field(
        default=None,
        description="Required for kind='purl_types': the product whose package-URL types to read.",
        ge=1,
    )
    purl_type: str | None = Field(
        default=None,
        description="With kind='purl_types': look up one type (e.g. 'maven') instead of listing all.",
        max_length=50,
    )

    @model_validator(mode="after")
    def _purl_types_need_a_product(self) -> StatusInput:
        if self.kind == "purl_types" and not self.product_id:
            raise ValueError("kind='purl_types' needs product_id; the endpoint reports 404 without it.")
        return self


class VexDocumentInput(_Base):
    """Input model for generating or revising a VEX document."""

    format: Literal["csaf", "openvex", "cyclonedx"] = Field(..., description="VEX document format to generate.")
    document_id_prefix: str | None = Field(
        default=None,
        description="Prefix of the document id. Required when creating, and to identify the document when updating.",
        max_length=200,
    )
    document_base_id: str | None = Field(
        default=None,
        description="The generated base id. Required only when updating an existing document.",
        max_length=200,
    )
    product_id: int | None = Field(
        default=None,
        description="Cover one product. Give product_id or vulnerability_names (or both) when creating.",
        ge=1,
    )
    vulnerability_names: list[str] | None = Field(
        default=None,
        description="Cover these vulnerabilities across products, e.g. ['CVE-2024-3094'].",
        max_length=20,
    )
    branch_ids: list[int] | None = Field(
        default=None,
        description="Restrict to these branches of the product.",
        max_length=20,
    )
    fields: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Format-specific fields. CSAF create needs title, publisher_name, publisher_category, "
            "publisher_namespace, tracking_status, tlp_label; OpenVEX needs id_namespace and author; "
            "CycloneDX takes author and manufacturer. Read the exact set with "
            "secobserve_describe_resource on the matching vex_* resource, or from /api/oa3/swagger-ui."
        ),
    )
    filename: str | None = Field(
        default=None,
        description="Base filename for the generated document. No directory separators.",
        max_length=120,
    )

    @model_validator(mode="after")
    def _scope_given(self) -> VexDocumentInput:
        updating = bool(self.document_base_id)
        if updating and not self.document_id_prefix:
            raise ValueError("Updating a document needs both document_id_prefix and document_base_id.")
        if not updating:
            if not self.document_id_prefix:
                raise ValueError("Creating a document needs document_id_prefix.")
            if not self.product_id and not self.vulnerability_names:
                raise ValueError("Creating a document needs product_id, vulnerability_names, or both.")
        return self


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
async def secobserve_assess_observation(params: AssessObservationInput) -> str:
    """Record a human assessment on one observation: change its severity, status, priority or VEX justification.

    This is how triage is done. It writes an observation log, so the change is
    attributable and reversible, and it is what later VEX documents are generated
    from. Never edit an observation's severity or status with secobserve_update --
    that bypasses the log and the approval workflow.

    Two rules the API enforces: a comment is mandatory, and a new assessment is
    refused while the previous one is still in 'Needs approval'.

    Args:
        params (AssessObservationInput): Validated input containing:
            - observation_id (int): Observation to assess.
            - severity (Optional[Severity]): Unknown/None/Low/Medium/High/Critical.
            - status (Optional[Status]): Open/Affected/Resolved/Duplicate/False positive/
              In review/Not affected/Not security/Risk accepted.
            - priority (Optional[int]): 1-99, or null to clear.
            - vex_justification (Optional[VexJustification]): Machine-readable reason,
              expected with 'Not affected' and 'False positive'.
            - risk_acceptance_expiry_date (Optional[str]): YYYY-MM-DD, for 'Risk accepted'.
            - comment (str): Mandatory rationale, 1-4096 characters.

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
    await request("PATCH", f"/observations/{params.observation_id}/assessment/", json_body=params.payload())
    changed = ", ".join(k for k in params.payload() if k != "comment") or "nothing"
    return (
        f"Assessed observation {params.observation_id} ({changed}). "
        "If this instance requires four-eyes approval, the assessment is now in 'Needs approval' -- "
        "check with secobserve_list(resource='observation_logs', "
        f"filters={{'observation': {params.observation_id}}})."
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
async def secobserve_bulk_assess_observations(params: BulkAssessInput) -> str:
    """Apply one identical assessment to up to 250 observations by id.

    The comment is stored on every one of them, so write it to be true of the whole
    set. Get the ids from secobserve_list with response_format="json" and
    fields=["id"]; a filter that matches more than 250 rows needs several calls.

    Args:
        params (BulkAssessInput): Validated input containing:
            - observation_ids (List[int]): 1-250 observation ids.
            - product_id (Optional[int]): Use the product-scoped endpoint instead of
              the instance-wide one; required for product API tokens.
            - severity, status, priority, vex_justification,
              risk_acceptance_expiry_date: as in secobserve_assess_observation.
            - comment (str): Mandatory rationale applied to every observation.

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
    body = params.payload()
    if params.product_id:
        body["observations"] = params.observation_ids
        path = f"/products/{params.product_id}/observations_bulk_assessment/"
    else:
        body["observations"] = params.observation_ids
        path = "/observations/bulk_assessment/"

    await request("POST", path, json_body=body)
    changed = ", ".join(k for k in body if k not in {"comment", "observations"}) or "nothing"
    return (
        f"Submitted a bulk assessment for {len(params.observation_ids)} observations ({changed}) via {path}. "
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
async def secobserve_approve_observation_log(params: ApproveInput) -> str:
    """Approve or reject assessments waiting in 'Needs approval' (the four-eyes workflow).

    Only an approver other than the submitter can clear a pending assessment, and
    until it is cleared the observation accepts no further assessment. Rejection
    requires a remark, which is what the submitter sees.

    Args:
        params (ApproveInput): Validated input containing:
            - observation_log_ids (List[int]): 1-250 pending observation log ids.
            - assessment_status (ApprovalStatus): "Approved", "Approved with edits"
              or "Rejected".
            - rejection_remark (Optional[str]): Required when rejecting.
            - observation_log_comment (Optional[str]): Replacement comment, only with
              "Approved with edits".
            - observation_log_vex_justification (Optional[VexJustification]):
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
    body: dict[str, Any] = {"assessment_status": params.assessment_status.value}
    if params.rejection_remark:
        body["rejection_remark"] = params.rejection_remark
    if params.observation_log_comment:
        body["observation_log_comment"] = params.observation_log_comment
    if params.observation_log_vex_justification:
        body["observation_log_vex_justification"] = params.observation_log_vex_justification.value

    if len(params.observation_log_ids) == 1:
        log_id = params.observation_log_ids[0]
        await request("PATCH", f"/observation_logs/{log_id}/approval/", json_body=body)
        return f"Recorded '{params.assessment_status.value}' on observation log {log_id}."

    if params.observation_log_vex_justification:
        raise SecObserveError(
            "observation_log_vex_justification applies to a single assessment. "
            "Call this tool once per log, or drop the justification override."
        )
    body["observation_logs"] = params.observation_log_ids
    await request("POST", "/observation_logs/bulk_approval/", json_body=body)
    return (
        f"Recorded '{params.assessment_status.value}' on {len(params.observation_log_ids)} observation logs. "
        "Logs that were no longer pending are skipped by the backend."
    )


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
async def secobserve_product_metrics(params: MetricsInput) -> str:
    """Read pre-aggregated observation and license counts for a product, a group, or the whole instance.

    Far cheaper than counting rows with secobserve_list: these come from the
    metrics tables a background job maintains. That also means they are as old as
    the last calculation -- kind="status" tells you how old, and is worth reading
    before quoting a number as current.

    Args:
        params (MetricsInput): Validated input containing:
            - kind (str): "current", "timeline" or "status".
            - product_id (Optional[int]): One product, or every product in a group
              when the id is a product group. Omit for the instance.
            - age (Optional[MetricsAge]): Window for "timeline": "Past 7 days",
              "Past 30 days", "Past 90 days", "Past 365 days".
            - response_format (ResponseFormat): "json" (default) or "markdown".

    Returns:
        str: For kind="current", a JSON object of counts keyed by severity
             (open_critical, open_high, ...) and by license evaluation result.
             For kind="timeline", a JSON object keyed by ISO date, each value the
             counts for that day. For kind="status",
             {"last_calculated": ISO timestamp, "calculation_interval": minutes}.

    Examples:
        - Use when: "how many critical findings are open in product 12?" ->
          kind="current", product_id=12
        - Use when: "is our backlog growing?" -> kind="timeline", age="Past 90 days"
        - Use when: a metric looks wrong -> kind="status", to check the job has run.
        - Don't use when: you need the findings themselves (use secobserve_list).

    Error Handling:
        403 means no view permission on the product. An empty timeline usually
        means the metrics job has not run yet for that window -- check kind="status".
    """
    if params.kind == "status":
        payload = await request("GET", "/metrics/product_metrics_status/")
    elif params.kind == "current":
        payload = await request("GET", "/metrics/product_metrics_current/", params={"product_id": params.product_id})
    else:
        payload = await request(
            "GET",
            "/metrics/product_metrics_timeline/",
            params={"product_id": params.product_id, "age": params.age.value if params.age else None},
        )

    if params.response_format is ResponseFormat.JSON:
        return json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    scope = f"product {params.product_id}" if params.product_id else "all products"
    if isinstance(payload, dict):
        return render_object(
            payload, title=f"Metrics ({params.kind}, {scope})", response_format=ResponseFormat.MARKDOWN
        )
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
async def secobserve_upload_file(params: UploadInput) -> str:
    """Import a local scanner report, SBOM or VEX document into SecObserve.

    This is the correct way to get findings in: the import deduplicates against
    existing observations, applies rules, resolves findings that disappeared from
    the report, and records a vulnerability check. Creating observations by hand
    with secobserve_create does none of that.

    The file must live under the server's import directory (SECOBSERVE_IMPORT_DIR,
    the working directory by default) and be at most 64 MiB.

    Args:
        params (UploadInput): Validated input containing:
            - kind (str): "observations", "sbom" or "vex".
            - file_path (str): Path to the report, absolute or relative to the import directory.
            - product_id (Optional[int]) / product_name (Optional[str]): exactly one,
              ignored for kind="vex" which matches on the document's own product data.
            - branch_id (Optional[int]) with product_id, or branch_name (Optional[str])
              with product_name; a named branch is created if missing.
            - service (Optional[str]): Service to attach findings to.
            - suppress_licenses (Optional[bool]): kind="observations" only.
            - docker_image_name_tag / endpoint_url / kubernetes_cluster /
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
    filename, content = read_upload(params.file_path)

    if params.kind == "vex":
        payload = await request("POST", "/vex/vex_import/", files={"file": (filename, content)})
        return _summarise_import(payload, f"Imported VEX document {filename}.")

    by_name = bool(params.product_name)
    if params.kind == "sbom":
        path = "/import/file_upload_sbom_by_name/" if by_name else "/import/file_upload_sbom_by_id/"
    else:
        path = "/import/file_upload_observations_by_name/" if by_name else "/import/file_upload_observations_by_id/"

    form: dict[str, Any] = {}
    if by_name:
        form["product_name"] = params.product_name
        if params.branch_name:
            form["branch_name"] = params.branch_name
    else:
        form["product"] = params.product_id
        if params.branch_id:
            form["branch"] = params.branch_id
    if params.service:
        form["service"] = params.service
    if params.kind == "observations" and params.suppress_licenses is not None:
        form["suppress_licenses"] = params.suppress_licenses
    for key in ("docker_image_name_tag", "endpoint_url", "kubernetes_cluster", "kubernetes_namespace"):
        value = getattr(params, key)
        if value:
            form[key] = value

    payload = await request("POST", path, files={"file": (filename, content)}, data=form)
    return _summarise_import(payload, f"Imported {filename} as {params.kind} via {path}.")


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
async def secobserve_api_import(params: ApiImportInput) -> str:
    """Pull findings into SecObserve from an upstream API it already has credentials for.

    The credentials, base URL and parser come from an API configuration stored on
    the product; list them with secobserve_list(resource="api_configurations").
    The call blocks while SecObserve fetches and parses, so it can take a while.

    Args:
        params (ApiImportInput): Validated input containing:
            - api_configuration_id (Optional[int]) or api_configuration_name
              (Optional[str]): exactly one.
            - branch_id (Optional[int]) with the id form, or branch_name
              (Optional[str]) with the name form; a named branch is created if missing.
            - service (Optional[str]): Service to attach findings to.
            - docker_image_name_tag / endpoint_url (Optional[str]): origin metadata.

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
    by_name = bool(params.api_configuration_name)
    path = "/import/api_import_observations_by_name/" if by_name else "/import/api_import_observations_by_id/"

    body: dict[str, Any] = {}
    if by_name:
        body["api_configuration_name"] = params.api_configuration_name
        if params.branch_name:
            body["branch_name"] = params.branch_name
    else:
        body["api_configuration"] = params.api_configuration_id
        if params.branch_id:
            body["branch"] = params.branch_id
    if params.service:
        body["service"] = params.service
    if params.docker_image_name_tag:
        body["docker_image_name_tag"] = params.docker_image_name_tag
    if params.endpoint_url:
        body["endpoint_url"] = params.endpoint_url

    payload = await request("POST", path, json_body=body)
    target = params.api_configuration_name or params.api_configuration_id
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
async def secobserve_trigger_scan(params: TriggerScanInput) -> str:
    """Run SecObserve's own OSV or VulnerableCode scan over a product's known components.

    These scanners need no report: they look up the components SecObserve already
    has, which is why they are the usual follow-up to an SBOM import. Each must be
    enabled on the product (osv_enabled / vulnerablecode_enabled) or the call is
    rejected. The request blocks until the scan finishes, so a product with many
    components can exceed the HTTP timeout.

    Args:
        params (TriggerScanInput): Validated input containing:
            - scanner (str): "osv" or "vulnerablecode".
            - product_id (int): Product to scan.
            - branch_id (Optional[int]): One branch, or every branch when omitted.

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
    suffix = f"scan_{'osv' if params.scanner == 'osv' else 'vulnerablecode'}"
    path = (
        f"/products/{params.product_id}/{params.branch_id}/{suffix}/"
        if params.branch_id
        else f"/products/{params.product_id}/{suffix}/"
    )
    payload = await request("POST", path)
    scope = f"branch {params.branch_id}" if params.branch_id else "all branches"
    return _summarise_import(payload, f"{params.scanner} scan of product {params.product_id} ({scope}) finished.")


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
async def secobserve_run_periodic_task(params: RunPeriodicTaskInput) -> str:
    """Trigger one of SecObserve's scheduled background jobs now, or list which jobs exist.

    Useful when a metric looks stale or housekeeping has not run. The task is
    queued, not executed inline: the call returns immediately and the outcome shows
    up in secobserve_list(resource="periodic_tasks"). Only one instance of a task
    runs at a time.

    Args:
        params (RunPeriodicTaskInput): Validated input containing:
            - task (Optional[str]): Registered task name. Omit to list the accepted
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
    if not params.task:
        payload = await request("GET", "/periodic_tasks/registered_tasks/")
        return json.dumps(payload, indent=2, ensure_ascii=False, default=str)

    await request("POST", "/periodic_tasks/run/", json_body={"task": params.task})
    return (
        f"Queued background task '{params.task}'. Watch it with "
        f"secobserve_list(resource='periodic_tasks', filters={{'task': '{params.task}'}}, ordering='-start_time')."
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
async def secobserve_status(params: StatusInput) -> str:
    """Read instance-level facts: version, health, public settings, queue statistics, PURL types.

    Worth calling once at the start of a session: the version decides which
    features exist, and the settings say whether four-eyes approval, license
    management or the built-in scanners are switched on at all.

    Args:
        params (StatusInput): Validated input containing:
            - kind (str): "version", "health", "settings", "background_tasks" or "purl_types".
            - product_id (Optional[int]): Required for kind="purl_types".
            - purl_type (Optional[str]): With kind="purl_types", look up one type.

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
    query: dict[str, Any] | None = None
    if params.kind == "purl_types":
        path = f"/purl_types/{params.purl_type}/" if params.purl_type else "/purl_types/"
        query = {"product": params.product_id}
    else:
        path = {
            "version": "/status/version/",
            "health": "/status/health/",
            "settings": "/status/settings/",
            "background_tasks": "/status/background_task_statistics/",
        }[params.kind]

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
async def secobserve_vex_document(params: VexDocumentInput) -> str:
    """Generate a CSAF, OpenVEX or CycloneDX VEX document from assessed observations, or revise one.

    The document's content comes from the assessments already recorded: statuses
    like "Not affected" plus their VEX justification. Assess first, generate second.
    Passing document_base_id revises that document and bumps its version instead of
    creating a new one. The generated file is written to the server's export directory.

    Args:
        params (VexDocumentInput): Validated input containing:
            - format (str): "csaf", "openvex" or "cyclonedx".
            - document_id_prefix (Optional[str]): Required to create, and to identify
              a document to update.
            - document_base_id (Optional[str]): Present only when updating.
            - product_id (Optional[int]) and/or vulnerability_names (Optional[List[str]]):
              the scope when creating; at least one is required.
            - branch_ids (Optional[List[int]]): Restrict to these branches.
            - fields (Optional[dict]): Format-specific metadata (CSAF: title,
              publisher_name, publisher_category, publisher_namespace, tracking_status,
              tlp_label; OpenVEX: id_namespace, author, role; CycloneDX: author, manufacturer).
            - filename (Optional[str]): Base filename for the written document.

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
    body: dict[str, Any] = dict(params.fields or {})
    if params.product_id:
        body["product"] = params.product_id
    if params.vulnerability_names:
        body["vulnerability_names"] = params.vulnerability_names
    if params.branch_ids:
        body["branches"] = params.branch_ids

    stem = f"vex/{params.format}_document"
    if params.document_base_id:
        path = f"/{stem}/update/{params.document_id_prefix}/{params.document_base_id}/"
        body.pop("product", None)
        body.pop("vulnerability_names", None)
        body.pop("branches", None)
    else:
        body["document_id_prefix"] = params.document_id_prefix
        path = f"/{stem}/create/"

    content = await request("POST", path, json_body=body, expect_binary=True)
    default_name = f"{params.document_id_prefix}-{params.document_base_id or 'new'}-{params.format}"
    return write_export(params.filename or default_name, "json", content or b"")

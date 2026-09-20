"""Catalogue of SecObserve API resources, their operations and custom actions.

The registry is what makes generic CRUD tools usable: it tells the agent which
resources exist, which verbs each one accepts, and which named actions hang off
it. `list_fields` is the default projection for list results -- an Observation
row carries ~100 columns, so listing unprojected rows would swamp the context.

Exact filters and field schemas are NOT duplicated here; they are read from the
live OpenAPI schema at /api/oa3/schema/ by secobserve_describe_resource, so the
catalogue cannot drift from the deployed backend.
"""

from __future__ import annotations

from dataclasses import dataclass, field

LIST = "list"
GET = "get"
CREATE = "create"
UPDATE = "update"
DELETE = "delete"

READ = frozenset({LIST, GET})
READ_DELETE = frozenset({LIST, GET, DELETE})
CRUD = frozenset({LIST, GET, CREATE, UPDATE, DELETE})


@dataclass(frozen=True)
class Action:
    """A non-CRUD endpoint hanging off a resource."""

    name: str
    method: str
    detail: bool
    summary: str
    binary: bool = False


@dataclass(frozen=True)
class Resource:
    path: str
    ops: frozenset[str]
    summary: str
    list_fields: tuple[str, ...] = ()
    label: str = "name"
    actions: tuple[Action, ...] = field(default_factory=tuple)

    def action(self, name: str) -> Action | None:
        for candidate in self.actions:
            if candidate.name == name:
                return candidate
        return None


OBSERVATION_LIST_FIELDS = (
    "id",
    "title",
    "current_severity",
    "current_status",
    "current_priority",
    "product_data.name",
    "branch_name",
    "vulnerability_id",
    "origin_component_name_version",
    "scanner_name",
    "epss_score",
    "fix_available",
    "has_potential_duplicates",
    "last_observation_log",
)

PRODUCT_LIST_FIELDS = (
    "id",
    "name",
    "product_group_name",
    "security_gate_passed",
    "last_observation_change",
    "active_critical_observation_count",
    "active_high_observation_count",
    "active_medium_observation_count",
    "active_low_observation_count",
)

LICENSE_COMPONENT_LIST_FIELDS = (
    "id",
    "component_name_version",
    "effective_license_name",
    "evaluation_result",
    "product_name",
    "branch_name",
    "origin_service_name",
)

OBSERVATION_LOG_FIELDS = (
    "id",
    "observation",
    "user_full_name",
    "severity",
    "status",
    "priority",
    "assessment_status",
    "comment",
    "created",
)

RESOURCES: dict[str, Resource] = {
    # --- access control -----------------------------------------------------
    "users": Resource(
        path="/users/",
        ops=CRUD,
        summary="User accounts.",
        list_fields=("id", "username", "full_name", "email", "is_active", "is_superuser", "is_external"),
        label="full_name",
        actions=(
            Action("me", "GET", False, "The authenticated user's own profile and permissions."),
            Action("my_settings", "PATCH", False, "Update the authenticated user's own settings."),
            Action("change_password", "PATCH", True, "Change a user's password."),
            Action("password_rules", "GET", False, "Password complexity rules enforced by this instance."),
        ),
    ),
    "authorization_groups": Resource(
        path="/authorization_groups/",
        ops=CRUD,
        summary="Groups used to grant product roles to many users at once.",
        list_fields=("id", "name", "oidc_group", "is_active"),
    ),
    "authorization_group_members": Resource(
        path="/authorization_group_members/",
        ops=CRUD,
        summary="Membership of users in authorization groups.",
        list_fields=("id", "authorization_group", "user", "is_manager"),
        label="id",
    ),
    "api_tokens": Resource(
        path="/api_tokens/",
        ops=frozenset({LIST}),
        summary="User API tokens (metadata only; token values are never returned).",
        list_fields=("id", "name"),
    ),
    "product_api_tokens": Resource(
        path="/product_api_tokens/",
        ops=frozenset({LIST, CREATE, DELETE}),
        summary="Per-product API tokens. Creating one returns the secret exactly once.",
        list_fields=("id", "product", "role"),
        label="id",
    ),
    # --- products -----------------------------------------------------------
    "products": Resource(
        path="/products/",
        ops=CRUD,
        summary="Products: the unit of access control, scanning and reporting.",
        list_fields=PRODUCT_LIST_FIELDS,
        actions=(
            Action("apply_rules", "POST", True, "Re-apply all rules to the product's observations."),
            Action("observations_bulk_assessment", "POST", True, "Assess many observations of this product."),
            Action("observations_bulk_mark_duplicates", "POST", True, "Mark listed observations as duplicates."),
            Action("observations_bulk_delete", "POST", True, "Delete listed observations of this product."),
            Action("license_components_bulk_delete", "POST", True, "Delete listed license components."),
            Action("synchronize_issues", "POST", True, "Push observations to the configured issue tracker."),
            Action("export_observations_excel", "GET", True, "Observations as XLSX.", binary=True),
            Action("export_observations_csv", "GET", True, "Observations as CSV.", binary=True),
            Action("export_license_components_excel", "GET", True, "License components as XLSX.", binary=True),
            Action("export_license_components_csv", "GET", True, "License components as CSV.", binary=True),
        ),
    ),
    "product_groups": Resource(
        path="/product_groups/",
        ops=CRUD,
        summary="Product groups: containers that own products and share a license policy.",
        list_fields=("id", "name", "products_count", "license_policy"),
    ),
    "product_names": Resource(
        path="/product_names/",
        ops=READ,
        summary="Id/name pairs of products. Cheapest way to resolve a product name to an id.",
        list_fields=("id", "name"),
    ),
    "product_group_names": Resource(
        path="/product_group_names/",
        ops=READ,
        summary="Id/name pairs of product groups.",
        list_fields=("id", "name"),
    ),
    "product_members": Resource(
        path="/product_members/",
        ops=CRUD,
        summary="Direct user membership and role on a product.",
        list_fields=("id", "product", "user", "role"),
        label="id",
    ),
    "product_authorization_group_members": Resource(
        path="/product_authorization_group_members/",
        ops=CRUD,
        summary="Authorization-group membership and role on a product.",
        list_fields=("id", "product", "authorization_group", "role"),
        label="id",
    ),
    "branches": Resource(
        path="/branches/",
        ops=CRUD,
        summary="Branches or versions of a product; observations are scoped to one.",
        list_fields=("id", "name", "product", "is_default_branch", "last_import", "housekeeping_protect"),
    ),
    "branch_names": Resource(
        path="/branch_names/",
        ops=READ,
        summary="Id/name pairs of branches.",
        list_fields=("id", "name"),
    ),
    "services": Resource(
        path="/services/",
        ops=CRUD,
        summary="Services within a product, used to group observations.",
        list_fields=("id", "name", "product"),
    ),
    "service_names": Resource(
        path="/service_names/",
        ops=READ,
        summary="Id/name pairs of services.",
        list_fields=("id", "name"),
    ),
    # --- metrics ------------------------------------------------------------
    "metrics": Resource(
        path="/metrics/",
        ops=frozenset(),
        summary="File exports of product metrics; read the numbers themselves with secobserve_product_metrics.",
        actions=(
            Action(
                "export_excel",
                "GET",
                False,
                "Product metrics as XLSX. Scope it with params={'product_id': N}; the endpoint reads that one "
                "parameter and ignores every other name, so a typo exports the whole instance instead of failing.",
                binary=True,
            ),
            Action(
                "export_csv",
                "GET",
                False,
                "Product metrics as CSV. Scope it with params={'product_id': N}; the endpoint reads that one "
                "parameter and ignores every other name, so a typo exports the whole instance instead of failing.",
                binary=True,
            ),
            Action(
                "export_codecharta",
                "GET",
                False,
                "Per-source-file counts for the product's default branch, as CodeCharta CSV. "
                "params={'product_id': N} is required here and the call fails without it, but any other parameter "
                "name is still ignored rather than reported.",
                binary=True,
            ),
        ),
    ),
    # --- observations -------------------------------------------------------
    "observations": Resource(
        path="/observations/",
        ops=CRUD,
        summary="Observations: the findings imported from scanners. The main triage resource.",
        list_fields=OBSERVATION_LIST_FIELDS,
        label="title",
        actions=(
            Action("assessment", "PATCH", True, "Assess one observation; prefer secobserve_assess_observation."),
            Action("remove_assessment", "PATCH", True, "Drop a manual assessment and fall back to parser values."),
            Action("bulk_assessment", "POST", False, "Assess up to 250 observations by id."),
            Action("count_reviews", "GET", False, "Number of observations in status 'In review'."),
            Action("export_excel", "GET", False, "Filtered observations as XLSX.", binary=True),
            Action("export_csv", "GET", False, "Filtered observations as CSV.", binary=True),
        ),
    ),
    "observation_titles": Resource(
        path="/observation_titles/",
        ops=READ,
        summary="Distinct observation titles, for building filters.",
        list_fields=("id", "title"),
        label="title",
    ),
    "observation_logs": Resource(
        path="/observation_logs/",
        ops=READ,
        summary="Assessment history of observations, including approval state.",
        list_fields=OBSERVATION_LOG_FIELDS,
        label="id",
        actions=(
            Action("approval", "PATCH", True, "Approve or reject one pending assessment."),
            Action("bulk_approval", "POST", False, "Approve or reject up to 250 pending assessments."),
            Action("count_approvals", "GET", False, "Number of assessments awaiting approval."),
            Action("bulk_delete", "DELETE", False, "Delete up to 250 observation logs."),
        ),
    ),
    "evidences": Resource(
        path="/evidences/",
        ops=READ,
        summary="Raw scanner evidence attached to an observation.",
        list_fields=("id", "name", "observation"),
    ),
    "potential_duplicates": Resource(
        path="/potential_duplicates/",
        ops=frozenset({LIST}),
        summary="Observations the deduplication pass considers potential duplicates of each other.",
        list_fields=("id", "observation", "potential_duplicate_observation"),
        label="id",
    ),
    "components": Resource(
        path="/components/",
        ops=READ,
        summary="Software components seen in SBOMs and scans.",
        list_fields=("id", "name_version", "purl", "cpe"),
        label="name_version",
    ),
    "component_names": Resource(
        path="/component_names/",
        ops=READ,
        summary="Distinct component names.",
        list_fields=("id", "name"),
    ),
    # --- import -------------------------------------------------------------
    "parsers": Resource(
        path="/parsers/",
        ops=READ,
        summary="Supported scanners and their parser type. Read this before an import.",
        list_fields=("id", "name", "type", "source"),
    ),
    "api_configurations": Resource(
        path="/api_configurations/",
        ops=CRUD,
        summary="Stored credentials for pull-based imports (Dependency Track, Trivy server, ...).",
        list_fields=("id", "name", "product", "parser", "base_url", "project_key"),
    ),
    "vulnerability_checks": Resource(
        path="/vulnerability_checks/",
        ops=READ,
        summary="One row per completed import: what was scanned, when, and the resulting counts.",
        list_fields=(
            "id",
            "product",
            "branch",
            "filename",
            "api_configuration_name",
            "scanner",
            "last_import_observations_new",
            "last_import_observations_updated",
            "last_import_observations_resolved",
        ),
        label="id",
    ),
    # --- rules --------------------------------------------------------------
    "general_rules": Resource(
        path="/general_rules/",
        ops=CRUD,
        summary="Instance-wide rules that rewrite severity/status/priority on import.",
        list_fields=("id", "name", "enabled", "approval_status", "new_severity", "new_status", "new_priority"),
        actions=(
            Action("approval", "PATCH", True, "Approve or reject a rule awaiting approval."),
            Action("simulate", "POST", True, "Count observations an unsaved rule definition would match."),
            Action("evaluate", "POST", True, "Re-apply this rule to existing observations."),
        ),
    ),
    "product_rules": Resource(
        path="/product_rules/",
        ops=CRUD,
        summary="Product-scoped rules; they take precedence over general rules.",
        list_fields=("id", "name", "product", "enabled", "approval_status", "new_severity", "new_status"),
        actions=(
            Action("approval", "PATCH", True, "Approve or reject a rule awaiting approval."),
            Action("simulate", "POST", True, "Count observations an unsaved rule definition would match."),
        ),
    ),
    # --- licenses -----------------------------------------------------------
    "licenses": Resource(
        path="/licenses/",
        ops=READ,
        summary="The SPDX license list as shipped with this instance.",
        list_fields=("id", "spdx_id", "name", "is_osi_approved", "is_deprecated"),
        label="spdx_id",
    ),
    "license_components": Resource(
        path="/license_components/",
        ops=READ,
        summary="Components with their effective license and license-policy verdict.",
        list_fields=LICENSE_COMPONENT_LIST_FIELDS,
        label="component_name_version",
        actions=(
            Action("concluded_license", "PATCH", True, "Override the detected license for one component."),
            Action(
                "license_overview",
                "GET",
                False,
                "Counts grouped by license. Requires params={'product': <id>}; optional 'branch'.",
            ),
        ),
    ),
    "license_component_ids": Resource(
        path="/license_component_ids/",
        ops=READ,
        summary="Ids only of the filtered license components; use before a bulk delete.",
        list_fields=("id",),
        label="id",
    ),
    "license_component_evidences": Resource(
        path="/license_component_evidences/",
        ops=READ,
        summary="Evidence backing a license component's detected license.",
        list_fields=("id", "name", "license_component"),
    ),
    "concluded_licenses": Resource(
        path="/concluded_licenses/",
        ops=READ_DELETE,
        summary="Manual license conclusions that survive re-imports.",
        list_fields=("id", "purl", "concluded_license_name", "comment"),
        label="purl",
    ),
    "license_groups": Resource(
        path="/license_groups/",
        ops=CRUD,
        summary="Named sets of licenses referenced by license policies.",
        list_fields=("id", "name", "is_public", "description"),
        actions=(
            Action("copy", "POST", True, "Copy this group, including its licenses."),
            Action("add_license", "POST", True, "Add one license to the group."),
            Action("remove_license", "POST", True, "Remove one license from the group."),
        ),
    ),
    "license_group_members": Resource(
        path="/license_group_members/",
        ops=CRUD,
        summary="Users who may manage a license group.",
        list_fields=("id", "license_group", "user", "is_manager"),
        label="id",
    ),
    "license_group_authorization_group_members": Resource(
        path="/license_group_authorization_group_members/",
        ops=CRUD,
        summary="Authorization groups that may manage a license group.",
        list_fields=("id", "license_group", "authorization_group", "is_manager"),
        label="id",
    ),
    "license_policies": Resource(
        path="/license_policies/",
        ops=CRUD,
        summary="Policies deciding whether a license is allowed, forbidden or needs review.",
        list_fields=("id", "name", "is_public", "ignore_component_types"),
        actions=(
            Action("copy", "POST", True, "Copy this policy and its items."),
            Action("apply", "POST", True, "Re-evaluate every product using this policy."),
            Action("apply_product", "POST", False, "Re-evaluate one product's license components."),
            Action("export_json", "GET", True, "Policy as JSON.", binary=True),
            Action("export_yaml", "GET", True, "Policy as YAML.", binary=True),
            Action("export_sbom_utility", "GET", True, "Policy in sbom-utility format.", binary=True),
        ),
    ),
    "license_policy_items": Resource(
        path="/license_policy_items/",
        ops=CRUD,
        summary="Individual allow/forbid/review entries of a license policy.",
        list_fields=(
            "id",
            "license_policy",
            "license_group",
            "license",
            "non_spdx_license",
            "license_expression",
            "evaluation_result",
        ),
        label="id",
    ),
    "license_policy_members": Resource(
        path="/license_policy_members/",
        ops=CRUD,
        summary="Users who may manage a license policy.",
        list_fields=("id", "license_policy", "user", "is_manager"),
        label="id",
    ),
    "license_policy_authorization_group_members": Resource(
        path="/license_policy_authorization_group_members/",
        ops=CRUD,
        summary="Authorization groups that may manage a license policy.",
        list_fields=("id", "license_policy", "authorization_group", "is_manager"),
        label="id",
    ),
    # --- notifications ------------------------------------------------------
    "notifications": Resource(
        path="/notifications/",
        ops=READ_DELETE,
        summary="Instance notifications: exceptions, security gate changes, task failures.",
        list_fields=("id", "name", "type", "created", "product", "user", "message"),
        actions=(
            Action("mark_as_viewed", "POST", True, "Mark one notification as viewed."),
            Action("bulk_mark_as_viewed", "POST", False, "Mark listed notifications as viewed."),
            Action("test_webhook", "POST", False, "Send a test message to a configured webhook."),
        ),
    ),
    "product_notifications": Resource(
        path="/product_notifications/",
        ops=frozenset({LIST, UPDATE}),
        summary="Per-product notification configuration.",
        list_fields=("id", "product", "notification_type", "enabled"),
        label="id",
        actions=(
            Action("template", "GET", False, "The default notification template."),
            Action("for_product", "GET", False, "Effective configuration for one product."),
            Action("override", "POST", False, "Create (POST) or clear (DELETE) a product override."),
        ),
    ),
    # --- background tasks ---------------------------------------------------
    "periodic_tasks": Resource(
        path="/periodic_tasks/",
        ops=READ,
        summary="History of background jobs: metrics, housekeeping, EPSS, OSV scans.",
        list_fields=("id", "task", "status", "start_time", "end_time", "message"),
        label="task",
        actions=(
            Action("registered_tasks", "GET", False, "Names of tasks that can be triggered."),
            Action("run", "POST", False, "Trigger one task now; 409 while it is already running."),
        ),
    ),
    # --- instance settings --------------------------------------------------
    "settings": Resource(
        path="/settings/",
        ops=frozenset({GET, UPDATE}),
        summary="Instance-wide settings. A singleton: always use id=1. Superuser only.",
        label="id",
    ),
    # --- VEX ----------------------------------------------------------------
    "vex_csaf": Resource(
        path="/vex/csaf/",
        ops=READ_DELETE,
        summary="Generated CSAF documents.",
        list_fields=("id", "document_id_prefix", "document_base_id", "version", "title", "product_data.name"),
        label="title",
    ),
    "vex_csaf_vulnerabilities": Resource(
        path="/vex/csaf_vulnerabilities/",
        ops=READ,
        summary="Vulnerabilities pinned into a CSAF document.",
        list_fields=("id", "csaf", "name"),
    ),
    "vex_csaf_branches": Resource(
        path="/vex/csaf_branches/",
        ops=READ,
        summary="Branches pinned into a CSAF document.",
        list_fields=("id", "csaf", "branch"),
        label="id",
    ),
    "vex_openvex": Resource(
        path="/vex/openvex/",
        ops=READ_DELETE,
        summary="Generated OpenVEX documents.",
        list_fields=("id", "document_id_prefix", "document_base_id", "version", "author", "product_data.name"),
        label="document_base_id",
    ),
    "vex_openvex_vulnerabilities": Resource(
        path="/vex/openvex_vulnerabilities/",
        ops=READ,
        summary="Vulnerabilities pinned into an OpenVEX document.",
        list_fields=("id", "openvex", "name"),
    ),
    "vex_openvex_branches": Resource(
        path="/vex/openvex_branches/",
        ops=READ,
        summary="Branches pinned into an OpenVEX document.",
        list_fields=("id", "openvex", "branch"),
        label="id",
    ),
    "vex_cyclonedx": Resource(
        path="/vex/cyclonedx/",
        ops=READ_DELETE,
        summary="Generated CycloneDX VEX documents.",
        list_fields=("id", "document_id_prefix", "document_base_id", "version", "author", "product_data.name"),
        label="document_base_id",
    ),
    "vex_cyclonedx_vulnerabilities": Resource(
        path="/vex/cyclonedx_vulnerabilities/",
        ops=READ,
        summary="Vulnerabilities pinned into a CycloneDX VEX document.",
        list_fields=("id", "cyclonedx", "name"),
    ),
    "vex_cyclonedx_branches": Resource(
        path="/vex/cyclonedx_branches/",
        ops=READ,
        summary="Branches pinned into a CycloneDX VEX document.",
        list_fields=("id", "cyclonedx", "branch"),
        label="id",
    ),
    "vex_counters": Resource(
        path="/vex/vex_counters/",
        ops=CRUD,
        summary="Sequence counters backing generated VEX document ids.",
        list_fields=("id", "document_id_prefix", "year", "counter"),
        label="document_id_prefix",
    ),
    "vex_documents": Resource(
        path="/vex/vex_documents/",
        ops=READ_DELETE,
        summary="Imported third-party VEX documents.",
        list_fields=("id", "document_id", "author", "version", "product"),
        label="document_id",
    ),
    "vex_statements": Resource(
        path="/vex/vex_statements/",
        ops=READ,
        summary="Statements extracted from imported VEX documents.",
        list_fields=("id", "document", "vulnerability_id", "status", "justification", "product_purl"),
        label="vulnerability_id",
    ),
}

# Endpoints that are not resource collections. Exposed through dedicated tools.
SINGLETON_PATHS = {
    "version": "/status/version/",
    "health": "/status/health/",
    "status_settings": "/status/settings/",
    "background_task_statistics": "/status/background_task_statistics/",
    "purl_types": "/purl_types/",
}


def get_resource(name: str) -> Resource:
    """Look up a resource, raising a message that lists the valid names."""
    try:
        return RESOURCES[name]
    except KeyError:
        raise KeyError(
            f"Unknown resource '{name}'. Call secobserve_list_resources for the catalogue. "
            f"Closest names: {', '.join(sorted(n for n in RESOURCES if name.rstrip('s') in n)[:5]) or 'none'}"
        ) from None

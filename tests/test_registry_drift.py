"""registry.py is hand-written, so this pins it to a real backend schema.

AGENTS.md, Known limitations: a resource SecObserve adds stays invisible until someone adds it by hand, with no error
and no hint. The fixture is `/api/oa3/schema/` reduced to paths and operation ids, so this runs offline and never
touches an instance.
"""

from __future__ import annotations

import json
from pathlib import Path

from secobserve_mcp.registry import RESOURCES, SINGLETON_PATHS

SCHEMA_FILE = Path(__file__).parent / "fixtures" / "secobserve_openapi_paths.json"
_SCHEMA = json.loads(SCHEMA_FILE.read_text())
VERSION: str = _SCHEMA["secobserve_version"]
PATHS: dict[str, dict[str, str]] = _SCHEMA["paths"]

# Endpoints the registry deliberately leaves out, each with the reason. An entry here is a decision that names what
# reaches the endpoint instead -- never a way to quiet a failure.
IGNORED_PATHS: dict[str, str] = {
    "/api/authentication/authenticate/": "login flow; this server is handed a credential and never issues one",
    "/api/authentication/create_user_api_token/": "issues a credential; out of scope for an agent",
    "/api/authentication/revoke_user_api_token/": "revokes a credential; out of scope for an agent",
    "/api/jwt_secret/reset/": "rotates the instance secret and invalidates every session; not an agent operation",
    "/api/oa3/schema/": "the schema itself, read by schema.py and not through the catalogue",
    "/api/purl_types/": "a list, but only ever for one product: secobserve_status(kind='purl_types')",
    "/api/purl_types/{purl_type_id}/": "same endpoint, one type: secobserve_status(kind='purl_types')",
    "/api/import/api_import_observations_by_id/": "secobserve_api_import; blocks until the backend finishes",
    "/api/import/api_import_observations_by_name/": "secobserve_api_import; blocks until the backend finishes",
    "/api/import/file_upload_observations_by_id/": "multipart; secobserve_upload_file, confined to the import dir",
    "/api/import/file_upload_observations_by_name/": "multipart; secobserve_upload_file, confined to the import dir",
    "/api/import/file_upload_sbom_by_id/": "multipart; secobserve_upload_file, confined to the import dir",
    "/api/import/file_upload_sbom_by_name/": "multipart; secobserve_upload_file, confined to the import dir",
    "/api/metrics/product_metrics_current/": "secobserve_product_metrics; a zero here can mean 'not calculated'",
    "/api/metrics/product_metrics_status/": "secobserve_product_metrics; the guard against quoting that zero",
    "/api/metrics/product_metrics_timeline/": "secobserve_product_metrics; its age buckets are not Age_Choices",
    "/api/products/{product_id}/scan_osv/": "secobserve_trigger_scan; a timeout does not cancel the scan",
    "/api/products/{product_id}/scan_vulnerablecode/": "secobserve_trigger_scan; a timeout does not cancel the scan",
    "/api/products/{product_id}/{branch_id}/scan_osv/": "secobserve_trigger_scan, branch-scoped",
    "/api/products/{product_id}/{branch_id}/scan_vulnerablecode/": "secobserve_trigger_scan, branch-scoped",
    "/api/vex/csaf_document/create/": "secobserve_vex_document; the body has required fields a path cannot express",
    "/api/vex/csaf_document/update/{document_id_prefix}/{document_base_id}/": "secobserve_vex_document, update branch",
    "/api/vex/cyclonedx_document/create/": "secobserve_vex_document; required fields a path cannot express",
    "/api/vex/cyclonedx_document/update/{document_id_prefix}/{document_base_id}/": "secobserve_vex_document, update",
    "/api/vex/openvex_document/create/": "secobserve_vex_document; required fields a path cannot express",
    "/api/vex/openvex_document/update/{document_id_prefix}/{document_base_id}/": "secobserve_vex_document, update",
    "/api/vex/vex_import/": "multipart; secobserve_upload_file, confined to the import dir",
}

# op -> (which path serves it, which verb)
OP_ENDPOINT = {
    "list": ("collection", "get"),
    "create": ("collection", "post"),
    "get": ("detail", "get"),
    "update": ("detail", "patch"),
    "delete": ("detail", "delete"),
}


def _action_path(path: str, name: str, detail: bool) -> str:
    """The path secobserve_call_action builds, so a match here means the action is callable."""
    return f"/api{path}{{id}}/{name}/" if detail else f"/api{path}{name}/"


def _registered_paths() -> set[str]:
    reachable = {f"/api{path}" for path in SINGLETON_PATHS.values()}
    for resource in RESOURCES.values():
        reachable.add(f"/api{resource.path}")
        reachable.add(f"/api{resource.path}{{id}}/")
        reachable |= {_action_path(resource.path, a.name, a.detail) for a in resource.actions}
    return reachable


def test_every_collection_endpoint_is_a_registry_resource() -> None:
    """drf-spectacular names a DRF list operation `<basename>_list`, which is exactly the shape a Resource wraps."""
    collections = {path for path, ops in PATHS.items() if ops.get("get", "").endswith("_list")}
    registered = {f"/api{resource.path}" for resource in RESOURCES.values()}
    missing = sorted(collections - registered - set(IGNORED_PATHS))
    assert not missing, (
        f"SecObserve {VERSION} serves collections registry.py does not carry: {missing}. "
        "Add a Resource with a summary and list_fields, or add the path to IGNORED_PATHS with its reason."
    )


def test_every_declared_operation_is_still_served() -> None:
    """The opposite drift: the catalogue promises a verb the backend dropped, and the agent gets a 404 or a 405."""
    problems = []
    for name, resource in sorted(RESOURCES.items()):
        served = {
            "collection": PATHS.get(f"/api{resource.path}", {}),
            "detail": PATHS.get(f"/api{resource.path}{{id}}/", {}),
        }
        for op in sorted(resource.ops):
            level, method = OP_ENDPOINT[op]
            if method not in served[level]:
                problems.append(f"{name} declares '{op}', but {method.upper()} is not served on its {level} path")
    assert not problems, f"registry.py promises operations SecObserve {VERSION} does not serve: {problems}"


def test_every_declared_action_exists_with_the_verb_it_claims() -> None:
    """Actions are hand-typed down to the verb, and call_action sends that verb without asking the schema."""
    problems = []
    for name, resource in sorted(RESOURCES.items()):
        for action in resource.actions:
            path = _action_path(resource.path, action.name, action.detail)
            served = PATHS.get(path)
            if served is None:
                problems.append(f"{name}.{action.name}: {path} is not served")
            elif action.method.lower() not in served:
                problems.append(f"{name}.{action.name}: declares {action.method}, served verbs are {sorted(served)}")
    assert not problems, f"registry.py promises actions SecObserve {VERSION} does not serve: {problems}"


def test_no_backend_endpoint_is_silently_unreachable() -> None:
    """Catches a new action on an existing resource, which no list-path check would see."""
    unreachable = sorted(set(PATHS) - _registered_paths() - set(IGNORED_PATHS))
    assert not unreachable, (
        f"SecObserve {VERSION} serves endpoints no tool can reach: {unreachable}. "
        "Add an Action to the owning Resource, or add the path to IGNORED_PATHS with its reason."
    )


def test_ignored_paths_are_real_and_explained() -> None:
    """An ignore entry for a path the backend stopped serving is stale, and a blank reason is not a reason."""
    stale = sorted(set(IGNORED_PATHS) - set(PATHS))
    assert not stale, f"IGNORED_PATHS names paths SecObserve {VERSION} does not serve: {stale}"
    unexplained = sorted(path for path, reason in IGNORED_PATHS.items() if len(reason) < 20)
    assert not unexplained, f"IGNORED_PATHS entries without a reason: {unexplained}"

#!/usr/bin/env python3
"""Seed a SecObserve instance with the dataset evaluation.xml asks questions about.

Run against an EMPTY instance -- it creates products and imports findings, and the
evaluation answers are counts, so pre-existing data would change them.

    SECOBSERVE_BASE_URL=... SECOBSERVE_API_TOKEN=... uv run python evals/seed.py

Everything goes through the MCP server's own tools, so a successful run is also an
end-to-end check of the create, import and assessment paths.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from secobserve_mcp import config
from secobserve_mcp.formatting import ResponseFormat
from secobserve_mcp.tools_crud import (
    CreateInput,
    ListInput,
    UpdateInput,
    secobserve_create,
    secobserve_list,
    secobserve_update,
)
from secobserve_mcp.tools_workflows import (
    AssessObservationInput,
    RunPeriodicTaskInput,
    UploadInput,
    secobserve_assess_observation,
    secobserve_run_periodic_task,
    secobserve_upload_file,
)

PRODUCTS = [
    {"name": "Payments API", "description": "Card and transfer processing."},
    {"name": "Web Frontend", "description": "Customer-facing single page app."},
    {"name": "Legacy Batch", "description": "Overnight settlement jobs."},
]

BRANCHES = [
    ("Payments API", "main", True),
    ("Payments API", "release/2.0", False),
    ("Web Frontend", "main", True),
    ("Legacy Batch", "main", True),
]


def finding(
    title: str,
    severity: str,
    scanner: str,
    component: str,
    version: str,
    vulnerability_id: str = "",
) -> dict[str, Any]:
    return {
        "title": title,
        "description": f"{title} reported by {scanner}.",
        "parser_severity": severity,
        "scanner": scanner,
        "vulnerability_id": vulnerability_id,
        "origin_component_name": component,
        "origin_component_version": version,
        "origin_component_name_version": f"{component}:{version}",
    }


# Deliberate structure the questions rely on:
#   - log4j-core:2.14.1 is the only component shared by two products.
#   - Payments API/main is the only branch with two Critical findings.
#   - Trivy is the only scanner appearing in all three products.
REPORTS: dict[tuple[str, str], list[dict[str, Any]]] = {
    ("Payments API", "main"): [
        finding("Remote code execution in log4j", "Critical", "Trivy", "log4j-core", "2.14.1", "CVE-2021-44228"),
        finding("Deserialization flaw in commons-collections", "Critical", "Trivy", "commons-collections", "3.2.1"),
        finding("Denial of service in netty", "High", "Trivy", "netty-handler", "4.1.68", "CVE-2021-43797"),
        finding("Weak TLS ciphers accepted", "High", "ZAP", "tls-config", "1.0"),
        finding("Hardcoded credential in settings", "High", "Gitleaks", "config", "1.0"),
        finding("Missing rate limiting on /transfer", "Medium", "ZAP", "api", "1.0"),
        finding("Verbose error page", "Medium", "ZAP", "api", "1.0"),
        finding("Outdated jackson-databind", "Medium", "Trivy", "jackson-databind", "2.12.3"),
        finding("Cookie without SameSite", "Low", "ZAP", "api", "1.0"),
    ],
    ("Payments API", "release/2.0"): [
        finding("Remote code execution in log4j", "Critical", "Trivy", "log4j-core", "2.14.1", "CVE-2021-44228"),
        finding("Denial of service in netty", "High", "Trivy", "netty-handler", "4.1.68", "CVE-2021-43797"),
        finding("Outdated jackson-databind", "Medium", "Trivy", "jackson-databind", "2.12.3"),
    ],
    ("Web Frontend", "main"): [
        finding("Prototype pollution in lodash", "High", "Trivy", "lodash", "4.17.15", "CVE-2020-8203"),
        finding("Cross-site scripting in template", "High", "SARIF", "render", "1.0"),
        finding("Vulnerable log4j in build tooling", "Medium", "Trivy", "log4j-core", "2.14.1", "CVE-2021-44228"),
        finding("Missing Content-Security-Policy", "Medium", "DrHeader", "headers", "1.0"),
        finding("Mixed content on asset load", "Low", "ZAP", "assets", "1.0"),
    ],
    ("Legacy Batch", "main"): [
        finding("SQL injection in report job", "Critical", "SARIF", "reports", "1.0"),
        finding("Unencrypted database connection", "High", "Trivy", "jdbc-driver", "8.0.21"),
        finding("World-readable credentials file", "Medium", "Gitleaks", "config", "1.0"),
        finding("Unused debug endpoint", "Low", "SARIF", "debug", "1.0"),
    ],
}

# Assessments: one per verdict the questions ask about.
ASSESSMENTS = [
    {
        "product": "Payments API",
        "branch": "main",
        "title": "Cookie without SameSite",
        "status": "Not affected",
        "vex_justification": "inline_mitigations_already_exist",
        "comment": "The gateway rewrites Set-Cookie and adds SameSite=Strict for every response.",
    },
    {
        "product": "Payments API",
        "branch": "main",
        "title": "Verbose error page",
        "status": "Risk accepted",
        "risk_acceptance_expiry_date": "2027-06-30",
        "comment": "Staging only; scheduled with the error-handling rework in H1.",
    },
    {
        "product": "Legacy Batch",
        "branch": "main",
        "title": "Unused debug endpoint",
        "status": "False positive",
        "vex_justification": "component_not_present",
        "comment": "The endpoint was deleted in the 2025 cleanup; the scanner reads a stale manifest.",
    },
]

# CycloneDX components without a "bom-ref" are skipped by the parser, so every
# component here carries one.
SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "component": {
            "type": "application",
            "bom-ref": "pkg:generic/payments-api@2.0.0",
            "name": "payments-api",
            "version": "2.0.0",
        }
    },
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "name": "log4j-core",
            "version": "2.14.1",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        },
        {
            "type": "library",
            "bom-ref": "pkg:npm/readline-wrapper@1.4.0",
            "name": "readline-wrapper",
            "version": "1.4.0",
            "purl": "pkg:npm/readline-wrapper@1.4.0",
            "licenses": [{"license": {"id": "GPL-3.0-only"}}],
        },
        {
            "type": "library",
            "bom-ref": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.3",
            "name": "jackson-databind",
            "version": "2.12.3",
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.3",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        },
        {
            "type": "library",
            "bom-ref": "pkg:pypi/chardet@4.0.0",
            "name": "chardet",
            "version": "4.0.0",
            "purl": "pkg:pypi/chardet@4.0.0",
            "licenses": [{"license": {"id": "LGPL-2.1-or-later"}}],
        },
    ],
}


async def resource_id(resource: str, **filters: Any) -> int:
    items = json.loads(
        await secobserve_list(
            ListInput(resource=resource, filters=filters, page_size=100, response_format=ResponseFormat.JSON)
        )
    )["items"]
    if len(items) != 1:
        raise SystemExit(f"Expected exactly one {resource} for {filters}, got {len(items)}")
    return int(items[0]["id"])


async def main() -> int:
    existing = json.loads(
        await secobserve_list(ListInput(resource="products", page_size=1, response_format=ResponseFormat.JSON))
    )
    if existing["total"]:
        print(f"Refusing to seed: the instance already has {existing['total']} products.", file=sys.stderr)
        return 1

    group_id = int(
        json.loads(
            await secobserve_create(
                CreateInput(
                    resource="product_groups",
                    data={"name": "Platform", "description": "Customer-facing platform."},
                    response_format=ResponseFormat.JSON,
                )
            )
        )["id"]
    )

    for spec in PRODUCTS:
        data = dict(spec)
        if spec["name"] != "Legacy Batch":
            data["product_group"] = group_id
        await secobserve_create(CreateInput(resource="products", data=data, response_format=ResponseFormat.JSON))
        print(f"created product {spec['name']}")

    for product_name, branch_name, is_default in BRANCHES:
        product_id = await resource_id("product_names", name=product_name)
        # The product-level counters and the security gate only count findings on the
        # branch flagged is_default_branch, so it has to be set here.
        await secobserve_create(
            CreateInput(
                resource="branches",
                data={"product": product_id, "name": branch_name, "is_default_branch": is_default},
                response_format=ResponseFormat.JSON,
            )
        )
        print(f"created branch {product_name}/{branch_name}")

    import_dir = Path(config.get_config().import_dir)
    import_dir.mkdir(parents=True, exist_ok=True)

    for (product_name, branch_name), observations in REPORTS.items():
        report = {"format": "SecObserve", "observations": observations}
        path = import_dir / f"seed-{product_name.replace(' ', '-').lower()}-{branch_name.replace('/', '-')}.json"
        path.write_text(json.dumps(report, indent=2))
        product_id = await resource_id("product_names", name=product_name)
        result = await secobserve_upload_file(
            UploadInput(
                kind="observations",
                file_path=path.name,
                product_id=product_id,
                # "main" exists on every product, so the branch lookup must be product-scoped.
                branch_id=await resource_id("branch_names", name=branch_name, product=product_id),
            )
        )
        print(f"imported {product_name}/{branch_name}: {result.splitlines()[1].strip()}")

    sbom_path = import_dir / "seed-sbom.cdx.json"
    sbom_path.write_text(json.dumps(SBOM, indent=2))
    payments_id = await resource_id("product_names", name="Payments API")
    # Without a policy every component evaluates to "Unknown".
    await secobserve_update(
        UpdateInput(
            resource="products",
            id=payments_id,
            data={"license_policy": await resource_id("license_policies", name="Standard")},
            response_format=ResponseFormat.JSON,
        )
    )
    await secobserve_upload_file(
        UploadInput(
            kind="sbom",
            file_path=sbom_path.name,
            product_id=payments_id,
            branch_id=await resource_id("branch_names", name="main", product=payments_id),
        )
    )
    print("imported SBOM for Payments API/main")

    for assessment in ASSESSMENTS:
        product_id = await resource_id("product_names", name=assessment["product"])
        matches = json.loads(
            await secobserve_list(
                ListInput(
                    resource="observations",
                    filters={"product": product_id, "title": assessment["title"]},
                    fields=["id", "branch_name"],
                    page_size=100,
                    response_format=ResponseFormat.JSON,
                )
            )
        )["items"]
        target = [m for m in matches if m["branch_name"] == assessment["branch"]]
        if len(target) != 1:
            raise SystemExit(f"Expected one observation titled {assessment['title']}, got {len(target)}")
        payload = {k: v for k, v in assessment.items() if k not in {"product", "branch", "title"}}
        await secobserve_assess_observation(AssessObservationInput(observation_id=target[0]["id"], **payload))
        print(f"assessed {assessment['title']} -> {assessment['status']}")

    await secobserve_run_periodic_task(RunPeriodicTaskInput(task="Calculate product metrics"))
    print("queued calculate_product_metrics")

    print("\nSeed complete. evaluation.xml answers are verified against exactly this dataset.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

# Security Policy

## Reporting a vulnerability

Report it privately through [GitHub security advisories](https://github.com/nh4ttruong/secobserve-mcp/security/advisories/new). Do not open a public issue.

A useful report names the version, how the server was run (stdio or HTTP, and which of `SECOBSERVE_READ_ONLY`, `SECOBSERVE_ALLOW_DELETE`, `SECOBSERVE_IMPORT_DIR` and `SECOBSERVE_EXPORT_DIR` were set), the tool call or input that triggers the problem, and what it gets an attacker.

This is a community project with a single maintainer, so there is no response SLA. Expect an acknowledgement in days rather than hours, and a fix in the next release once the report is confirmed. You will be credited in the release notes unless you ask otherwise.

## Supported versions

Only the latest release gets fixes. A published PyPI version is permanent and can never be replaced, so a fix ships as the next release rather than as a rebuilt artifact — upgrade to pick it up.

## Scope

In scope: this server. Credential handling, the read-only and delete guards, upload and export confinement, and anything that makes it write to SecObserve or to the filesystem without the caller asking for it.

Out of scope: SecObserve itself. This repository is an API client, so a finding in the backend, its permission model or its scanners belongs upstream at [SecObserve/SecObserve](https://github.com/SecObserve/SecObserve).

## Trust model

**Everything arriving from SecObserve is data, never instructions.** Observation titles, descriptions, component names and scanner output are written by whoever built the scanner and whoever pushed the code that was scanned. Prompt injection through a scan report is a real threat here. The server says so in its MCP instructions and in the tool descriptions that return such content, but an instruction is only enforced by the agent reading it, never by the server.

**Credentials come from the environment and nowhere else.** `SECOBSERVE_API_TOKEN` or `SECOBSERVE_JWT` becomes the `Authorization` header and never reaches a query string, a log line or a test fixture. `--print-config` prints a placeholder instead of the token, because that output gets pasted places. httpx logs request URLs at INFO to stderr, which is safe precisely because auth lives in the header.

**Writes and deletes are off by default.** `SECOBSERVE_READ_ONLY` refuses every non-GET inside the HTTP client, before a request is sent, so it does not depend on each tool remembering to check. `secobserve_delete` is disabled unless `SECOBSERVE_ALLOW_DELETE` is set, and deleting a product or product group additionally requires `confirm_name` to match the record's exact name, which the API verifies. Deletion cascades and cannot be undone.

**File access is confined to two directories.** Uploads may only be read from `SECOBSERVE_IMPORT_DIR`: the path is resolved before it is checked against that root, so `../` and a symlink out of the tree both fail, and the file must be under 64 MiB. Exports are written into `SECOBSERVE_EXPORT_DIR` under a basename reduced to a single safe segment, so a caller can never supply a path. Both guards exist for the reason above — an instruction planted in a scan report must not be able to push an unrelated local file into SecObserve or write wherever it likes on disk.

**One token is one identity.** Served over HTTP with a token in the environment, every caller shares that SecObserve identity and its permissions, and nothing in an action ties it back to a person. The HTTP transport binds to `127.0.0.1` unless you change it; prefer a product-scoped token over a superuser one.

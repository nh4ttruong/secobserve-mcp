# Changelog

Notable changes per release. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html), where a minor bump below 1.0.0 may still break.

## [Unreleased]

## [0.2.1] — 2026-09-19

### Fixed

- The container image is built for `linux/arm64` as well as `linux/amd64`. 0.2.0 shipped amd64 only, which ran under emulation on an arm64 host and not at all on an arm64 node.

## [0.2.0] — 2026-09-19

### Changed

- **BREAKING — tool arguments are flat.** Every tool took a single `params` object; arguments are now declared on the tool itself, so a client renders each one with its own description. The published schema shrank from 28,683 to 25,151 characters across the 18 tools, returned on every session.
- **BREAKING — clearing a priority is `clear_priority: true`.** It used to be an explicit `priority: null`, which depended on Pydantic's `model_fields_set` to tell "sent as null" apart from "omitted". A flat signature has no such distinction.
- Unknown tool arguments are now rejected instead of ignored. Flattening alone would have let the SDK drop a misspelled argument in silence, so `filter=` instead of `filters=` would have returned an unfiltered list.
- The OpenAPI schema cache expires after 300 seconds instead of living as long as the process. A long-running HTTP deployment outlives backend upgrades, and a stale schema rejects filters the backend now accepts.

### Added

- `--print-config claude|codex|json|vscode` prints a ready-to-paste registration snippet. The token is always a placeholder, and the token-minting hint goes to stderr so `--print-config json > mcp.json` writes a usable file.
- `--version`.
- A container image at `ghcr.io/nh4ttruong/secobserve-mcp`, published on each tag. It runs as a non-root user and defaults to `--transport http --host 0.0.0.0`.
- `GET /healthz`, returning status and version. It never calls SecObserve, so a backend outage cannot get the server restarted.
- CI on every push and pull request: ruff and mypy once, pytest on Python 3.11 through 3.14.

### Upgrading

`uvx` re-resolves to the newest version every time it launches the server, so an existing install picks this release up on the next client restart. Pin with `uvx secobserve-mcp@0.1.3` to stay on the previous argument shape.

## [0.1.3] — 2026-09-18

### Changed

- The PyPI summary, keywords and project URLs now carry the terms someone would actually search for. `server.json` uses the same description, so PyPI and the MCP Registry agree.

## [0.1.2] — 2026-09-17

### Added

- A mark and a GitHub social preview card.

### Fixed

- `__version__` is read from installed package metadata, so the version reported over the protocol can no longer disagree with the published one.

## [0.1.1] — 2026-09-17

### Fixed

- MCP Registry publishing. `server.json` caps `description` at 100 characters, and `astral-sh/setup-uv` has no floating `v10` tag.

## [0.1.0] — 2026-09-17

First release. 18 tools over the SecObserve REST API: generic CRUD and discovery across ~50 resources, an escape hatch for the ~40 named actions, and validated workflows for assessment, four-eyes approval, metrics, import, scans, periodic tasks, status and VEX generation.

[Unreleased]: https://github.com/nh4ttruong/secobserve-mcp/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/nh4ttruong/secobserve-mcp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/nh4ttruong/secobserve-mcp/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/nh4ttruong/secobserve-mcp/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/nh4ttruong/secobserve-mcp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/nh4ttruong/secobserve-mcp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/nh4ttruong/secobserve-mcp/releases/tag/v0.1.0

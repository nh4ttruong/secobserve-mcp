# Agent base memory — `secobserve-mcp`

Read this before changing code in this repository. It records the current state and the invariants that must hold. It is not a backlog or a design document.

## Purpose of the repository

`secobserve-mcp` is an MCP server that exposes the SecObserve REST API to LLM agents. Current scope:

- Generic CRUD over the whole resource catalogue (~50 resources), with filtering, sorting, pagination and projection.
- Discovery: a static catalogue (`list_resources`) and the instance's live schema (`describe_resource`).
- An escape hatch for the ~40 named non-CRUD actions (`call_action`).
- Validated workflows: assessment, bulk assessment, approval, metrics, file upload (observations / SBOM / VEX), API import, scan triggering, periodic tasks, instance status, VEX document generation.

Project priorities, in order:

1. Never return a wrong answer silently.
2. Spend the agent's context sparingly.
3. Error messages must be enough for the agent to fix the call and retry.
4. Be safe about writes and deletes.
5. Keep the tool surface small and stable.

Out of scope today:

- Changing the SecObserve backend.
- Duplicating `secobserve-cli` (multi-file Excel/CSV export, migration scripts, GitOps config apply). This server only calls the backend's own export endpoints.
- A per-endpoint resource layer: adding one tool per endpoint works against the design, see [Tool surface invariants](#tool-surface-invariants).
- Caching business data. Only the OpenAPI schema is cached, and only within one process.

Do not expand into these without the user asking.

## Technical state

- Package: Python 3.11+ (uses `X | None`, `from __future__ import annotations` in every module).
- Entry point: `secobserve-mcp = secobserve_mcp.__main__:main`.
- MCP: **SDK 2.x** (`mcp>=2.2,<3`). The class is `MCPServer` in `mcp.server.mcpserver`, **not** `FastMCP` — that name is the 1.x API and is gone.
- HTTP: one `httpx.AsyncClient` shared for the process lifetime.
- Validation: Pydantic v2 via `Annotated[..., Field(...)]` on each tool argument; the signature is the schema.
- Tests: `pytest` + `pytest-asyncio` (`asyncio_mode = "auto"`) with `respx` mocking HTTP.
- Lint/types: `ruff` (line-length 120) and `mypy --strict`.
- Container: `Dockerfile` (two stages, `python:3.13-slim`, non-root), published to `ghcr.io/nh4ttruong/secobserve-mcp` by the release workflow. Defaults to HTTP on 0.0.0.0:8931 and serves `GET /healthz` — liveness only, it never calls SecObserve.
- CI: `.github/workflows/ci.yml` on every push to `main` and every pull request — ruff and mypy once, `pytest` on 3.11, 3.12, 3.13 and 3.14. `release.yml` re-runs the same checks on the tag, because the tagged commit is what ships.
- Current version: `0.1.2`.
- Baseline when this file was updated: 47 tests passing, ruff and mypy strict clean, stdio handshake and streamable HTTP both verified against a live instance.

## Code structure

```text
src/secobserve_mcp/
├── app.py              # MCPServer instance + INSTRUCTIONS shown to the agent
├── config.py           # env vars, lru_cache, auth header
├── client.py           # httpx client, error translation, tool_errors decorator
├── registry.py         # resource catalogue: path, ops, list_fields, actions
├── schema.py           # reads and slices the live OpenAPI schema, cached once per process
├── formatting.py       # projection, markdown/json rendering, pagination envelope
├── exports.py          # writes export files, reads upload files (with confinement)
├── types.py            # enums mirrored from the backend (Severity, Status, VEX, ...)
├── tools_crud.py       # 8 generic and discovery tools
├── tools_workflows.py  # 10 validated workflow tools
└── __main__.py         # argparse, --check, transport selection

evals/seed.py           # seeds the dataset evaluation.xml asks about, via the server's own tools
evaluation.xml          # 10 read-only questions with verified answers
```

Layering rule: `tools_*` never calls `httpx` directly; every request goes through `client.request`. `client` knows nothing about resources; all resource knowledge lives in `registry` or is read from `schema`.

## API contract in use

- The client's base URL is `<SECOBSERVE_BASE_URL>/api`. Every `path` passed to `request()` is relative, **with** a leading and a trailing slash (`/observations/`).
- Auth: header `Authorization: APIToken <token>`, or `JWT <token>`. Credentials never go in a query string.
- Pagination: `?page=N&page_size=M`, response `{count, next, previous, results}`. The backend does not cap `page_size`; this server caps it at 100.
- `MultipleChoiceFilter` takes repeated parameters. `httpx` encodes a list value as repeated parameters, so `filters={"current_status": ["Open", "In review"]}` works.
- `search` only exists on endpoints with a `SearchFilter` (observations search their title).
- Assessment: `PATCH /observations/{id}/assessment/`, `comment` mandatory, refused while the previous assessment is still in `Needs approval`.
- Bulk endpoints take at most 250 ids per call: `bulk_assessment`, `bulk_approval`, `bulk_delete`.
- File import: multipart, a `file` part plus form fields; two variants, `_by_id` and `_by_name`.
- OSV / VulnerableCode scans: POST with no body, and they **block until the scan finishes**, returning counters.
- `periodic_tasks/run`: queues rather than running inline, returns 409 while the task is already running, requires superuser.
- Deleting a product or product group requires a `name` query parameter matching the record's exact name.
- OpenAPI schema: `GET /api/oa3/schema/?format=json`; paths inside the schema carry the `/api` prefix.

When the backend changes its contract, update `registry.py` and the matching tests in the same change.

## Tool surface invariants

- The surface is **18 tools** and must stay small. A new endpoint means a new entry in `registry.py` (a resource or an `Action`), not a new tool.
- Only add a dedicated tool when an endpoint carries **a rule the agent cannot infer from the path**: required fields, a precondition, multipart bodies, or a side effect worth warning about. Otherwise `call_action` already covers it.
- Tool names are always prefixed `secobserve_`, snake_case, and start with a verb or an action noun.
- Every tool declares `name`, `title` and `annotations=ToolAnnotations(...)`. **Use the snake_case field names** (`read_only_hint`, `destructive_hint`, `idempotent_hint`, `open_world_hint`); the camelCase aliases work at runtime but fail `mypy --strict`.
- Tool arguments are **flat**, each one `Annotated[T, Field(description=...)]`, and every tool returns `str`. There is no wrapper model: what the signature says is what the client sees.
- `app.py` sets `extra="forbid"` on the SDK's `ArgModelBase` before any tool is registered. Without it the SDK drops unknown arguments in silence, so `filter=` instead of `filters=` would return an unfiltered list. Removing that line reopens the worst failure mode in this repository.
- Cross-field rules live at the top of the tool body as `raise ValueError(...)`, which `@tool_errors` turns into text the agent can act on.
- The docstring is the tool description the agent sees. It must carry: a one-line summary, Args with types and constraints, Returns with the schema of the JSON returned, Examples including "Don't use when", and Error Handling.
- Every tool carries `@tool_errors` directly below `@mcp.tool(...)`.

## Context invariants

- SecObserve serializers return **every** column. An Observation has 99 fields plus nested `product_data` / `parser_data`; one raw page of 25 rows is tens of thousands of tokens.
- Every resource that returns many rows must have `list_fields` in `registry.py`. Having no default projection is a bug, not a choice.
- `fields=["*"]` is the only way to opt out of projection, and a list result must say what it dropped.
- Long string values are truncated in markdown with a note giving the real length and pointing at `secobserve_get`. Never truncate in the JSON format.
- Field projection uses dotted paths (`product_data.name`). Check field names against a real response instead of guessing: `license_components` uses `product_name`, while `observations` and the `vex_*` resources use `product_data.name`.

## Correctness invariants

This is the most important invariant in the repository.

- django-filter **silently ignores** query parameters it does not recognise. A misspelled or invented filter returns the **unfiltered** list, and the agent reports a wrong number with full confidence.
- So `secobserve_list` validates filter names against the live schema before sending the request, and the error must list the filters that do exist.
- When the schema cannot be read, filters **pass through** rather than being blocked: the API remains the authority, and this server must not turn into a roadblock when the schema is unavailable.
- Never hardcode a filter list into this repo. Every filter, field and enum comes from the running instance's `/api/oa3/schema/`.
- `vulnerability_id` is **not** a filter on `observations`. This actually happened; do not add it to the catalogue.

## Error invariants

- An exception raised to the client is reported by MCP as `Error executing tool <name>`, discarding the message. Expected failures are therefore **returned as text**, through the `tool_errors` decorator.
- `tool_errors` catches only `SecObserveError`, `ConfigError`, `ValueError` and `KeyError`. Anything else still raises, because it is a bug.
- Every error message must say **what to do next**: the offending field, the valid values, or the tool to use instead.
- DRF 400 bodies are returned verbatim, because they already name the wrong field. Do not swallow or paraphrase them.
- A 404 must mention that SecObserve hides records outside the caller's products, not just say "not found".
- Never log the token, the `Authorization` header, or request bodies. `httpx` logs URLs at INFO to stderr, which is acceptable because auth lives in the header.

## Write and delete safety invariants

- `secobserve_delete` is disabled unless `SECOBSERVE_ALLOW_DELETE` is set. Deletion in SecObserve cascades and cannot be undone.
- Deleting `products` / `product_groups` additionally requires `confirm_name` to match the exact name; the API itself verifies this.
- `SECOBSERVE_READ_ONLY` is enforced in `client.request`, before any request is made, so it does not depend on each tool remembering to check.
- Uploads may only read files under `SECOBSERVE_IMPORT_DIR` (resolve, then compare `parents`). The reason is prompt injection: scan reports are third-party data, and without confinement an instruction planted in a report could talk an agent into uploading an unrelated local file to SecObserve.
- Exports are written to `SECOBSERVE_EXPORT_DIR` under a basename sanitised to a single segment. A caller can never supply a path.
- Never change an observation's severity or status with `secobserve_update`; it must go through `assess` so the observation log and the approval workflow stay intact.
- A tool with side effects must set `destructive_hint` correctly and state the side effect in its docstring.

## Working process for agents

### Before changing anything

1. Read the module you are touching and its tests.
2. Check `git status`; the repository may carry the user's own changes — do not overwrite anything outside your scope.
3. For API-related changes, check against the real SecObserve source (`Development/SecObserve/backend/application/...`) or `/api/oa3/schema/`, and state which version you checked against.
4. For projection changes, verify field names against a real response before editing `registry.py`.

### While changing

- Keep Python 3.11 compatibility and `mypy --strict` clean.
- Never create a new `httpx.AsyncClient` per request.
- No business logic in `client.py`, no HTTP in `tools_*`.
- No new dependency for something a few lines of code can do.
- Comments are sparse. Only what cannot be derived from the code, never a comment restating the line below, and a clear name or a short docstring in preference to either.
- No comment points at another repository. Sibling repos change without notice and the comment goes stale in silence.
- Never call mutating endpoints on a real SecObserve instance from tests.
- A new tool ships with tests for its guards, not just the happy path.

### Required verification

```bash
uv pip install -e ".[dev]"
uv run pytest -q
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run secobserve-mcp --help
```

For changes touching tool registration, the schema, or error paths, verify at the protocol level too, not just by calling the functions — only the protocol level exposes a swallowed message:

```bash
SECOBSERVE_BASE_URL=... SECOBSERVE_API_TOKEN=... uv run secobserve-mcp --check
```

then open a `ClientSession` over `stdio_client` and run `list_tools()` plus at least one successful and one failing `call_tool()`.

For changes touching the write paths (create, import, assessment, tasks), run `evals/seed.py` against a disposable **empty** instance.

### When handing over

- Name the main files changed.
- State how many tests passed and which verification commands you ran.
- State whether you called a real instance, and which one.
- If you changed an answer in `evaluation.xml`, say how you re-verified it.

## Contributing

### Writing

Applies to every file: Markdown, YAML, docstrings, commit messages, PR bodies.

- Do not hard-wrap prose. One sentence or one bullet per line, however long it runs. Python obeys the 120-character ruff limit, which is a formatter rule and not a prose one.
- Say it once. No paragraph restating a bullet, no sentence defending a decision nobody questioned.
- Do not translate technical terms. `observation`, `assessment`, `projection`, `trusted publishing` stay as they are.
- Shortest version that still carries the point. If it reads like it is explaining itself, cut it.

### Commits

Conventional Commits, one logical change per commit:

```text
<type>(<scope>): <subject>

<body>

<footer>
```

`type` is one of `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `build`, `ci`, `chore`. `scope` is optional and names the area, usually a module without its extension: `client`, `registry`, `schema`, `tools-crud`, `tools-workflows`, `evals`, `release`.

The subject is imperative, lower case, no trailing period, at most 72 characters: `fix(schema): reject unknown filters before sending the request`.

The body is **short**: the point, not an essay. Say **why** in a sentence or two — the diff already shows what. Name a SecObserve or MCP SDK behaviour when the change exists because of one, since that is the part nobody can rediscover from the code. No paragraph of reasoning, no walk through the alternatives you rejected, no restating the diff in prose. Two short paragraphs is a long body.

A breaking change is `feat!:` or a `BREAKING CHANGE:` footer. Breaking here means a tool was renamed or removed, an input field changed shape, or an output schema changed — anything an already-configured client would notice.

Never add AI attribution or co-author trailers.

### Pull requests

The PR describes the change, not the process of making it. **Short, logical, technical** — the main points only. No screenshots of passing tests, no narration of what you tried first, no justifying a decision at length. A reviewer opens the diff; the body tells them where to look and what to distrust.

Four parts, in this order:

```markdown
## Feature
What this adds or fixes, in one or two sentences.

## Change
The technical substance: which modules, which behaviour, which contract.
Bullets, one line each. Never prose. Name the invariant if one is involved.

## Impact
What a user or an already-configured client notices. Say "none" when
nothing observable changes. Call out anything that needs a version bump,
a re-release, or a config change.

## Notes
Optional, and CRITICAL only: an accepted limitation, or a trap the next person will hit.
With nothing critical, the PR ends at Impact.

- Verified:
- Live instance touched: no
```

The verification block closes every PR, with or without a `## Notes` section.

Rules that matter more than the template:

- Length is a rule, not a preference. If a section needs more than a few bullets, the PR is doing too much.
- `## Notes` is CRITICAL or absent. A follow-up you chose not to do, a rationale you are proud of, and a detail already visible in the diff are none of them critical.
- One concern per PR. A refactor and a fix in the same PR means neither can be reverted alone.
- State what you actually verified, and what you did not. "47 tests pass, no live instance touched" is worth more than a claim that everything works.
- If the change touches a documented invariant, say which one and why it still holds — or say plainly that it changes.

### Releases

Versions live in `pyproject.toml`, `server.json` and the git tag, and the release workflow fails when they disagree. The Python module reads its version from installed package metadata, so it is never edited by hand.

To release: bump `pyproject.toml` and `server.json`, commit as `chore(release): v<x.y.z>`, then tag `v<x.y.z>` and push the tag. The workflow runs the checks, publishes to PyPI via trusted publishing, and registers with the MCP Registry via GitHub OIDC.

A published version is permanent. PyPI does not allow re-uploading a version, so a bad release is fixed by releasing the next patch, never by retagging.

## Known limitations

- `registry.py` is a hand-written list and can fall behind when the backend adds resources. Filters and fields cannot drift, since they are read from the live schema, but **a new resource will not appear** until it is added by hand.
- `secobserve_trigger_scan` and `secobserve_api_import` block until the backend finishes. A timeout does not cancel the work in flight; check `vulnerability_checks` rather than retrying blind.
- No automated integration test runs in CI: verification against a real backend is still manual, via `--check` and `evals/seed.py`.
- Publishing is tokenless: PyPI trusted publishing plus GitHub OIDC for the registry. Both are configured on the provider side, not in this repo, so a fresh fork cannot release without setting them up.
- Version lives in three places that must agree: `pyproject.toml`, `server.json`, and the git tag; the release workflow fails the build when they diverge. The Python module derives its own version from installed package metadata, so it is not a fourth place to edit.
- The OpenAPI schema is cached in-process for `SCHEMA_TTL_SECONDS` (300). A backend upgraded mid-run is picked up within that window, not immediately; restart the server if you need it now. Callers past the TTL may refetch concurrently — the GET is idempotent, and a module-level `asyncio.Lock` would break across the event loops the tests create.

Do not hide these limitations in tool descriptions or documentation when making related changes.

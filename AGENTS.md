# Agent base memory — `secobserve-mcp`

Read this before changing code in this repository. It records the invariants that must hold. It is not a backlog, a design document or a status report.

## Purpose of the repository

`secobserve-mcp` is an MCP server that exposes the SecObserve REST API to LLM agents. Current scope:

- Generic CRUD over the whole resource catalogue (~50 resources), with filtering, sorting, pagination and projection.
- Discovery: a static catalogue (`list_resources`) and the instance's live schema (`describe_resource`).
- An escape hatch for the ~40 named non-CRUD actions (`call_action`).
- Validated workflows: assessment, bulk assessment, approval, metrics, file upload (observations / SBOM / VEX), API import, scan triggering, periodic tasks, instance status, VEX document generation.
- MCP Prompts for the work that is a sequence of calls rather than one: triage and the daily / weekly / monthly reports.

Project priorities, in order:

1. Never return a wrong answer silently.
2. Spend the agent's context sparingly.
3. Error messages must be enough for the agent to fix the call and retry.
4. Be safe about writes and deletes.
5. Keep the tool surface small and stable.

Out of scope today:

- Changing the SecObserve backend.
- Rebuilding what the backend already does: report rendering, multi-file export pipelines, migration scripts, GitOps config apply. This server only calls the backend's own export endpoints and returns what they give it.
- A per-endpoint resource layer: adding one tool per endpoint works against the design, see [Tool surface invariants](#tool-surface-invariants).
- Caching business data. Only the OpenAPI schema is cached, and only within one process.

Do not expand into these without the user asking.

## Technical constraints

- Python 3.11+ (uses `X | None`, `from __future__ import annotations` in every module).
- Entry point: `secobserve-mcp = secobserve_mcp.__main__:main`.
- MCP: **SDK 2.x**, pinned to one minor (`mcp>=2.2,<2.3`) because the per-request credential hangs off a hook the SDK marks provisional. The class is `MCPServer` in `mcp.server.mcpserver`, **not** `FastMCP` — that name is the 1.x API and is gone.
- HTTP: one `httpx.AsyncClient` shared for the process lifetime, never one per request.
- Validation: Pydantic v2 via `Annotated[..., Field(...)]` on each tool argument; the signature is the schema.
- Tests: `pytest` + `pytest-asyncio` (`asyncio_mode = "auto"`) with `respx` mocking HTTP. Never call mutating endpoints on a real SecObserve instance from a test.
- Lint/types: `ruff` (line-length 120) and `mypy --strict`, both clean before anything ships.
- CI runs the same checks on every push and every pull request, and `release.yml` re-runs them on the tag, because the tagged commit is what ships.

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
├── tools_crud.py       # the generic and discovery tools
├── tools_workflows.py  # the validated workflow tools
├── prompts.py          # MCP Prompts: triage, the change feeds and the reports
└── __main__.py         # argparse, --check, transport selection

scripts/release.py      # version bump, checks, commit and tag -- never pushes
```

Layering rule: `tools_*` holds no HTTP and never calls `httpx` directly; every request goes through `client.request`. `client` holds no business logic and knows nothing about resources; all resource knowledge lives in `registry` or is read from `schema`.

## API contract in use

- The client's base URL is `<SECOBSERVE_BASE_URL>/api`. Every `path` passed to `request()` is relative, **with** a leading and a trailing slash (`/observations/`).
- Auth: header `Authorization: APIToken <token>`, or `JWT <token>`. Credentials never go in a query string.
- Pagination: `?page=N&page_size=M`, response `{count, next, previous, results}`. The backend does not cap `page_size`; this server caps it at 100.
- `MultipleChoiceFilter` takes repeated parameters. `httpx` encodes a list value as repeated parameters, so `filters={"current_status": ["Open", "In review"]}` works.
- `search` only exists on endpoints with a `SearchFilter` (observations search their title).
- Assessment: `PATCH /observations/{id}/assessment/`, `comment` mandatory, refused while the previous assessment is still in `Needs approval`.
- Bulk endpoints take at most 250 ids per call: `bulk_assessment`, `bulk_approval`, `bulk_delete`.
- File import: multipart, a `file` part plus form fields; two variants, `_by_id` and `_by_name`.
- OSV / VulnerableCode scans: POST with no body, returning counters.
- `periodic_tasks/run`: queues rather than running inline, returns 409 while the task is already running, requires superuser.
- OpenAPI schema: `GET /api/oa3/schema/?format=json`; paths inside the schema carry the `/api` prefix.

When the backend changes its contract, update `registry.py` and the matching tests in the same change.

### Metrics

Verified against SecObserve 1.59.2.

- `/metrics/product_metrics_current/` answers **200 with every counter at `0`** when today's rows have not been written; there is no error path, so a zero is indistinguishable from "not calculated". Read `product_metrics_status` before quoting a count. This is the most dangerous behaviour in the whole metrics surface.
- An unknown `product_id` is **ignored, not rejected**: `get_product_by_id` returns `None` on `DoesNotExist`, and `None` means the whole instance, so a wrong id answers 200 with instance-wide numbers. The same applies to the timeline and the metrics exports. Resolve the id before presenting any number as one product's.
- Metrics rows are written for each product's **default branch only**, and never for a product group; a group id sums its products' rows. The per-product `active_*_observation_count` fields on `/products/` are default-branch only too, and are read from today's metrics rows when the instance setting `observation_count_from_metrics` is on, so they fall to zero exactly like metrics.
- `product_metrics_status` is **not** proof the job has ever run. `Product_Metrics_Status.load()` is a `get_or_create(pk=1)` whose `last_calculated` defaults to `timezone.now`, so the first read on an instance that never calculated creates the row and reports that it just did -- and every later read agrees. It detects a job that died, never one that never started; an empty timeline is what distinguishes those.
- The timeline's age buckets are `metrics/services/age.py`, **not** `commons/types.py` `Age_Choices`: it has no `Today`, and an unrecognised age silently means the full retained history.
- The backend has **no due date and no SLA**, anywhere, so nothing can compute "overdue". The `age` filter on `observations` filters `last_observation_log__gte`, i.e. *recently changed* and not *old*, and must never be used to measure how long a finding has been open.

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
- Prompts do not count against the 18, and a prompt is never a way to smuggle in a tool. A tool's schema is sent on every connection while a prompt's text is fetched by name, which is why the long-form caveats live in `prompts.py` and not in a tool description.

## Context invariants

- SecObserve serializers return **every** column: an observation is around 100 fields plus nested `product_data` / `parser_data`, so one raw page of 25 rows is tens of thousands of tokens.
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
- Deleting `products` / `product_groups` additionally requires `confirm_name` to match the record's exact name, passed to the API as a `name` query parameter; the API itself verifies it.
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

- No new dependency for something a few lines of code can do.
- Comments are sparse: only what cannot be derived from the code, never a comment restating the line below, and a clear name or a short docstring in preference to either.
- No comment points at another repository. Sibling repos change without notice and the comment goes stale in silence.
- A new tool ships with tests for its guards, not just the happy path.

### Required verification

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest -q
uv run secobserve-mcp --help
```

For changes touching tool registration, the schema, or error paths, verify at the protocol level too, not just by calling the functions — only the protocol level exposes a swallowed message:

```bash
SECOBSERVE_BASE_URL=... SECOBSERVE_API_TOKEN=... uv run secobserve-mcp --check
```

then open a `ClientSession` over `stdio_client` and run `list_tools()` plus at least one successful and one failing `call_tool()`.

For changes touching the write paths (create, import, assessment, tasks), exercise them against a disposable **empty** instance before trusting them; nothing in CI does.

### When handing over

- Name the main files changed, and which verification commands you ran and passed.
- State whether you called a real instance, and which one.

## Contributing

This section is the binding version, and a new rule is recorded here. [CONTRIBUTING.md](CONTRIBUTING.md) states the same expectations for human contributors in their own terms; when the two differ, this one is right.

### Writing

Applies to every file: Markdown, YAML, docstrings, commit messages, PR bodies.

- Do not hard-wrap prose. One sentence or one bullet per line, however long it runs. Python obeys the 120-character ruff limit, which is a formatter rule and not a prose one.
- Say it once. No paragraph restating a bullet, no sentence defending a decision nobody questioned.
- Do not translate technical terms. `observation`, `assessment`, `projection`, `trusted publishing` stay as they are.
- Shortest version that still carries the point. If it reads like it is explaining itself, cut it.
- This file stays general. Edit it when a rule, an invariant or a capability changes, and for nothing else. Volatile state — test counts, version numbers, what passed when it was last written — belongs in the pull request, not here.

### Commits

Conventional Commits, one logical change per commit:

```text
<type>(<scope>): <subject>

<body>

<footer>
```

`type` is one of `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `build`, `ci`, `chore`. `scope` is optional and names the area, usually a module without its extension: `client`, `registry`, `schema`, `tools-crud`, `tools-workflows`, `release`.

The subject is imperative, lower case, no trailing period, at most 72 characters: `fix(schema): reject unknown filters before sending the request`.

The body is **short**: say **why** in a sentence or two, since the diff already shows what. Name a SecObserve or MCP SDK behaviour when the change exists because of one, since that is the part nobody can rediscover from the code. Two short paragraphs is a long body.

A breaking change is `feat!:` or a `BREAKING CHANGE:` footer. Breaking here means a tool was renamed or removed, an input field changed shape, or an output schema changed — anything an already-configured client would notice.

Never add AI attribution or co-author trailers.

### Pull requests

The PR describes the change, not the process of making it. **Short, logical, technical** — a reviewer opens the diff; the body tells them where to look and what to distrust.

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
- State what you actually verified, and what you did not.
- If the change touches a documented invariant, say which one and why it still holds — or say plainly that it changes.

### Releases

Versions live in `pyproject.toml`, `server.json` and the git tag, and the release workflow fails when they disagree. The Python module reads its version from installed package metadata, so it is never edited by hand.

Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html), and from 1.0.0 that is a promise rather than a convention: breaking an already-configured client costs a major bump, features go in the minor and fixes in the patch. Before 1.0.0 a minor could break; it cannot now, so a rename that used to be a minor is a reason to redesign rather than a reason to bump.

Breaking is judged against an already-configured client, not against the Python code: a tool or prompt renamed or removed, an argument renamed, an argument becoming required, a value dropped from an enum, an existing output field changing shape, or an environment variable renamed. Adding a tool, a prompt, an optional argument, an enum member or a new key to an output is not breaking.

To release: `uv run python scripts/release.py <x.y.z>`. It refuses unless `main` is clean and matches `origin/main` and the tag does not already exist anywhere, runs the four checks first so a failure leaves the tree untouched, then bumps `pyproject.toml` and both version fields in `server.json`, commits as `chore(release): v<x.y.z>` and tags.

It never pushes. `git push origin main && git push origin v<x.y.z>` stays manual, because that is the step that cannot be undone. The workflow then runs the checks again on the tag, publishes to PyPI via trusted publishing, registers with the MCP Registry via GitHub OIDC, builds the multi-arch image and creates the GitHub release.

**Those steps are ordered, and PyPI is first.** A later step failing leaves a version that exists on PyPI and nowhere else, and PyPI will not take that version again, so the repair is the next patch release rather than a retag. The registry enforces rules its published JSON schema does not carry -- an OCI package must not set `registryBaseUrl`, and its `identifier` must be the canonical reference including the tag (`ghcr.io/<owner>/<image>:<x.y.z>`) -- so `server.json` is only truly validated by a release. `bump_server_json` checks both rules before it writes.

There is no changelog file. The GitHub release carries the notes, generated from the merged pull request titles, which is why a pull request title has to stand on its own. Auto-generated titles cannot tell someone what to change, so **after a breaking release, edit its GitHub release notes by hand** and say what an already-configured client has to do differently.

A published version is permanent. PyPI does not allow re-uploading a version, so a bad release is fixed by releasing the next patch, never by retagging.

## Known limitations

- `registry.py` is a hand-written list and can fall behind when the backend adds resources. Filters and fields cannot drift, since they are read from the live schema, but **a new resource will not appear** until it is added by hand.
- `secobserve_trigger_scan` and `secobserve_api_import` block until the backend finishes. A timeout does not cancel the work in flight; check `vulnerability_checks` rather than retrying blind.
- Nothing in CI runs against a real SecObserve. Every check is offline, so a change that only breaks against a live backend is found by someone using it. This is deliberate and it has a cost: the correctness bugs this repository has shipped were all found that way, not by a test.
- Publishing is tokenless: PyPI trusted publishing plus GitHub OIDC for the registry. Both are configured on the provider side, not in this repo, so a fresh fork cannot release without setting them up.
- The per-request credential and the audit log both hang off the MCP SDK's `Server.middleware`, which the SDK marks provisional. Three things guard it: the dependency is pinned to one SDK minor, the tests fail if the hook stops binding, and `app.py` drives a synthetic message through the chain at import and refuses to start when the credential did not bind. What that last one cannot see is a future transport bypassing `ServerRunner`, which every transport in 2.2 goes through.
- The OpenAPI schema is cached in-process for `SCHEMA_TTL_SECONDS` (300). A backend upgraded mid-run is picked up within that window, not immediately; restart the server if you need it now. Callers past the TTL may refetch concurrently — the GET is idempotent, and a module-level `asyncio.Lock` would break across the event loops the tests create.

Do not hide these limitations in tool descriptions or documentation when making related changes.

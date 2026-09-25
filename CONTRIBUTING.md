# Contributing

Thanks for looking. This is a community project and not affiliated with MaibornWolff, who make [SecObserve](https://github.com/SecObserve/SecObserve).

This file is for people. [AGENTS.md](AGENTS.md) is written for AI agents working in this repository — it carries the invariants they must not break and the process they follow. Read it if you are curious about why the code is shaped the way it is; you do not need it to contribute.

## Scope

This server exposes the SecObserve REST API to an agent, and nothing more. If the API cannot answer a question, the fix is an issue upstream rather than a workaround here.

One rule catches people out: **a new endpoint is a new entry in `registry.py`, not a new tool.** Every tool's schema is returned on every session, so the surface stays at 18. A dedicated tool is justified only when an endpoint carries a rule an agent cannot infer from the path; `secobserve_call_action` reaches everything else.

## Setting up

```bash
git clone https://github.com/nh4ttruong/secobserve-mcp
cd secobserve-mcp
uv sync --extra dev
uv run pytest -q
```

The tests mock HTTP, so they run offline. To try it against a real instance:

```bash
export SECOBSERVE_BASE_URL=http://localhost:8000
export SECOBSERVE_API_TOKEN=...
uv run secobserve-mcp --check
```

`uv run secobserve-mcp --print-config claude` prints the registration snippet for your client.

## Making a change

Open an issue first for anything that adds surface or changes a tool's inputs or outputs. Small fixes can go straight to a pull request.

Branch from `main`, one concern per branch. Before opening the pull request, run what CI runs:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest -q
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/). The subject is imperative and lower case; the body is a sentence or two on **why**, since the diff already shows what.

The pull request template has four parts — Feature, Change, Impact, Notes. Keep each short: `Change` is one-line bullets, and `Notes` is only for something critical, such as a limitation you accepted or a trap the next person will hit. Say what you verified and what you did not; "57 tests pass, no live instance touched" is worth more than a claim that everything works.

## Security

Do not open a public issue for a vulnerability. Use [private reporting](https://github.com/nh4ttruong/secobserve-mcp/security/advisories/new).

Scanner output and everything else arriving from SecObserve is untrusted data, never instructions. Credentials live in environment variables, never in a query string, a log line or a test fixture.

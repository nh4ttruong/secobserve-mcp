"""One JSON line per tool call, on stderr: which tool, which caller, which resource, how long, how it ended.

SecObserve's observation log records writes only, so a read is invisible there -- and a read is how data leaves.
This is the server's own record. It is written from a middleware rather than from the tools, so every tool is
covered and a new one is covered without being touched.

Nothing here may change the outcome of a call, so building and writing the line is guarded and a failure is dropped.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
from datetime import UTC, datetime
from typing import Any

from mcp.server.context import CallNext, HandlerResult, ServerRequestContext

from .config import CREDENTIAL_HEADER, ConfigError, _bool_env, request_auth_header
from .registry import RESOURCES

ENV_AUDIT_LOG = "SECOBSERVE_AUDIT_LOG"

# Domain separation: a digest here cannot be matched against a plain SHA-256 of the same token taken anywhere else.
_DIGEST_PREFIX = b"secobserve-mcp/audit/v1:"
_DIGEST_CHARS = 12
_MAX_VALUE_CHARS = 64


def _clip(value: str) -> str:
    return value if len(value) <= _MAX_VALUE_CHARS else value[:_MAX_VALUE_CHARS] + "..."


def _digest(credential: str) -> str:
    return hashlib.sha256(_DIGEST_PREFIX + credential.encode()).hexdigest()[:_DIGEST_CHARS]


def _claimed_username(token: str) -> str | None:
    """The `username` claim of a JWT, so a line can name a person instead of only a digest.

    The signature is not checked and cannot be: the token is the caller's own data, and only SecObserve holds the
    secret. The value is what the caller claimed, which is worth recording precisely because it can be a lie.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except ValueError:
        return None
    username = payload.get("username") if isinstance(payload, dict) else None
    return _clip(username) if isinstance(username, str) else None


def _caller(presented: bool) -> tuple[str, str | None]:
    """`<source>:<digest>` for the credential this call is being served with, plus any username it claims.

    The credential itself never reaches the line. The digest correlates one caller's lines with each other and
    with nothing else, and `source` separates a caller the gateway authenticated from the server's own identity.
    """
    try:
        credential = request_auth_header()
    except ConfigError:
        return "unknown", None

    scheme, _, token = credential.partition(" ")
    source = scheme.lower() if presented else "server"
    return f"{source}:{_digest(credential)}", _claimed_username(token) if scheme == "JWT" else None


def _resource(arguments: Any) -> str | None:
    """The `resource` argument, and only when the catalogue already knows that name.

    Arguments are never logged: a filter value carries product names, and an argument is where a credential would
    leak if one were ever passed as one. The catalogue check is what makes this single argument safe to record --
    a value the caller invented is dropped rather than written through.
    """
    if not isinstance(arguments, dict):
        return None
    name = arguments.get("resource")
    return name if isinstance(name, str) and name in RESOURCES else None


def _emit(ctx: ServerRequestContext[Any, Any], outcome: str, elapsed: float) -> None:
    try:
        params = ctx.params or {}
        caller, claimed_username = _caller(ctx.request is not None and CREDENTIAL_HEADER in ctx.request.headers)
        line = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "tool": _clip(str(params.get("name", ""))),
            "caller": caller,
            "claimed_username": claimed_username,
            "resource": _resource(params.get("arguments")),
            "outcome": outcome,
            "ms": round(elapsed * 1000, 1),
        }
        sys.stderr.write(json.dumps(line, separators=(",", ":")) + "\n")
        sys.stderr.flush()
    except Exception:  # noqa: BLE001, S110  # a raise here would be a failed call the caller could not explain
        pass


async def audit_tool_calls(ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
    """Write one line per tool call, timed around the whole call so a tool that raises is timed like one that does not.

    `outcome` is what this layer can honestly observe: `returned` when the tool produced a result, `error` when it
    raised and the SDK turned that into an error result, `rejected` when the call never reached the tool. An expected
    failure that `@tool_errors` returned as text is a `returned`, because reading the string to tell the difference
    would tie this layer to the wording of every error message in the repository.
    """
    if ctx.method != "tools/call" or not _bool_env(ENV_AUDIT_LOG, True):
        return await call_next(ctx)

    started = time.perf_counter()
    outcome = "rejected"
    try:
        result = await call_next(ctx)
        outcome = "error" if isinstance(result, dict) and result.get("isError") else "returned"
        return result
    finally:
        _emit(ctx, outcome, time.perf_counter() - started)

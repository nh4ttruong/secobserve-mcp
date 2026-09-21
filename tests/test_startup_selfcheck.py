"""The startup self-check: `Server.middleware` is provisional, and a release that stopped consulting it is silent.

These are synchronous tests on purpose. The check runs once while `app` is imported, long before any event loop.
"""

from __future__ import annotations

import socket
from typing import Any

import pytest
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.runner import ServerRunner

from secobserve_mcp import app
from secobserve_mcp.config import request_auth_header

ENVIRONMENT_CREDENTIAL = "APIToken test-token"


async def passthrough(ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
    """A middleware that runs and binds nothing: the shape of a hook that moved to a seam with no request on it."""
    return await call_next(ctx)


def test_the_check_passes_on_the_chain_this_server_composes(capsys: pytest.CaptureFixture[str]) -> None:
    """Silence is the contract: a passing check says nothing, so nothing of the credential can reach a log line."""
    app.verify_middleware_binds_credential()

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_an_sdk_that_ignores_the_middleware_list_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Composition is where the SDK consults `Server.middleware`; skipping it is exactly the change nobody would see."""
    monkeypatch.setattr(ServerRunner, "_compose_server_middleware", lambda self, inner: inner)

    with pytest.raises(RuntimeError) as refused:
        app.verify_middleware_binds_credential()

    message = str(refused.value)
    assert "did not run mcp.middleware" in message
    assert app.SELF_CHECK_CREDENTIAL not in message
    assert "test-token" not in message
    assert capsys.readouterr().err == ""


def test_a_chain_that_runs_without_binding_refuses_to_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hook that still runs but no longer carries the request would pass every check that only reads the list."""
    chain = list(app.mcp.middleware)
    monkeypatch.setattr(
        app.mcp._lowlevel_server,
        "middleware",
        [passthrough if m is app.bind_request_credential else m for m in chain],
    )

    with pytest.raises(RuntimeError) as refused:
        app.verify_middleware_binds_credential()

    message = str(refused.value)
    assert "without binding the credential" in message
    assert "test-token" not in message


def test_a_check_that_cannot_run_warns_instead_of_failing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The gap is conditional and silent; a check that misfires breaks every deployment at once, stdio included."""

    async def boom(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise TypeError("serve_one() got an unexpected keyword argument 'connection'")

    monkeypatch.setattr("mcp.server.runner.serve_one", boom)

    app.verify_middleware_binds_credential()

    warning = capsys.readouterr().err
    assert "could not run" in warning
    assert "TypeError" in warning
    assert app.SELF_CHECK_CREDENTIAL not in warning
    assert "test-token" not in warning


def test_the_check_opens_no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """The synthetic message must never reach SecObserve, and a server that dialled out on start would be worse."""

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("the startup self-check opened a connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)

    app.verify_middleware_binds_credential()


def test_stdio_is_left_exactly_as_it_was() -> None:
    """One process, one user, no header: the environment credential is correct there and the check must not move it."""
    before = list(app.mcp.middleware)

    app.verify_middleware_binds_credential()

    assert app.mcp.middleware == before
    assert request_auth_header() == ENVIRONMENT_CREDENTIAL


def test_the_synthetic_credential_is_not_shaped_like_one() -> None:
    """A JWT-shaped literal in this repository has failed a secret scan before."""
    scheme, _, token = app.SELF_CHECK_CREDENTIAL.partition(" ")

    assert scheme == "APIToken"
    assert "not-a-token" in token
    assert token.count(".") == 0

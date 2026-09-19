"""Tests for the HTTP surface that is not MCP itself."""

from __future__ import annotations

from starlette.testclient import TestClient

from secobserve_mcp import __version__
from secobserve_mcp.app import mcp


def test_healthz_answers_without_touching_secobserve() -> None:
    """No respx mock is installed here, so any outbound call would fail the test."""
    with TestClient(mcp.streamable_http_app(stateless_http=True, json_response=True)) as client:
        response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}

"""Tests for the command line surface: --version, --print-config, the advisory version check in --check, and the shared-identity guard on HTTP."""

from __future__ import annotations

import json
import tomllib

import httpx
import pytest
import respx

from secobserve_mcp import __version__, config
from secobserve_mcp.__main__ import (
    PYPI_JSON_URL,
    SHARED_IDENTITY_FLAG,
    TOKEN_PLACEHOLDER,
    _check,
    _print_config,
    _report_install,
    _runs_from_uv_tool_env,
    main,
)


def test_version_prints_the_package_version(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setattr("sys.argv", ["secobserve-mcp", "--version"])
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_print_config_never_emits_the_configured_token(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """The snippet is pasted into shells and issues; a real token must not ride along."""
    monkeypatch.setenv(config.ENV_API_TOKEN, "super-secret-token")
    config.get_config.cache_clear()

    for client in ("claude", "codex", "json", "vscode"):
        assert _print_config(client) == 0
        captured = capsys.readouterr()
        assert "super-secret-token" not in captured.out + captured.err
        assert TOKEN_PLACEHOLDER in captured.out


def test_print_config_uses_the_configured_base_url(capsys) -> None:
    _print_config("claude")
    out = capsys.readouterr().out
    assert out.startswith("claude mcp add secobserve ")
    assert f"--env {config.ENV_BASE_URL}=http://secobserve.test" in out


def test_print_config_json_is_parseable_and_keyed_per_client(capsys) -> None:
    _print_config("json")
    assert "mcpServers" in json.loads(capsys.readouterr().out)

    # VS Code is the odd one out: it reads "servers", not "mcpServers".
    _print_config("vscode")
    assert "servers" in json.loads(capsys.readouterr().out)


def test_print_config_codex_is_valid_toml(capsys) -> None:
    _print_config("codex")
    parsed = tomllib.loads(capsys.readouterr().out)
    assert parsed["mcp_servers"]["secobserve"]["command"] == "uvx"


def test_print_config_keeps_the_token_hint_off_stdout(capsys) -> None:
    """So that `--print-config json > mcp.json` writes a usable file."""
    _print_config("json")
    captured = capsys.readouterr()
    assert "create_user_api_token" in captured.err
    assert "create_user_api_token" not in captured.out


def test_print_config_escapes_a_pinned_uv_tool_install(capsys) -> None:
    """`uv tool install` makes a bare `uvx secobserve-mcp` run that copy forever, including from a client config."""
    _print_config("claude")
    assert capsys.readouterr().out.rstrip().endswith("-- uvx secobserve-mcp@latest")

    _print_config("codex")
    assert tomllib.loads(capsys.readouterr().out)["mcp_servers"]["secobserve"]["args"] == ["secobserve-mcp@latest"]

    for client, key in (("json", "mcpServers"), ("vscode", "servers")):
        _print_config(client)
        assert json.loads(capsys.readouterr().out)[key]["secobserve"]["args"] == ["secobserve-mcp@latest"]


@respx.mock
async def test_report_install_names_the_newer_release(capsys) -> None:
    respx.get(PYPI_JSON_URL).mock(return_value=httpx.Response(200, json={"info": {"version": "99.0.0"}}))
    await _report_install()
    captured = capsys.readouterr()
    assert f"secobserve-mcp: {__version__} (PyPI has 99.0.0)" in captured.out
    assert captured.err == ""


@respx.mock
async def test_report_install_says_nothing_to_do_when_current(capsys) -> None:
    respx.get(PYPI_JSON_URL).mock(return_value=httpx.Response(200, json={"info": {"version": __version__}}))
    await _report_install()
    assert f"secobserve-mcp: {__version__} (latest)" in capsys.readouterr().out


@respx.mock
async def test_report_install_survives_an_unreachable_index(capsys) -> None:
    respx.get(PYPI_JSON_URL).mock(side_effect=httpx.ConnectError("no route to host"))
    await _report_install()
    captured = capsys.readouterr()
    assert "could not be determined" in captured.err
    assert captured.out == ""


@respx.mock
async def test_report_install_survives_a_timeout(capsys) -> None:
    respx.get(PYPI_JSON_URL).mock(side_effect=httpx.ReadTimeout("pypi is slow"))
    await _report_install()
    assert "could not be determined" in capsys.readouterr().err


@respx.mock
async def test_report_install_survives_a_payload_without_a_version(capsys) -> None:
    respx.get(PYPI_JSON_URL).mock(return_value=httpx.Response(200, json={"info": {}}))
    await _report_install()
    assert "could not be determined" in capsys.readouterr().err


@respx.mock
async def test_report_install_flags_a_shadowing_tool_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path, capsys
) -> None:
    """uv writes uv-receipt.toml at the root of a persistent tool environment and nowhere else."""
    respx.get(PYPI_JSON_URL).mock(return_value=httpx.Response(200, json={"info": {"version": __version__}}))
    monkeypatch.setattr("sys.prefix", str(tmp_path))
    assert _runs_from_uv_tool_env() is False

    (tmp_path / "uv-receipt.toml").write_text("[tool]\n")
    assert _runs_from_uv_tool_env() is True

    await _report_install()
    out = capsys.readouterr().out
    assert "uv tool environment" in out
    assert "uv tool upgrade secobserve-mcp" in out
    assert "uvx secobserve-mcp@latest" in out


@respx.mock
def test_starting_the_server_never_calls_pypi(monkeypatch: pytest.MonkeyPatch) -> None:
    """An MCP server that phones an index on every launch is something a security team rejects outright."""
    from secobserve_mcp import app

    pypi = respx.get(PYPI_JSON_URL).mock(return_value=httpx.Response(200, json={"info": {"version": "99.0.0"}}))
    monkeypatch.setattr(app.mcp, "run", lambda **kwargs: None)

    for argv in (["secobserve-mcp"], ["secobserve-mcp", "--transport", "http", "--shared-identity"]):
        monkeypatch.setattr("sys.argv", argv)
        assert main() == 0

    assert not pypi.called


@respx.mock
async def test_check_still_reports_secobserve_when_the_index_is_unreachable(
    monkeypatch: pytest.MonkeyPatch, tmp_path, capsys
) -> None:
    """The version check is advisory: its failure must not change what --check says about the instance."""
    monkeypatch.setattr("sys.prefix", str(tmp_path))
    api = f"{config.get_config().base_url}/api"
    respx.get(f"{api}/status/version/").mock(return_value=httpx.Response(200, json={"version": "1.59.2"}))
    respx.get(f"{api}/users/me/").mock(return_value=httpx.Response(200, json={"username": "you", "is_superuser": True}))
    respx.get(PYPI_JSON_URL).mock(side_effect=httpx.ConnectError("no route to host"))

    assert await _check() == 0
    captured = capsys.readouterr()
    assert "Connected to http://secobserve.test" in captured.out
    assert "  version: 1.59.2" in captured.out
    assert "could not be determined" in captured.err


def _no_run_server(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    """Record mcp.run kwargs instead of serving, so main() can be driven to the end."""
    from secobserve_mcp import app

    calls: list[dict[str, object]] = []
    monkeypatch.setattr(app.mcp, "run", lambda **kwargs: calls.append(kwargs))
    return calls


def test_http_refuses_a_credential_every_caller_would_share(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """HTTP has no authentication of its own, so one env token makes every caller one SecObserve identity."""
    calls = _no_run_server(monkeypatch)
    monkeypatch.setattr("sys.argv", ["secobserve-mcp", "--transport", "http", "--host", "0.0.0.0"])

    assert main() == 2
    assert calls == []

    err = capsys.readouterr().err
    assert "Refusing to start" in err
    assert "0.0.0.0:8931" in err
    # The refusal has to carry the whole command line: arguments to `docker run` replace CMD rather than extend it.
    assert f"secobserve-mcp --transport http --host 0.0.0.0 --port 8931 {SHARED_IDENTITY_FLAG}" in err
    assert "gateway" in err


def test_the_guard_also_fires_on_loopback(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """The bind address changes who can reach the port, not that they all share one identity."""
    _no_run_server(monkeypatch)
    monkeypatch.setattr("sys.argv", ["secobserve-mcp", "--transport", "http"])

    assert main() == 2
    assert "127.0.0.1:8931" in capsys.readouterr().err


def test_shared_identity_starts_http_and_forces_read_only(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """Writes under a shared token record the wrong actor in the observation log and in four-eyes approval."""
    calls = _no_run_server(monkeypatch)
    monkeypatch.setattr("sys.argv", ["secobserve-mcp", "--transport", "http", SHARED_IDENTITY_FLAG])

    assert main() == 0
    assert calls and calls[0]["transport"] == "streamable-http"
    assert config.get_config().read_only is True
    assert "refuses every write" in capsys.readouterr().err


async def test_a_write_is_refused_after_shared_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    """The flag routes through SECOBSERVE_READ_ONLY, which client.request enforces before any request is made."""
    from secobserve_mcp.client import ReadOnlyError, request

    _no_run_server(monkeypatch)
    monkeypatch.setattr("sys.argv", ["secobserve-mcp", "--transport", "http", SHARED_IDENTITY_FLAG])
    assert main() == 0

    with pytest.raises(ReadOnlyError):
        await request("POST", "/products/")


def test_stdio_is_untouched(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """One process, one user, their own token: the hazard does not exist and nothing may get harder."""
    calls = _no_run_server(monkeypatch)
    monkeypatch.setattr("sys.argv", ["secobserve-mcp"])

    assert main() == 0
    assert calls == [{}]
    assert config.get_config().read_only is False
    assert capsys.readouterr().err == ""


@respx.mock
def test_check_runs_before_the_guard(monkeypatch: pytest.MonkeyPatch, tmp_path, capsys) -> None:
    """--check reports on the wiring; refusing it would hide the answer the operator came for."""
    monkeypatch.setattr("sys.prefix", str(tmp_path))
    _no_run_server(monkeypatch)
    api = f"{config.get_config().base_url}/api"
    respx.get(f"{api}/status/version/").mock(return_value=httpx.Response(200, json={"version": "1.59.2"}))
    respx.get(f"{api}/users/me/").mock(return_value=httpx.Response(200, json={"username": "you"}))
    respx.get(PYPI_JSON_URL).mock(return_value=httpx.Response(200, json={"info": {"version": __version__}}))
    monkeypatch.setattr("sys.argv", ["secobserve-mcp", "--transport", "http", "--check"])

    assert main() == 0
    captured = capsys.readouterr()
    assert "Connected to http://secobserve.test" in captured.out
    assert "Refusing to start" not in captured.err


def test_print_config_runs_before_the_guard(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """The snippet is how you find out how to supply credentials, and it still must not carry a real token."""
    monkeypatch.setenv(config.ENV_API_TOKEN, "super-secret-token")
    config.get_config.cache_clear()
    monkeypatch.setattr("sys.argv", ["secobserve-mcp", "--transport", "http", "--print-config", "json"])

    assert main() == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["mcpServers"]["secobserve"]["env"][config.ENV_API_TOKEN] == TOKEN_PLACEHOLDER
    assert "super-secret-token" not in captured.out + captured.err

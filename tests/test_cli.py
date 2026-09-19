"""Tests for the command line surface: --version and --print-config."""

from __future__ import annotations

import json
import tomllib

import pytest

from secobserve_mcp import __version__, config
from secobserve_mcp.__main__ import TOKEN_PLACEHOLDER, _print_config, main


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

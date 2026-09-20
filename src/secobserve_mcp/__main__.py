"""Entry point for the SecObserve MCP server.

Defaults to stdio, which is what a local MCP client expects. Streamable HTTP is
available for a shared deployment; it binds to 127.0.0.1 unless told otherwise,
because an MCP server carries the caller's SecObserve credentials.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from . import __version__
from .config import (
    ENV_ALLOW_DELETE,
    ENV_API_TOKEN,
    ENV_BASE_URL,
    ENV_EXPORT_DIR,
    ENV_IMPORT_DIR,
    ENV_JWT,
    ENV_READ_ONLY,
    ENV_TIMEOUT,
    ENV_VERIFY_SSL,
    ConfigError,
    get_config,
)

EPILOG = f"""environment:
  {ENV_BASE_URL}     SecObserve base URL without /api (default http://localhost:8000)
  {ENV_API_TOKEN}    user or product API token (recommended)
  {ENV_JWT}          JWT, as an alternative to an API token
  {ENV_TIMEOUT}      request timeout in seconds (default 60; raise it for imports and scans)
  {ENV_VERIFY_SSL}   set to false only for a self-signed dev certificate
  {ENV_READ_ONLY}    set to true to refuse every write
  {ENV_ALLOW_DELETE} set to true to enable secobserve_delete (deletes cascade)
  {ENV_IMPORT_DIR}   directory uploads may be read from (default: working directory)
  {ENV_EXPORT_DIR}   directory exports are written to (default: ./secobserve-exports)
"""


def _load_tools() -> None:
    # Imported for the @mcp.tool and @mcp.prompt registrations they perform.
    from . import prompts, tools_crud, tools_workflows  # noqa: F401


TOKEN_PLACEHOLDER = "<your-api-token>"

CLIENTS = ("claude", "codex", "json", "vscode")

# Once `uv tool install` has created a persistent environment, a bare `uvx secobserve-mcp` runs that pinned copy
# forever. `@latest` revalidates against the index on every launch; `--isolated` only skips the tool environment and
# may still serve a cached build.
PACKAGE_SPEC = "secobserve-mcp@latest"

PYPI_JSON_URL = "https://pypi.org/pypi/secobserve-mcp/json"
PYPI_TIMEOUT_SECONDS = 3.0


def _print_config(client: str) -> int:
    """Print a registration snippet for one MCP client.

    The base URL comes from the environment; the token never does, because this output gets pasted places.
    """
    base_url = get_config().base_url
    env = {ENV_BASE_URL: base_url, ENV_API_TOKEN: TOKEN_PLACEHOLDER}

    if client == "claude":
        flags = " ".join(f"--env {k}={v}" for k, v in env.items())
        print(f"claude mcp add secobserve {flags} -- uvx {PACKAGE_SPEC}")
    elif client == "codex":
        pairs = ", ".join(f'{k} = "{v}"' for k, v in env.items())
        print("[mcp_servers.secobserve]")
        print('command = "uvx"')
        print(f'args = ["{PACKAGE_SPEC}"]')
        print(f"env = {{ {pairs} }}")
    else:
        # VS Code keys this "servers"; everyone else kept "mcpServers".
        key = "servers" if client == "vscode" else "mcpServers"
        block = {key: {"secobserve": {"command": "uvx", "args": [PACKAGE_SPEC], "env": env}}}
        print(json.dumps(block, indent=2))

    print(f"\nReplace {TOKEN_PLACEHOLDER}; create one with", file=sys.stderr)
    print(f"  curl -X POST {base_url}/api/authentication/create_user_api_token/ \\", file=sys.stderr)
    print('       -H "Content-Type: application/json" \\', file=sys.stderr)
    print('       -d \'{"username": "you", "password": "...", "name": "mcp"}\'', file=sys.stderr)
    return 0


def _runs_from_uv_tool_env() -> bool:
    """Whether this interpreter is a persistent `uv tool install` environment rather than an ephemeral uvx one.

    uv writes uv-receipt.toml at the root of a tool environment and nowhere else; an ephemeral uvx run lives under
    the uv cache with no receipt.
    """
    return (Path(sys.prefix) / "uv-receipt.toml").is_file()


async def _latest_release() -> str | None:
    """The newest version on PyPI, or None when it cannot be determined. Never raises, never called on server start."""
    import httpx

    try:
        async with httpx.AsyncClient(timeout=PYPI_TIMEOUT_SECONDS) as http:
            response = await http.get(PYPI_JSON_URL)
            response.raise_for_status()
            latest = response.json()["info"]["version"]
        return latest if isinstance(latest, str) else None
    except Exception:  # noqa: BLE001 - advisory only; --check must still report on SecObserve
        return None


async def _report_install() -> None:
    latest = await _latest_release()
    if latest is None:
        print(f"  secobserve-mcp: {__version__} (latest release could not be determined)", file=sys.stderr)
    elif latest == __version__:
        print(f"  secobserve-mcp: {__version__} (latest)")
    else:
        print(f"  secobserve-mcp: {__version__} (PyPI has {latest})")

    if _runs_from_uv_tool_env():
        print("  install: a uv tool environment, which `uvx secobserve-mcp` keeps running instead of the latest")
        print(f"  fix: uv tool upgrade secobserve-mcp, or point the client at `uvx {PACKAGE_SPEC}`")


async def _check() -> int:
    from .client import close_client, request

    config = get_config()
    try:
        version = await request("GET", "/status/version/")
        user = await request("GET", "/users/me/")
        print(f"Connected to {config.base_url}")
        print(f"  version: {version.get('version', version)}")
        print(f"  authenticated as: {user.get('username', '?')} (superuser: {user.get('is_superuser', False)})")
        print(f"  read-only: {config.read_only}, deletes enabled: {config.allow_delete}")
        status = 0
    except Exception as exc:  # noqa: BLE001 - the message is the whole point here
        print(f"Check failed: {exc}", file=sys.stderr)
        status = 1
    finally:
        await close_client()

    await _report_install()
    return status


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="secobserve-mcp",
        description="MCP server exposing the SecObserve REST API.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--transport", choices=["stdio", "http"], default="stdio", help="default: stdio")
    parser.add_argument("--host", default="127.0.0.1", help="bind address for --transport http")
    parser.add_argument("--port", type=int, default=8931, help="port for --transport http")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify connectivity, credentials and that this install is current, then exit",
    )
    parser.add_argument(
        "--print-config",
        choices=CLIENTS,
        metavar="CLIENT",
        help=f"print a registration snippet for one of: {', '.join(CLIENTS)}",
    )
    parser.add_argument("--version", action="version", version=f"secobserve-mcp {__version__}")
    args = parser.parse_args()

    # Before the credential check: this is how you find out how to supply them.
    if args.print_config:
        return _print_config(args.print_config)

    _load_tools()
    from .app import mcp

    try:
        config = get_config()
        _ = config.auth_header
    except ConfigError as exc:
        # stdio clients swallow stdout, so configuration problems go to stderr.
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    if args.check:
        return asyncio.run(_check())

    if args.transport == "http":
        mcp.run(
            transport="streamable-http",
            host=args.host,
            port=args.port,
            stateless_http=True,
            json_response=True,
        )
    else:
        mcp.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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


def _print_config(client: str) -> int:
    """Print a registration snippet for one MCP client.

    The base URL comes from the environment; the token never does, because this output gets pasted places.
    """
    base_url = get_config().base_url
    env = {ENV_BASE_URL: base_url, ENV_API_TOKEN: TOKEN_PLACEHOLDER}

    if client == "claude":
        flags = " ".join(f"--env {k}={v}" for k, v in env.items())
        print(f"claude mcp add secobserve {flags} -- uvx secobserve-mcp")
    elif client == "codex":
        pairs = ", ".join(f'{k} = "{v}"' for k, v in env.items())
        print("[mcp_servers.secobserve]")
        print('command = "uvx"')
        print('args = ["secobserve-mcp"]')
        print(f"env = {{ {pairs} }}")
    else:
        # VS Code keys this "servers"; everyone else kept "mcpServers".
        key = "servers" if client == "vscode" else "mcpServers"
        block = {key: {"secobserve": {"command": "uvx", "args": ["secobserve-mcp"], "env": env}}}
        print(json.dumps(block, indent=2))

    print(f"\nReplace {TOKEN_PLACEHOLDER}; create one with", file=sys.stderr)
    print(f"  curl -X POST {base_url}/api/authentication/create_user_api_token/ \\", file=sys.stderr)
    print('       -H "Content-Type: application/json" \\', file=sys.stderr)
    print('       -d \'{"username": "you", "password": "...", "name": "mcp"}\'', file=sys.stderr)
    return 0


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
        return 0
    except Exception as exc:  # noqa: BLE001 - the message is the whole point here
        print(f"Check failed: {exc}", file=sys.stderr)
        return 1
    finally:
        await close_client()


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
    parser.add_argument("--check", action="store_true", help="verify connectivity and credentials, then exit")
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

"""Entry point for the SecObserve MCP server.

Defaults to stdio, which is what a local MCP client expects. Streamable HTTP is
available for a shared deployment; it binds to 127.0.0.1 unless told otherwise,
because an MCP server carries the caller's SecObserve credentials.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

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
    # Imported for the @mcp.tool registrations they perform.
    from . import tools_crud, tools_workflows  # noqa: F401


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
    args = parser.parse_args()

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
        # Stateless JSON: no per-client session state to scale or expire.
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

"""MCP server for SecObserve, an open-source vulnerability and license management platform."""

from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

try:
    # Read from installed package metadata so the version lives only in pyproject.toml.
    __version__ = version("secobserve-mcp")
except PackageNotFoundError:  # pragma: no cover - only when running from a bare checkout
    __version__ = "0.0.0+unknown"

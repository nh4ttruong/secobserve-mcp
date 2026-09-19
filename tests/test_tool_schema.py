"""The shape of the tool schemas the server publishes."""

from __future__ import annotations

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from secobserve_mcp import tools_crud, tools_workflows  # noqa: F401  (import registers the tools)
from secobserve_mcp.app import mcp


async def test_unknown_tool_arguments_are_rejected() -> None:
    """Flat arguments lose extra="forbid" unless app.py puts it back on ArgModelBase.

    Without it, `filter=` instead of `filters=` is dropped in silence and the unfiltered
    list comes back as if it were the answer.
    """
    with pytest.raises(ToolError, match="filter"):
        await mcp.call_tool("secobserve_list", {"resource": "products", "filter": {"id": 1}})


async def test_every_tool_publishes_flat_arguments() -> None:
    for tool in await mcp.list_tools():
        assert tool.input_schema.get("additionalProperties") is False, tool.name
        properties = tool.input_schema["properties"]
        # call_action forwards query parameters, so it owns the one legitimate "params".
        assert "params" not in properties or tool.name == "secobserve_call_action", tool.name

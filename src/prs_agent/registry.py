"""Tool registry and validation boundary."""

from __future__ import annotations

from typing import Any

from prs_agent.contracts import ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool


class ToolRegistry:
    """Registry of tools that Bifrost is allowed to call."""

    def __init__(self) -> None:
        self._tools: dict[str, BaseTool] = {}

    def register(self, tool: BaseTool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def list_schemas(self, tool_names: set[str] | None = None) -> list[dict[str, Any]]:
        if tool_names is None:
            return [tool.schema_for_model() for tool in self._tools.values()]
        return [tool.schema_for_model() for name, tool in self._tools.items() if name in tool_names]

    def execute(
        self,
        *,
        tool_name: str | None,
        arguments: dict[str, Any],
        context: ToolContext,
    ) -> ToolResult:
        """Validate and execute a registered tool."""

        if not tool_name or tool_name not in self._tools:
            return ToolResult(
                tool_name=tool_name or "<missing>",
                status=ToolStatus.VALIDATION_ERROR,
                summary="Bifrost requested an unknown tool.",
                error=f"Unknown tool. Available tools: {sorted(self._tools)}",
            )

        tool = self._tools[tool_name]
        validation_error = tool.validate(arguments)
        if validation_error:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.VALIDATION_ERROR,
                summary="Tool arguments failed validation.",
                error=validation_error,
            )

        try:
            return tool.run(arguments=arguments, context=context)
        except Exception as exc:  # Defensive boundary; individual tools should normalize expected failures.
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                summary="Tool wrapper raised an unhandled exception.",
                error=f"{type(exc).__name__}: {exc}",
            )

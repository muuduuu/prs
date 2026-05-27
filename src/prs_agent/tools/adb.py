"""Mock-friendly ADB tool wrapper."""

from __future__ import annotations

from prs_agent.contracts import ToolContext, ToolResult
from prs_agent.tools.base import BaseTool
from prs_agent.tools.subprocess_tool import SubprocessRunner


class AdbTool(BaseTool):
    """Allow-listed ADB wrapper.

    The skeleton exposes only harmless discovery commands. More operations can
    be added as explicit enum values with purpose-built argument handling.
    """

    name = "adb"
    description = "Run allow-listed Android Debug Bridge discovery commands."
    args_schema = {
        "type": "object",
        "required": ["subcommand"],
        "properties": {
            "subcommand": {
                "type": "string",
                "enum": ["devices", "version", "packages_third_party"],
            }
        },
    }

    def __init__(self, runner: SubprocessRunner | None = None) -> None:
        self.runner = runner or SubprocessRunner()

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        subcommand = arguments["subcommand"]
        argv = ["adb", subcommand]
        if subcommand == "packages_third_party":
            argv = ["adb", "shell", "pm", "list", "packages", "-3"]
        return self.runner.run(
            tool_name=self.name,
            argv=argv,
            cwd=context.workspace_dir,
            timeout_seconds=context.timeout_seconds,
        )

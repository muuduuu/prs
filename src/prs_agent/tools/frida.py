"""Frida readiness and session discovery wrapper."""

from __future__ import annotations

from prs_agent.contracts import ToolContext, ToolResult
from prs_agent.tools.base import BaseTool
from prs_agent.tools.subprocess_tool import SubprocessRunner


class FridaTool(BaseTool):
    """Allow-listed Frida commands for runtime instrumentation readiness."""

    name = "frida"
    description = "Run allow-listed Frida discovery commands such as version and process listing."
    args_schema = {
        "type": "object",
        "required": ["subcommand"],
        "properties": {
            "subcommand": {"type": "string", "enum": ["version", "ps_usb"]},
        },
    }

    def __init__(self, runner: SubprocessRunner | None = None) -> None:
        self.runner = runner or SubprocessRunner()

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        subcommand = arguments["subcommand"]
        argv = ["frida", "--version"] if subcommand == "version" else ["frida-ps", "-Uai"]
        return self.runner.run(
            tool_name=self.name,
            argv=argv,
            cwd=context.workspace_dir,
            timeout_seconds=context.timeout_seconds,
        )

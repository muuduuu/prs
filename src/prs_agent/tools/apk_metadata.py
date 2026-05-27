"""APK metadata extraction with aapt."""

from __future__ import annotations

from prs_agent.contracts import ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file
from prs_agent.tools.subprocess_tool import SubprocessRunner


class ApkMetadataTool(BaseTool):
    """Extract package, SDK, permissions, and launchable activity metadata."""

    name = "apk_metadata"
    description = "Run aapt dump badging on an APK to extract manifest-level metadata."
    args_schema = {
        "type": "object",
        "required": ["apk_path"],
        "properties": {
            "apk_path": {"type": "string", "description": "Path to an APK inside the workspace."}
        },
    }

    def __init__(self, runner: SubprocessRunner | None = None) -> None:
        self.runner = runner or SubprocessRunner()

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        apk_path, error = resolve_workspace_file(context, arguments["apk_path"], self.name)
        if error:
            return error

        result = self.runner.run(
            tool_name=self.name,
            argv=["aapt", "dump", "badging", str(apk_path)],
            cwd=context.workspace_dir,
            timeout_seconds=context.timeout_seconds,
        )
        if result.status == ToolStatus.SUCCESS:
            result.summary = "Extracted APK package metadata with aapt."
        return result

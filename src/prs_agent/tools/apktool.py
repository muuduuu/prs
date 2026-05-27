"""Mock-friendly apktool wrapper."""

from __future__ import annotations

from pathlib import Path

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file
from prs_agent.tools.subprocess_tool import SubprocessRunner


class ApktoolDecompilerTool(BaseTool):
    """Decompile an APK into the run artifact directory."""

    name = "apktool_decompile"
    description = "Decompile an APK with apktool and return the output directory artifact."
    args_schema = {
        "type": "object",
        "required": ["apk_path"],
        "properties": {
            "apk_path": {
                "type": "string",
                "description": "Path to an APK inside the workspace.",
            }
        },
    }

    def __init__(self, runner: SubprocessRunner | None = None) -> None:
        self.runner = runner or SubprocessRunner()

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        apk_path, error = resolve_workspace_file(context, arguments["apk_path"], self.name)
        if error:
            return error

        output_dir = context.artifacts_dir / "apktool" / Path(apk_path).stem
        output_dir.parent.mkdir(parents=True, exist_ok=True)

        result = self.runner.run(
            tool_name=self.name,
            argv=["apktool", "d", "-f", str(apk_path), "-o", str(output_dir)],
            cwd=context.workspace_dir,
            timeout_seconds=context.timeout_seconds,
        )

        if result.status == ToolStatus.SUCCESS:
            result.summary = f"Decompiled APK to {output_dir}."
            result.artifacts.append(
                Artifact(
                    kind="directory",
                    path=str(output_dir),
                    description="apktool decompiled project directory",
                )
            )

        return result

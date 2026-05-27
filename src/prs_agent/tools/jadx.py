"""JADX decompiler wrapper."""

from __future__ import annotations

from pathlib import Path

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file
from prs_agent.tools.subprocess_tool import SubprocessRunner


class JadxDecompilerTool(BaseTool):
    """Decompile APK bytecode into Java/Kotlin-like source."""

    name = "jadx_decompile"
    description = "Decompile an APK with JADX and return the generated source directory."
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

        output_dir = context.artifacts_dir / "jadx" / Path(apk_path).stem
        output_dir.parent.mkdir(parents=True, exist_ok=True)
        result = self.runner.run(
            tool_name=self.name,
            argv=["jadx", "-d", str(output_dir), str(apk_path)],
            cwd=context.workspace_dir,
            timeout_seconds=context.timeout_seconds,
        )
        if result.status == ToolStatus.SUCCESS:
            result.summary = f"Decompiled APK sources to {output_dir}."
            result.artifacts.append(
                Artifact(kind="directory", path=str(output_dir), description="JADX source output directory")
            )
        return result

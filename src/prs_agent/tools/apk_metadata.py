"""APK metadata extraction with a pure-Python primary path and aapt fallback."""

from __future__ import annotations

import json
import shutil
from typing import Any

from prs_agent.contracts import ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file
from prs_agent.tools.subprocess_tool import SubprocessRunner


class ApkMetadataTool(BaseTool):
    """Extract package, SDK, permissions, and launchable activity metadata."""

    name = "apk_metadata"
    description = "Extract AndroidManifest metadata from an APK (package, permissions, SDK levels, activities)."
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

        if shutil.which("aapt"):
            return self._run_aapt(apk_path, context)
        return self._run_python(apk_path)

    def _run_aapt(self, apk_path: Any, context: ToolContext) -> ToolResult:
        result = self.runner.run(
            tool_name=self.name,
            argv=["aapt", "dump", "badging", str(apk_path)],
            cwd=context.workspace_dir,
            timeout_seconds=context.timeout_seconds,
        )
        if result.status == ToolStatus.SUCCESS:
            result.summary = "Extracted APK package metadata with aapt."
        return result

    def _run_python(self, apk_path: Any) -> ToolResult:
        try:
            from pyaxmlparser import APK  # type: ignore[import-untyped]
        except ImportError:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                summary="pyaxmlparser is not installed and aapt is not on PATH.",
                error="Run: pip install pyaxmlparser",
            )

        try:
            apk = APK(str(apk_path))
        except Exception as exc:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                summary="Failed to parse APK.",
                error=f"{type(exc).__name__}: {exc}",
            )

        try:
            activities = list(apk.get_activities() or [])
            permissions = sorted(apk.get_permissions() or [])
            main_activity = _find_main_activity(apk, activities)

            metadata: dict[str, Any] = {
                "package": apk.get_package(),
                "version_name": apk.get_androidversion_name(),
                "version_code": apk.get_androidversion_code(),
                "min_sdk": apk.get_min_sdk_version(),
                "target_sdk": apk.get_target_sdk_version(),
                "max_sdk": apk.get_max_sdk_version() or None,
                "permissions": permissions,
                "activities": activities,
                "main_activity": main_activity,
                "services": list(apk.get_services() or []),
                "receivers": list(apk.get_receivers() or []),
                "providers": list(apk.get_providers() or []),
            }

            summary_lines = [
                f"package: {metadata['package']}  version: {metadata['version_name']} ({metadata['version_code']})",
                f"sdk: min={metadata['min_sdk']} target={metadata['target_sdk']}",
                f"permissions ({len(permissions)}): {', '.join(permissions[:8])}" + (" ..." if len(permissions) > 8 else ""),
                f"main activity: {main_activity or 'unknown'}",
            ]

            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.SUCCESS,
                summary="Extracted APK package metadata.",
                stdout_excerpt="\n".join(summary_lines),
                metadata=metadata,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                summary="Metadata extraction failed after parsing.",
                error=f"{type(exc).__name__}: {exc}",
            )


def _find_main_activity(apk: Any, activities: list[str]) -> str | None:
    try:
        declared = apk.get_main_activity()
        if declared:
            return declared
    except Exception:
        pass
    for act in activities:
        if "MainActivity" in act or "LauncherActivity" in act:
            return act
    return activities[0] if activities else None

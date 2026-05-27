"""Tool wrapper exposing reverse-analysis subagent workflows."""

from __future__ import annotations

from typing import Any

from prs_agent.contracts import ToolContext, ToolResult, ToolStatus
from prs_agent.subagents import build_reverse_analysis_plan
from prs_agent.tools.base import BaseTool


class ReverseAnalysisPlanTool(BaseTool):
    """Return a bounded specialist workflow plan for reverse analysis."""

    name = "reverse_analysis_plan"
    description = (
        "Describe specialist reverse-analysis subagents, responsibilities, "
        "handoffs, and guardrails for the current APK assessment."
    )
    args_schema: dict[str, Any] = {
        "type": "object",
        "required": ["objective"],
        "properties": {
            "objective": {
                "type": "string",
                "description": "The assessment objective to plan against.",
            },
            "apk_path": {
                "type": "string",
                "description": "Optional APK path relative to the workspace.",
            },
            "include_dynamic": {
                "type": "boolean",
                "description": "Whether to include the dynamic/device analyst lane.",
            },
            "include_mobsf": {
                "type": "boolean",
                "description": "Whether to include the MobSF triage analyst lane.",
            },
        },
    }

    def run(self, *, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        plan = build_reverse_analysis_plan(
            objective=arguments["objective"],
            apk_path=arguments.get("apk_path"),
            include_dynamic=bool(arguments.get("include_dynamic", True)),
            include_mobsf=bool(arguments.get("include_mobsf", True)),
        )
        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            summary="Prepared reverse-analysis subagent workflow scaffold.",
            metadata=plan,
        )

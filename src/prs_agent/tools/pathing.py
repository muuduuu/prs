"""Path helpers for workspace-confined tool arguments."""

from __future__ import annotations

from pathlib import Path

from prs_agent.contracts import ToolContext, ToolResult, ToolStatus


def resolve_workspace_file(context: ToolContext, relative_path: str, tool_name: str) -> tuple[Path | None, ToolResult | None]:
    """Resolve a user/model-provided file path while preventing workspace escape."""

    candidate = (context.workspace_dir / relative_path).resolve()
    workspace_root = context.workspace_dir.resolve()
    if not str(candidate).startswith(str(workspace_root)):
        return None, ToolResult(
            tool_name=tool_name,
            status=ToolStatus.VALIDATION_ERROR,
            summary="Path must remain inside the workspace.",
            error="path_escape",
        )
    if not candidate.exists():
        return None, ToolResult(
            tool_name=tool_name,
            status=ToolStatus.VALIDATION_ERROR,
            summary="Path does not exist.",
            error=f"Missing file: {candidate}",
        )
    return candidate, None

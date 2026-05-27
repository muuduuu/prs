"""Shared data contracts for the ReAct orchestrator."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4


def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp suitable for logs."""

    return datetime.now(timezone.utc).isoformat()


def new_run_id() -> str:
    """Create a compact run id with time ordering and random uniqueness."""

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{uuid4().hex[:8]}"


class ToolStatus(str, Enum):
    """Normalized outcome categories for every tool invocation."""

    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    VALIDATION_ERROR = "validation_error"


@dataclass(slots=True)
class Artifact:
    """Reference to a generated or captured artifact.

    Large files should be referenced here instead of copied into model context.
    """

    kind: str
    path: str
    description: str = ""
    sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "description": self.description,
            "sha256": self.sha256,
        }


@dataclass(slots=True)
class ToolResult:
    """A compact observation returned by every tool."""

    tool_name: str
    status: ToolStatus
    summary: str
    exit_code: int | None = None
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    artifacts: list[Artifact] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_observation(self) -> dict[str, Any]:
        """Return the model-safe observation form."""

        return {
            "tool_name": self.tool_name,
            "status": self.status.value,
            "summary": self.summary,
            "exit_code": self.exit_code,
            "stdout_excerpt": self.stdout_excerpt,
            "stderr_excerpt": self.stderr_excerpt,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "metadata": self.metadata,
            "error": self.error,
        }


@dataclass(slots=True)
class ToolContext:
    """Execution context shared with tool wrappers."""

    run_id: str
    workspace_dir: Path
    artifacts_dir: Path
    timeout_seconds: int = 120
    environment: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class BifrostDecision:
    """Structured decision returned by Bifrost."""

    type: Literal["tool_call", "final"]
    thought: str
    tool_name: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    answer: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AgentRunResult:
    """Final result returned to API callers."""

    run_id: str
    status: Literal["completed", "max_iterations", "error"]
    final_answer: dict[str, Any]
    trace_path: Path


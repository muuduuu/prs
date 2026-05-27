"""Local entrypoint for exercising the skeleton orchestrator."""

from __future__ import annotations

from pathlib import Path

from prs_agent.bifrost import MockBifrostClient
from prs_agent.orchestrator import AgentOrchestrator
from prs_agent.registry import ToolRegistry
from prs_agent.tools import AdbTool, ApktoolDecompilerTool, ReverseAnalysisPlanTool


def build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(ReverseAnalysisPlanTool())
    registry.register(AdbTool())
    registry.register(ApktoolDecompilerTool())
    return registry


def main() -> None:
    workspace = Path.cwd()
    orchestrator = AgentOrchestrator(
        bifrost=MockBifrostClient(),
        registry=build_default_registry(),
        workspace_dir=workspace,
    )
    result = orchestrator.run(
        "Run a mock initial mobile assessment and demonstrate the ReAct pipeline."
    )
    print(f"Run {result.run_id} finished with status={result.status}")
    print(f"Trace written to {result.trace_path}")


if __name__ == "__main__":
    main()

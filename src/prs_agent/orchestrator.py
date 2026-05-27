"""Main ReAct orchestration loop."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from prs_agent.bifrost import BifrostClient
from prs_agent.context import MemoryBuffer, compact_tool_result
from prs_agent.contracts import AgentRunResult, ToolContext, new_run_id
from prs_agent.logger import TraceLogger
from prs_agent.registry import ToolRegistry
from prs_agent.subagents import specialist_manifest


class AgentOrchestrator:
    """Coordinates Bifrost decisions, tool execution, context, and logging."""

    def __init__(
        self,
        *,
        bifrost: BifrostClient,
        registry: ToolRegistry,
        workspace_dir: Path,
        max_iterations: int = 10,
        tool_timeout_seconds: int = 120,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.bifrost = bifrost
        self.registry = registry
        self.workspace_dir = workspace_dir
        self.max_iterations = max_iterations
        self.tool_timeout_seconds = tool_timeout_seconds
        self.on_event = on_event

    def run(self, objective: str, run_id: str | None = None) -> AgentRunResult:
        run_id = run_id or new_run_id()
        run_dir = self.workspace_dir / "runs" / run_id
        artifacts_dir = run_dir / "artifacts"
        logs_dir = run_dir / "logs"
        trace_jsonl = logs_dir / "trace.jsonl"
        trace_json = logs_dir / "trace.json"

        context = ToolContext(
            run_id=run_id,
            workspace_dir=self.workspace_dir,
            artifacts_dir=artifacts_dir,
            timeout_seconds=self.tool_timeout_seconds,
        )
        memory = MemoryBuffer()
        logger = TraceLogger(
            run_id=run_id,
            objective=objective,
            log_path=trace_jsonl,
            bifrost_model=self.bifrost.model_name,
            on_event=self.on_event,
        )
        logger.event(
            phase="subagent_manifest",
            observation={"subagents": specialist_manifest()},
            labels={"success": True, "requires_human_review": False},
        )

        final_answer: dict[str, Any] = {}

        for _ in range(self.max_iterations):
            decision = self.bifrost.decide(
                objective=objective,
                tool_schemas=self.registry.list_schemas(),
                memory=memory.snapshot(),
            )

            if decision.type == "final":
                final_answer = decision.answer
                logger.event(
                    phase="final",
                    thought=decision.thought,
                    observation=final_answer,
                    labels={"success": True, "requires_human_review": False},
                )
                logger.write_final_trace(trace_json, final_answer)
                return AgentRunResult(
                    run_id=run_id,
                    status="completed",
                    final_answer=final_answer,
                    trace_path=trace_json,
                )

            action = {
                "tool_name": decision.tool_name,
                "arguments": decision.arguments,
            }
            logger.event(phase="thought_action", thought=decision.thought, action=action)

            result = self.registry.execute(
                tool_name=decision.tool_name,
                arguments=decision.arguments,
                context=context,
            )
            observation = compact_tool_result(result)
            logger.event(
                phase="observation",
                thought=decision.thought,
                action=action,
                observation=observation,
                labels={
                    "success": result.status.value == "success",
                    "error_category": None if result.status.value == "success" else result.status.value,
                    "requires_human_review": False,
                },
            )
            memory.append(
                {
                    "thought": decision.thought,
                    "action": action,
                    "observation": observation,
                }
            )
            logger.next_step()

        final_answer = {
            "summary": "Maximum ReAct iterations reached before Bifrost returned a final answer.",
            "max_iterations": self.max_iterations,
        }
        logger.event(
            phase="final",
            observation=final_answer,
            labels={"success": False, "error_category": "max_iterations"},
        )
        logger.write_final_trace(trace_json, final_answer)
        return AgentRunResult(
            run_id=run_id,
            status="max_iterations",
            final_answer=final_answer,
            trace_path=trace_json,
        )

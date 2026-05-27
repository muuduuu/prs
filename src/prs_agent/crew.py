"""Bifrost-backed specialist crew orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from prs_agent.bifrost import BifrostClient
from prs_agent.context import MemoryBuffer, compact_tool_result
from prs_agent.contracts import AgentRunResult, BifrostDecision, ToolContext, new_run_id
from prs_agent.logger import TraceLogger
from prs_agent.registry import ToolRegistry
from prs_agent.subagents import REVERSE_ANALYSIS_SUBAGENTS, specialist_manifest


@dataclass(frozen=True, slots=True)
class CrewConfig:
    apk_path: str | None
    include_device_checks: bool
    max_steps_per_agent: int = 6


class CrewOrchestrator:
    """Runs specialist Bifrost agents with restricted toolsets."""

    def __init__(
        self,
        *,
        bifrost: BifrostClient,
        registry: ToolRegistry,
        workspace_dir: Path,
        config: CrewConfig,
        tool_timeout_seconds: int = 120,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.bifrost = bifrost
        self.registry = registry
        self.workspace_dir = workspace_dir
        self.config = config
        self.tool_timeout_seconds = tool_timeout_seconds
        self.on_event = on_event

    def run(self, objective: str, run_id: str | None = None) -> AgentRunResult:
        run_id = run_id or new_run_id()
        run_dir = self.workspace_dir / "runs" / run_id
        artifacts_dir = run_dir / "artifacts"
        logs_dir = run_dir / "logs"
        trace_json = logs_dir / "trace.json"
        logger = TraceLogger(
            run_id=run_id,
            objective=objective,
            log_path=logs_dir / "trace.jsonl",
            bifrost_model=self.bifrost.model_name,
            on_event=self.on_event,
        )
        context = ToolContext(
            run_id=run_id,
            workspace_dir=self.workspace_dir,
            artifacts_dir=artifacts_dir,
            timeout_seconds=self.tool_timeout_seconds,
        )

        manifest = specialist_manifest()
        logger.event(
            phase="crew_manifest",
            observation={"subagents": manifest, "mode": "bifrost_crew"},
            labels={"success": True, "requires_human_review": False},
        )

        roles = [role for role in REVERSE_ANALYSIS_SUBAGENTS if self._role_enabled(role.identifier)]
        lane_results: list[dict[str, Any]] = []
        primary_roles = [
            role
            for role in roles
            if role.identifier in {"static_reverse", "mobsf_triage", "dynamic_device"}
        ]
        dependent_roles = [
            role
            for role in roles
            if role.identifier not in {"static_reverse", "mobsf_triage", "dynamic_device", "report_synthesis"}
        ]

        with ThreadPoolExecutor(max_workers=max(1, len(primary_roles))) as executor:
            futures = {
                executor.submit(self._run_lane, role, objective, context, logger, []): role.identifier
                for role in primary_roles
            }
            for future in as_completed(futures):
                lane_results.append(future.result())

        if dependent_roles:
            with ThreadPoolExecutor(max_workers=max(1, len(dependent_roles))) as executor:
                futures = {
                    executor.submit(self._run_lane, role, objective, context, logger, lane_results): role.identifier
                    for role in dependent_roles
                }
                for future in as_completed(futures):
                    lane_results.append(future.result())

        final_answer = self._synthesize_report(objective, lane_results)
        logger.event(
            phase="crew_final",
            thought="Report Synthesis Analyst consolidated specialist lane outputs.",
            observation=final_answer,
            labels={"success": True, "agent": "report_synthesis", "requires_human_review": False},
        )
        logger.write_final_trace(trace_json, final_answer)
        return AgentRunResult(
            run_id=run_id,
            status="completed",
            final_answer=final_answer,
            trace_path=trace_json,
        )

    def _role_enabled(self, role_id: str) -> bool:
        if role_id == "dynamic_device":
            return self.config.include_device_checks
        return True

    def _run_lane(
        self,
        role,
        objective: str,
        context: ToolContext,
        logger: TraceLogger,
        prior_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        memory = MemoryBuffer(max_items=10)
        artifact_conventions = self._artifact_conventions(context)
        lane_context = {
            "agent_id": role.identifier,
            "agent_name": role.name,
            "mission": role.mission,
            "apk_path": self.config.apk_path,
            "workflow": list(role.workflow),
            "outputs_expected": list(role.outputs),
            "artifact_conventions": artifact_conventions,
            "prior_lane_results": prior_results,
        }
        logger.event(
            phase="agent_start",
            observation=lane_context,
            labels={"success": True, "agent": role.identifier},
        )

        final: dict[str, Any] | None = None
        tool_names = set(role.tool_focus)
        if role.identifier == "static_reverse":
            tool_names.add("reverse_analysis_plan")
        if role.identifier == "mobsf_triage":
            tool_names.update({"mobsf_submit", "mobsf_poll"})
        if role.identifier == "exploitability_validation":
            tool_names.update({"finding_compile"})

        for _ in range(self.config.max_steps_per_agent):
            decision = self._decide_for_role(role, objective, tool_names, memory.snapshot(), lane_context)
            if decision.type == "final":
                final = decision.answer or {"summary": decision.thought}
                logger.event(
                    phase="agent_final",
                    thought=decision.thought,
                    observation=final,
                    labels={"success": True, "agent": role.identifier},
                )
                break

            action = {"tool_name": decision.tool_name, "arguments": decision.arguments}
            logger.event(
                phase="agent_thought_action",
                thought=decision.thought,
                action=action,
                labels={"agent": role.identifier},
            )
            result = self.registry.execute(
                tool_name=decision.tool_name,
                arguments=decision.arguments,
                context=context,
            )
            observation = compact_tool_result(result)
            logger.event(
                phase="agent_observation",
                thought=decision.thought,
                action=action,
                observation=observation,
                labels={
                    "success": result.status.value == "success",
                    "agent": role.identifier,
                    "error_category": None if result.status.value == "success" else result.status.value,
                },
            )
            memory.append({"thought": decision.thought, "action": action, "observation": observation})
            if self._lane_can_stop(role.identifier, observation):
                final = {"summary": f"{role.name} lane completed bounded work.", "last_observation": observation}
                break

        if final is None:
            final = {
                "summary": f"{role.name} reached its per-agent step budget.",
                "memory": memory.snapshot(),
            }
        return {"agent": role.identifier, "name": role.name, "result": final, "memory": memory.snapshot()}

    def _decide_for_role(
        self,
        role,
        objective: str,
        tool_names: set[str],
        memory: list[dict[str, Any]],
        lane_context: dict[str, Any],
    ) -> BifrostDecision:
        if hasattr(self.bifrost, "decide_for_role"):
            return self.bifrost.decide_for_role(
                role_name=role.name,
                mission=role.mission,
                objective=objective,
                tool_schemas=self.registry.list_schemas(tool_names),
                memory=memory,
                extra_context=lane_context,
            )
        return self.bifrost.decide(
            objective=objective,
            tool_schemas=self.registry.list_schemas(tool_names),
            memory=memory,
        )

    def _lane_can_stop(self, role_id: str, observation: dict[str, Any]) -> bool:
        if role_id == "mobsf_triage":
            status = observation.get("metadata", {}).get("job_status")
            return status == "completed" or observation.get("status") == "validation_error"
        return observation.get("status") in {"validation_error", "error"} and role_id == "dynamic_device"

    def _artifact_conventions(self, context: ToolContext) -> dict[str, str]:
        if not self.config.apk_path:
            return {
                "findings_dir": self._workspace_relative(context.artifacts_dir / "findings", context),
                "report_dir": self._workspace_relative(context.artifacts_dir / "report", context),
            }
        apk_stem = Path(self.config.apk_path).stem
        return {
            "jadx_output": self._workspace_relative(context.artifacts_dir / "jadx" / apk_stem, context),
            "apktool_output": self._workspace_relative(context.artifacts_dir / "apktool" / apk_stem, context),
            "findings_dir": self._workspace_relative(context.artifacts_dir / "findings", context),
            "report_dir": self._workspace_relative(context.artifacts_dir / "report", context),
        }

    def _workspace_relative(self, path: Path, context: ToolContext) -> str:
        try:
            return str(path.resolve().relative_to(context.workspace_dir.resolve()))
        except ValueError:
            return str(path)

    def _synthesize_report(self, objective: str, lane_results: list[dict[str, Any]]) -> dict[str, Any]:
        report_role = next(
            (role for role in REVERSE_ANALYSIS_SUBAGENTS if role.identifier == "report_synthesis"),
            None,
        )
        if report_role and hasattr(self.bifrost, "decide_for_role"):
            decision = self.bifrost.decide_for_role(
                role_name=report_role.name,
                mission=report_role.mission,
                objective=objective,
                tool_schemas=[],
                memory=lane_results,
                extra_context={
                    "agent_id": report_role.identifier,
                    "agent_name": report_role.name,
                    "instruction": "Return type=final with a concise assessment summary, findings, artifacts, blocked checks, and next steps.",
                },
            )
            if decision.type == "final" and decision.answer:
                decision.answer.setdefault("mode", "bifrost_crew")
                decision.answer.setdefault("agents", lane_results)
                return decision.answer

        artifacts: list[dict[str, Any]] = []
        for lane in lane_results:
            for item in lane.get("memory", []):
                artifacts.extend(item.get("observation", {}).get("artifacts") or [])
        return {
            "summary": "Bifrost specialist crew run completed.",
            "objective": objective,
            "mode": "bifrost_crew",
            "agents": lane_results,
            "artifacts": artifacts,
            "next_steps": [
                "Review each specialist lane for blocked prerequisites.",
                "Correlate MobSF findings with static reverse artifacts.",
                "Run dynamic checks on a connected authorized device when available.",
            ],
        }

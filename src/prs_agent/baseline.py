"""Deterministic baseline assessment pipeline.

The Bifrost crew is useful for triage and adaptive reasoning, but a real
assessment should not depend on the model choosing every obvious first step.
This module runs the core APK pipeline directly through the registered tool
boundary, then hands compact observations to specialist lanes for reasoning.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from prs_agent.context import compact_tool_result
from prs_agent.contracts import ToolContext, ToolResult
from prs_agent.logger import TraceLogger
from prs_agent.registry import ToolRegistry


class BaselineAssessmentRunner:
    """Run the default static/MobSF/report pipeline for a provided APK."""

    def __init__(
        self,
        *,
        registry: ToolRegistry,
        context: ToolContext,
        logger: TraceLogger,
        apk_path: str | None,
        include_device_checks: bool,
    ) -> None:
        self.registry = registry
        self.context = context
        self.logger = logger
        self.apk_path = apk_path
        self.include_device_checks = include_device_checks
        self.memory: list[dict[str, Any]] = []
        self.package_name: str | None = None

    def run(self, objective: str) -> dict[str, Any]:
        """Execute baseline tools and return a lane-like result."""

        self.logger.event(
            phase="baseline_start",
            observation={
                "summary": "Starting deterministic baseline assessment pipeline.",
                "apk_path": self.apk_path,
                "include_device_checks": self.include_device_checks,
            },
            labels={"success": True, "agent": "baseline_pipeline"},
        )

        if not self.apk_path:
            result = {
                "summary": "No APK was provided, so baseline APK reversing was skipped.",
                "blocked_prerequisites": ["Upload or provide an APK path."],
            }
            self.logger.event(
                phase="baseline_final",
                observation=result,
                labels={"success": False, "agent": "baseline_pipeline", "error_category": "missing_apk"},
            )
            return {"agent": "baseline_pipeline", "name": "Baseline Pipeline", "result": result, "memory": []}

        apk_stem = Path(self.apk_path).stem
        apktool_dir = self._rel(self.context.artifacts_dir / "apktool" / apk_stem)
        jadx_dir = self._rel(self.context.artifacts_dir / "jadx" / apk_stem)

        self._execute(
            "reverse_analysis_plan",
            {
                "objective": objective,
                "apk_path": self.apk_path,
                "include_dynamic": self.include_device_checks,
                "include_mobsf": True,
            },
            "Create the reverse-analysis work plan.",
        )
        self._execute("mobsf_submit", {"apk_path": self.apk_path}, "Submit APK to MobSF early if configured.")

        metadata = self._execute("apk_metadata", {"apk_path": self.apk_path}, "Extract package metadata.")
        self._capture_package(metadata)
        manifest = self._execute("manifest_findings", {"apk_path": self.apk_path}, "Analyze manifest findings.")
        self._capture_package(manifest)

        apktool = self._execute("apktool_decompile", {"apk_path": self.apk_path}, "Decompile resources and smali.")
        if self._ok(apktool):
            self._execute(
                "network_security_audit",
                {"apktool_dir": apktool_dir},
                "Audit Network Security Config from apktool output.",
            )
            self._source_suite(apktool_dir, label="apktool")

        jadx = self._execute("jadx_decompile", {"apk_path": self.apk_path}, "Decompile Java/Kotlin sources.")
        if self._ok(jadx):
            self._execute(
                "dependency_inventory",
                {"source_dir": jadx_dir},
                "Inventory dependencies and namespaces from JADX output.",
            )
            self._execute(
                "source_inventory",
                {"source_dir": jadx_dir},
                "Inventory endpoints, APIs, storage, crypto, native, and IPC from JADX output.",
            )
            self._execute("secret_scan", {"source_dir": jadx_dir}, "Scan JADX output for secrets.")
            self._execute("webview_audit", {"source_dir": jadx_dir}, "Audit WebView usage from JADX output.")

        poll = self._execute(
            "mobsf_poll",
            {"wait_seconds": 240},
            "Poll MobSF patiently for scanner results after local reverse work.",
        )
        for artifact in poll.artifacts:
            if artifact.kind == "json" and "report" in artifact.description.lower():
                self._execute(
                    "mobsf_findings",
                    {"report_path": artifact.path},
                    "Normalize MobSF report into findings.",
                )

        compiled = self._execute("finding_compile", {}, "Compile all findings into one report.")
        if self.package_name:
            self._execute(
                "exploit_verify",
                {"package": self.package_name, "skip_runtime": not self.include_device_checks},
                "Validate exploitability where bounded checks are available.",
            )
            self._execute(
                "finding_compile",
                {},
                "Recompile findings after exploit verification.",
            )
        self._execute("exploit_chain", {}, "Build CWE/CVSS enriched attack paths.")

        summary = {
            "summary": "Deterministic baseline assessment pipeline completed.",
            "apk_path": self.apk_path,
            "package": self.package_name,
            "steps": len(self.memory),
            "compiled_report_available": self._ok(compiled),
            "artifacts": self._artifacts(),
        }
        self.logger.event(
            phase="baseline_final",
            observation=summary,
            labels={"success": True, "agent": "baseline_pipeline"},
        )
        return {
            "agent": "baseline_pipeline",
            "name": "Baseline Pipeline",
            "result": summary,
            "memory": self.memory,
        }

    def _source_suite(self, source_dir: str, *, label: str) -> None:
        self._execute(
            "dependency_inventory",
            {"source_dir": source_dir},
            f"Inventory dependencies and native libraries from {label} output.",
        )
        self._execute(
            "source_inventory",
            {"source_dir": source_dir},
            f"Inventory endpoints, APIs, storage, crypto, native, and IPC from {label} output.",
        )
        self._execute("secret_scan", {"source_dir": source_dir}, f"Scan {label} output for secrets.")

    def _execute(self, tool_name: str, arguments: dict[str, Any], thought: str) -> ToolResult:
        action = {"tool_name": tool_name, "arguments": arguments}
        self.logger.event(
            phase="baseline_action",
            thought=thought,
            action=action,
            labels={"agent": "baseline_pipeline"},
        )
        result = self.registry.execute(tool_name=tool_name, arguments=arguments, context=self.context)
        observation = compact_tool_result(result)
        self.logger.event(
            phase="baseline_observation",
            thought=thought,
            action=action,
            observation=observation,
            labels={
                "success": result.status.value == "success",
                "agent": "baseline_pipeline",
                "error_category": None if result.status.value == "success" else result.status.value,
            },
        )
        self.memory.append({"thought": thought, "action": action, "observation": observation})
        self.logger.next_step()
        return result

    def _capture_package(self, result: ToolResult) -> None:
        if self.package_name:
            return
        package = result.metadata.get("package") if isinstance(result.metadata, dict) else None
        if isinstance(package, str) and package:
            self.package_name = package

    def _artifacts(self) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = []
        for item in self.memory:
            artifacts.extend(item.get("observation", {}).get("artifacts") or [])
        return artifacts

    def _rel(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.context.workspace_dir.resolve()))
        except ValueError:
            return str(path)

    def _ok(self, result: ToolResult) -> bool:
        return result.status.value == "success"

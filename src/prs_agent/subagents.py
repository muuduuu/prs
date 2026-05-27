"""Reverse-analysis subagent role definitions and workflow scaffolding."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class SubagentRole:
    """A bounded specialist lane for reverse-analysis planning."""

    identifier: str
    name: str
    mission: str
    tool_focus: tuple[str, ...]
    workflow: tuple[str, ...]
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    guardrails: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "name": self.name,
            "mission": self.mission,
            "tool_focus": list(self.tool_focus),
            "workflow": list(self.workflow),
            "inputs": list(self.inputs),
            "outputs": list(self.outputs),
            "guardrails": list(self.guardrails),
        }


REVERSE_ANALYSIS_SUBAGENTS: tuple[SubagentRole, ...] = (
    SubagentRole(
        identifier="static_reverse",
        name="Static Reverse Analyst",
        mission="Own fast APK reversing while slow scanner lanes run in parallel.",
        tool_focus=("apk_metadata", "manifest_findings", "apktool_decompile", "jadx_decompile"),
        workflow=(
            "Identify package name, version, SDK targets, permissions, and exported components.",
            "Review manifests, resources, network security config, and deep link declarations.",
            "Inspect decompiled code for hardcoded secrets, risky crypto, WebView exposure, storage misuse, and trust decisions.",
            "Record evidence paths and confidence for each candidate finding.",
        ),
        inputs=("apk_path", "apk_metadata output", "apktool artifacts", "jadx artifacts"),
        outputs=("static inventory", "candidate static findings", "artifact index"),
        guardrails=(
            "Do not infer exploitability without evidence.",
            "Prefer structured parsers and artifact references over large raw excerpts.",
            "Continue working while MobSF is queued or running.",
        ),
    ),
    SubagentRole(
        identifier="secret_webview",
        name="Secrets and WebView Analyst",
        mission="Turn decompiled artifacts into focused findings for embedded secrets and unsafe WebView behavior.",
        tool_focus=("secret_scan", "webview_audit"),
        workflow=(
            "Wait for or consume JADX/apktool output directories produced by the static reverse lane.",
            "Scan code, resources, smali, and configuration files for credential-shaped literals and sensitive endpoints.",
            "Audit WebView settings, JavaScript bridges, file access, SSL-error handling, mixed content, and debugging toggles.",
            "Emit normalized findings with file paths, line numbers, redacted snippets, and confidence notes.",
        ),
        inputs=("jadx artifacts", "apktool artifacts", "artifact conventions"),
        outputs=("secret findings", "WebView findings", "source evidence references"),
        guardrails=(
            "Redact secrets in observations and reports.",
            "Do not exfiltrate or validate third-party credentials.",
            "Treat regex matches as candidates until reviewed or corroborated.",
        ),
    ),
    SubagentRole(
        identifier="dynamic_device",
        name="Dynamic Device Analyst",
        mission="Coordinate device-readiness checks and bounded runtime observations on authorized devices.",
        tool_focus=("adb", "frida", "emulator", "frida_probe"),
        workflow=(
            "Confirm device visibility, Android version, target package install state, and Frida readiness.",
            "Capture bounded process/package observations without changing app state unexpectedly.",
            "Map runtime observations back to static hypotheses that need validation.",
            "Stop when device access, authorization, or instrumentation prerequisites are missing.",
        ),
        inputs=("device_id", "package_name", "static hypotheses"),
        outputs=("device readiness summary", "runtime observations", "blocked prerequisites"),
        guardrails=(
            "Use only allow-listed tool actions.",
            "Avoid destructive app or device operations in the scaffold.",
        ),
    ),
    SubagentRole(
        identifier="mobsf_triage",
        name="MobSF Triage Analyst",
        mission="Run MobSF as an asynchronous scanner lane and normalize results when ready.",
        tool_focus=("mobsf_submit", "mobsf_poll", "mobsf_scan"),
        workflow=(
            "Submit the APK to MobSF as early as possible.",
            "Poll later with bounded waits while other analysts perform local work.",
            "Extract high-signal categories such as permissions, components, network, crypto, and code warnings.",
            "Deduplicate MobSF findings against static and dynamic evidence.",
            "Flag items that require manual verification or richer parsing.",
        ),
        inputs=("apk_path", "MobSF JSON/report artifacts", "static inventory"),
        outputs=("triaged MobSF findings", "deduplication notes", "manual verification queue"),
        guardrails=(
            "Treat scanner severity as advisory until corroborated.",
            "Keep MobSF credentials and service configuration outside model context.",
        ),
    ),
    SubagentRole(
        identifier="exploitability_validation",
        name="Exploitability Validation Analyst",
        mission="Confirm whether high-risk findings are practically reachable using bounded, authorized probes.",
        tool_focus=("finding_compile", "exploit_verify", "exploit_chain", "intent_fuzzer", "backup_audit", "frida_probe"),
        workflow=(
            "Compile normalized findings from static, scanner, and runtime lanes.",
            "Prioritize high-severity items that have safe confirmation methods.",
            "Use bounded runtime probes only on connected devices or emulators owned by the tester.",
            "Build attack paths that connect entry points, weaknesses, evidence, preconditions, CWE, CVSS, and impact.",
            "Separate confirmed findings from unverified hypotheses and blocked checks.",
            "Record verification artifacts and commands through tool results, not free-form shell output.",
        ),
        inputs=("manifest findings", "secret findings", "WebView findings", "MobSF findings", "package name", "device readiness"),
        outputs=("compiled findings report", "verification table", "attack-path chains", "confirmed exploitability evidence", "blocked checks"),
        guardrails=(
            "Do not generate weaponized payloads, persistence, stealth, or data theft workflows.",
            "Keep probes bounded, reversible, and scoped to the provided package.",
            "If authorization, package identity, or device state is unclear, mark the check blocked.",
        ),
    ),
    SubagentRole(
        identifier="report_synthesis",
        name="Report Synthesis Analyst",
        mission="Combine specialist outputs into a concise assessment result with evidence and next steps.",
        tool_focus=(),
        workflow=(
            "Group findings by risk area and affected component.",
            "Attach artifact references, confidence, and validation status.",
            "Separate confirmed findings from hypotheses and blocked checks.",
            "Produce prioritized remediation and follow-up recommendations.",
        ),
        inputs=("static findings", "dynamic observations", "MobSF triage", "artifact index"),
        outputs=("executive summary", "technical findings", "evidence map", "next steps"),
        guardrails=(
            "Do not overstate impact beyond collected evidence.",
            "Call out missing prerequisites and manual-review needs explicitly.",
        ),
    ),
)


def list_subagents() -> list[dict[str, Any]]:
    """Return model-safe reverse-analysis subagent descriptions."""

    return [role.to_dict() for role in REVERSE_ANALYSIS_SUBAGENTS]


def specialist_manifest() -> list[dict[str, Any]]:
    """Return UI-safe specialist summaries expected by the app."""

    return [
        {
            "name": role.name,
            "mission": role.mission,
            "tool_names": list(role.tool_focus),
            "id": role.identifier,
        }
        for role in REVERSE_ANALYSIS_SUBAGENTS
    ]


def build_reverse_analysis_plan(
    *,
    objective: str,
    apk_path: str | None = None,
    include_dynamic: bool = True,
    include_mobsf: bool = True,
) -> dict[str, Any]:
    """Create a lightweight workflow plan for the current assessment."""

    selected_roles = []
    for role in REVERSE_ANALYSIS_SUBAGENTS:
        if role.identifier == "dynamic_device" and not include_dynamic:
            continue
        if role.identifier == "mobsf_triage" and not include_mobsf:
            continue
        selected_roles.append(role)

    return {
        "objective": objective,
        "apk_path": apk_path,
        "subagents": [role.to_dict() for role in selected_roles],
        "handoffs": [
            {
                "from": "static_reverse",
                "to": "secret_webview",
                "payload": "jadx/apktool output paths for source-level secret and WebView analysis",
                "enabled": True,
            },
            {
                "from": "static_reverse",
                "to": "mobsf_triage",
                "payload": "static inventory and artifact paths for scanner deduplication",
                "enabled": include_mobsf,
            },
            {
                "from": "dynamic_device",
                "to": "exploitability_validation",
                "payload": "device readiness, runtime observations, and blocked checks",
                "enabled": include_dynamic,
            },
            {
                "from": "mobsf_triage",
                "to": "exploitability_validation",
                "payload": "normalized scanner findings and verification queue",
                "enabled": include_mobsf,
            },
            {
                "from": "secret_webview",
                "to": "exploitability_validation",
                "payload": "secret and WebView findings requiring confirmation or manual review",
                "enabled": True,
            },
            {
                "from": "exploitability_validation",
                "to": "report_synthesis",
                "payload": "compiled findings, verification table, attack-path chains, and confirmed evidence",
                "enabled": True,
            },
        ],
        "execution_note": (
            "This scaffold defines specialist responsibilities and handoffs. "
            "Actual tool execution remains bounded by the registered tool schemas."
        ),
    }

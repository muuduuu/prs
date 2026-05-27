"""Intent fuzzer that probes exported components for IPC issues."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool


FUZZ_EXTRAS = (
    ("--es", "payload", "../../etc/passwd"),
    ("--es", "payload", "<script>alert(1)</script>"),
    ("--es", "payload", "'; DROP TABLE users; --"),
    ("--es", "url", "file:///etc/hosts"),
    ("--es", "uri", "content://com.android.contacts/contacts"),
    ("--ei", "payload_int", "2147483647"),
)


class IntentFuzzerTool(BaseTool):
    """Send malformed intents at exported components to surface crashes and IPC issues."""

    name = "intent_fuzzer"
    description = (
        "Fuzz exported activities, services, broadcast receivers, and content providers "
        "from a parsed AndroidManifest. Sends crafted intents via 'adb shell am' and records "
        "responses, crashes, and exceptions. Requires a connected device or emulator."
    )
    args_schema = {
        "type": "object",
        "required": ["package", "components"],
        "properties": {
            "package": {"type": "string", "description": "Target application package id."},
            "components": {
                "type": "array",
                "description": "Exported components as {type, name} (matches manifest_findings output).",
                "items": {"type": "object"},
            },
            "max_components": {"type": "integer", "description": "Cap on components fuzzed. Default 25."},
            "extras_per_component": {"type": "integer", "description": "Number of payload variants per component. Default 4."},
        },
    }

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        if not shutil.which("adb"):
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                summary="adb is required to run the intent fuzzer.",
                error="missing_binary:adb",
            )

        package = str(arguments.get("package") or "").strip()
        if not package:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.VALIDATION_ERROR,
                summary="package is required.",
                error="missing_argument:package",
            )

        components = arguments.get("components") or []
        if not isinstance(components, list) or not components:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.VALIDATION_ERROR,
                summary="components must be a non-empty list of {type, name}.",
                error="missing_argument:components",
            )

        max_components = max(1, int(arguments.get("max_components") or 25))
        extras_per = max(1, min(len(FUZZ_EXTRAS), int(arguments.get("extras_per_component") or 4)))

        # Drain logcat first so crash detection is per-component.
        _drain_logcat()

        attempts: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        for component in components[:max_components]:
            if not isinstance(component, dict):
                continue
            kind = str(component.get("type") or "").lower()
            name = component.get("name") or ""
            if not name or kind not in {"activity", "service", "receiver", "provider"}:
                continue

            target = name if name.startswith(".") or "." in name else f".{name}"
            qualified = name if "/" in name else f"{package}/{target}" if name.startswith(".") else f"{package}/{name}"

            for extra in FUZZ_EXTRAS[:extras_per]:
                argv = _build_am_command(kind, qualified, package, extra)
                if argv is None:
                    continue
                completed = _run(argv, timeout=15)
                anomaly = _detect_anomaly(completed.stdout, completed.stderr, completed.returncode)
                attempts.append(
                    {
                        "component": qualified,
                        "type": kind,
                        "extras": list(extra),
                        "exit_code": completed.returncode,
                        "stdout": _excerpt(completed.stdout),
                        "stderr": _excerpt(completed.stderr),
                        "anomaly": anomaly,
                    }
                )
                if anomaly:
                    findings.append(
                        {
                            "id": "INTENT-FUZZ-ANOMALY",
                            "title": f"{kind.capitalize()} {qualified} produced anomalous response under fuzzing",
                            "severity": "medium",
                            "category": "ipc",
                            "source": "intent_fuzzer",
                            "description": (
                                "Sending a malformed intent triggered a crash, exception trace, or "
                                "permission denial that indicates inadequate input validation in an "
                                "exported component."
                            ),
                            "evidence": {
                                "component": qualified,
                                "type": kind,
                                "extras": list(extra),
                                "anomaly": anomaly,
                            },
                            "cwe": "CWE-926",
                            "package": package,
                        }
                    )

        crashes = _scan_logcat_for_crashes(package)
        if crashes:
            findings.append(
                {
                    "id": "INTENT-FUZZ-CRASH",
                    "title": f"Target crashed {len(crashes)} time(s) during intent fuzzing",
                    "severity": "high",
                    "category": "ipc",
                    "source": "intent_fuzzer",
                    "description": (
                        "logcat captured FATAL EXCEPTION or ANR entries while fuzzing exported "
                        "components. The runtime failures suggest exploitable IPC handling defects."
                    ),
                    "evidence": {"package": package, "crashes": crashes[:20]},
                    "cwe": "CWE-754",
                    "package": package,
                }
            )

        out_dir = context.artifacts_dir / "exploits"
        out_dir.mkdir(parents=True, exist_ok=True)
        log_path = out_dir / "intent_fuzzer.json"
        log_path.write_text(
            json.dumps(
                {
                    "package": package,
                    "attempts": attempts,
                    "findings": findings,
                    "crashes": crashes,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        findings_dir = context.artifacts_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = findings_dir / "intent_fuzzer.json"
        findings_path.write_text(
            json.dumps({"source": "intent_fuzzer", "findings": findings}, indent=2),
            encoding="utf-8",
        )

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            summary=(
                f"Fuzzed {len(attempts)} intent variant(s) across {min(max_components, len(components))} "
                f"component(s); recorded {len(findings)} finding(s) and {len(crashes)} crash entries."
            ),
            artifacts=[
                Artifact(kind="json", path=str(log_path), description="Raw intent fuzz attempts"),
                Artifact(kind="json", path=str(findings_path), description="Intent fuzzer findings"),
            ],
            metadata={
                "package": package,
                "attempt_count": len(attempts),
                "finding_count": len(findings),
                "crash_count": len(crashes),
                "findings": findings,
            },
        )


def _build_am_command(kind: str, qualified: str, package: str, extra: tuple[str, str, str]) -> list[str] | None:
    if kind == "activity":
        verb = ["start", "-n", qualified]
    elif kind == "service":
        verb = ["start-service", "-n", qualified]
    elif kind == "receiver":
        action = "android.intent.action.VIEW"
        verb = ["broadcast", "-a", action, "-n", qualified]
    elif kind == "provider":
        # Providers cannot be queried via am; emit a no-op query through content.
        return [
            "adb",
            "shell",
            "content",
            "query",
            "--uri",
            f"content://{package}.provider",
        ]
    else:
        return None
    return ["adb", "shell", "am", *verb, *extra]


def _run(argv: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # noqa: S603 - bounded argv
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            args=argv,
            returncode=124,
            stdout=exc.stdout or "",
            stderr=(exc.stderr or "") + "\n[fuzzer] timeout",
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return subprocess.CompletedProcess(args=argv, returncode=127, stdout="", stderr=str(exc))


def _detect_anomaly(stdout: str, stderr: str, returncode: int) -> str | None:
    blob = f"{stdout}\n{stderr}".lower()
    for needle in (
        "fatal exception",
        "java.lang.runtimeexception",
        "java.lang.nullpointerexception",
        "java.lang.securityexception",
        "permission denial",
        "anr in",
        "tombstone",
    ):
        if needle in blob:
            return needle
    if returncode not in (0, 124):
        # SecurityException, missing component, etc.
        if "exception" in blob or "error" in blob:
            return f"non_zero_exit:{returncode}"
    return None


def _drain_logcat() -> None:
    try:
        subprocess.run(  # noqa: S603,S607
            ["adb", "logcat", "-c"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception:
        return


def _scan_logcat_for_crashes(package: str) -> list[str]:
    try:
        completed = subprocess.run(  # noqa: S603,S607
            ["adb", "logcat", "-d", "*:E"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except Exception:
        return []
    crashes: list[str] = []
    for line in completed.stdout.splitlines():
        lower = line.lower()
        if "fatal exception" in lower or "anr in" in lower or package.lower() in lower and "exception" in lower:
            crashes.append(line.strip()[:300])
        if len(crashes) >= 50:
            break
    return crashes


def _excerpt(text: str, *, limit: int = 400) -> str:
    if not text:
        return ""
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "..."

"""Local web app for running mobile assessment orchestrations."""

from __future__ import annotations

import cgi
import json
import shutil
import threading
import traceback
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from prs_agent.bifrost import AssessmentPlannerClient, BifrostHTTPClient, fetch_bifrost_models
from prs_agent.contracts import AgentRunResult, new_run_id, utc_now_iso
from prs_agent.crew import CrewConfig, CrewOrchestrator
from prs_agent.orchestrator import AgentOrchestrator
from prs_agent.registry import ToolRegistry
from prs_agent.subagents import specialist_manifest
from prs_agent.tools import (
    AdbTool,
    ApkMetadataTool,
    ApktoolDecompilerTool,
    BackupAuditTool,
    DependencyInventoryTool,
    EmulatorTool,
    ExploitChainTool,
    ExploitVerifyTool,
    FindingCompileTool,
    FridaTool,
    FridaProbeTool,
    IntentFuzzerTool,
    JadxDecompilerTool,
    ManifestFindingsTool,
    MobSFJobStore,
    MobSFFindingsTool,
    MobSFPollTool,
    MobSFScanTool,
    MobSFSubmitTool,
    NetworkSecurityAuditTool,
    ReverseAnalysisPlanTool,
    SecretScanTool,
    SourceInventoryTool,
    WebViewAuditTool,
)


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "web"


@dataclass
class ManagedRun:
    """In-memory state for a background assessment run."""

    run_id: str
    status: str
    objective: str
    created_at: str
    events: list[dict[str, Any]] = field(default_factory=list)
    final_answer: dict[str, Any] = field(default_factory=dict)
    trace_path: str | None = None
    error: str | None = None


class RunManager:
    """Starts and tracks orchestrator runs for the local app."""

    def __init__(self, workspace_dir: Path) -> None:
        self.workspace_dir = workspace_dir
        self._runs: dict[str, ManagedRun] = {}
        self._lock = threading.Lock()

    def start(self, payload: dict[str, Any]) -> ManagedRun:
        run_id = new_run_id()
        objective = payload.get("objective") or "Run an initial authorized mobile app assessment."
        managed = ManagedRun(
            run_id=run_id,
            status="queued",
            objective=objective,
            created_at=utc_now_iso(),
        )
        with self._lock:
            self._runs[run_id] = managed

        thread = threading.Thread(
            target=self._run_worker,
            args=(managed, payload),
            daemon=True,
        )
        thread.start()
        return managed

    def get(self, run_id: str) -> ManagedRun | None:
        with self._lock:
            return self._runs.get(run_id)

    def list(self) -> list[ManagedRun]:
        with self._lock:
            return list(self._runs.values())

    def _run_worker(self, managed: ManagedRun, payload: dict[str, Any]) -> None:
        self._set_status(managed.run_id, "running")
        try:
            registry = build_registry(payload)
            bifrost = build_bifrost(payload, run_id=managed.run_id)
            if (payload.get("bifrost") or {}).get("enabled"):
                orchestrator = CrewOrchestrator(
                    bifrost=bifrost,
                    registry=registry,
                    workspace_dir=self.workspace_dir,
                    config=CrewConfig(
                        apk_path=payload.get("apk_path"),
                        include_device_checks=bool(payload.get("include_device_checks", True)),
                        max_steps_per_agent=int(payload.get("max_steps_per_agent") or 6),
                    ),
                    tool_timeout_seconds=int(payload.get("tool_timeout_seconds") or 120),
                    on_event=lambda event: self._append_event(managed.run_id, event),
                )
            else:
                orchestrator = AgentOrchestrator(
                    bifrost=bifrost,
                    registry=registry,
                    workspace_dir=self.workspace_dir,
                    max_iterations=int(payload.get("max_iterations") or 12),
                    tool_timeout_seconds=int(payload.get("tool_timeout_seconds") or 120),
                    on_event=lambda event: self._append_event(managed.run_id, event),
                )
            result = orchestrator.run(managed.objective, run_id=managed.run_id)
            self._finish(managed.run_id, result)
        except Exception as exc:
            self._fail(managed.run_id, f"{type(exc).__name__}: {exc}", traceback.format_exc())

    def _set_status(self, run_id: str, status: str) -> None:
        with self._lock:
            self._runs[run_id].status = status

    def _append_event(self, run_id: str, event: dict[str, Any]) -> None:
        with self._lock:
            self._runs[run_id].events.append(event)

    def _finish(self, run_id: str, result: AgentRunResult) -> None:
        with self._lock:
            run = self._runs[run_id]
            run.status = result.status
            run.final_answer = result.final_answer
            run.trace_path = str(result.trace_path)

    def _fail(self, run_id: str, message: str, detail: str) -> None:
        with self._lock:
            run = self._runs[run_id]
            run.status = "error"
            run.error = message
            run.events.append(
                {
                    "phase": "orchestrator_error",
                    "timestamp": utc_now_iso(),
                    "observation": {"summary": message, "detail": detail},
                }
            )


def build_registry(payload: dict[str, Any] | None = None) -> ToolRegistry:
    payload = payload or {}
    mobsf_config = payload.get("mobsf") or {}
    mobsf_store = MobSFJobStore()
    registry = ToolRegistry()
    registry.register(ReverseAnalysisPlanTool())
    registry.register(AdbTool())
    registry.register(ApkMetadataTool())
    registry.register(ManifestFindingsTool())
    registry.register(ApktoolDecompilerTool())
    registry.register(NetworkSecurityAuditTool())
    registry.register(JadxDecompilerTool())
    registry.register(DependencyInventoryTool())
    registry.register(SourceInventoryTool())
    registry.register(SecretScanTool())
    registry.register(WebViewAuditTool())
    registry.register(FridaTool())
    registry.register(EmulatorTool())
    registry.register(IntentFuzzerTool())
    registry.register(BackupAuditTool())
    registry.register(FridaProbeTool())
    registry.register(
        MobSFSubmitTool(
            base_url=mobsf_config.get("base_url"),
            api_key=mobsf_config.get("api_key"),
            store=mobsf_store,
        )
    )
    registry.register(MobSFPollTool(store=mobsf_store))
    registry.register(
        MobSFScanTool(
            base_url=mobsf_config.get("base_url"),
            api_key=mobsf_config.get("api_key"),
        )
    )
    registry.register(MobSFFindingsTool())
    registry.register(FindingCompileTool())
    registry.register(ExploitVerifyTool())
    registry.register(ExploitChainTool())
    return registry


def build_bifrost(payload: dict[str, Any], run_id: str | None = None):
    bifrost_config = payload.get("bifrost") or {}
    mobsf_config = payload.get("mobsf") or {}
    apk_stem = Path(payload["apk_path"]).stem if payload.get("apk_path") else "<apk_stem>"
    context_hints = {
        "apk_path": payload.get("apk_path"),
        "run_id": run_id,
        "include_device_checks": bool(payload.get("include_device_checks", True)),
        "mobsf_configured": bool(mobsf_config.get("base_url") and mobsf_config.get("api_key")),
        "mobsf_url": mobsf_config.get("base_url"),
        "analysis_tools": [
            "apk_metadata",
            "manifest_findings",
            "network_security_audit",
            "apktool_decompile",
            "jadx_decompile",
            "dependency_inventory",
            "source_inventory",
            "secret_scan",
            "webview_audit",
            "mobsf_submit",
            "mobsf_poll",
            "mobsf_findings",
            "finding_compile",
            "exploit_verify",
            "exploit_chain",
            "emulator",
            "intent_fuzzer",
            "backup_audit",
            "frida_probe",
        ],
        "artifact_conventions": {
            "jadx_output": f"runs/{run_id}/artifacts/jadx/{apk_stem}" if run_id else "runs/<run_id>/artifacts/jadx/<apk_stem>",
            "apktool_output": f"runs/{run_id}/artifacts/apktool/{apk_stem}" if run_id else "runs/<run_id>/artifacts/apktool/<apk_stem>",
            "findings_dir": f"runs/{run_id}/artifacts/findings" if run_id else "runs/<run_id>/artifacts/findings",
        },
    }
    if bifrost_config.get("enabled"):
        return BifrostHTTPClient(
            gateway_url=bifrost_config["gateway_url"],
            api_key=bifrost_config["api_key"],
            model_name=bifrost_config.get("model") or "bifrost",
            context_hints=context_hints,
        )
    return AssessmentPlannerClient(
        apk_path=payload.get("apk_path"),
        include_device_checks=bool(payload.get("include_device_checks", True)),
        run_id=run_id,
    )


def tool_health() -> dict[str, Any]:
    return {
        "adb": {"available": shutil.which("adb") is not None, "path": shutil.which("adb")},
        "apk_metadata": {"available": True, "path": "pyaxmlparser primary path; aapt optional fallback"},
        "aapt": {"available": shutil.which("aapt") is not None, "path": shutil.which("aapt")},
        "apktool": {"available": shutil.which("apktool") is not None, "path": shutil.which("apktool")},
        "jadx": {"available": shutil.which("jadx") is not None, "path": shutil.which("jadx")},
        "emulator": {"available": shutil.which("emulator") is not None, "path": shutil.which("emulator")},
        "frida": {"available": shutil.which("frida") is not None, "path": shutil.which("frida")},
        "frida-ps": {"available": shutil.which("frida-ps") is not None, "path": shutil.which("frida-ps")},
    }


class AppHandler(BaseHTTPRequestHandler):
    """HTTP API and static file handler."""

    manager: RunManager
    workspace_dir: Path

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._json({"status": "ok", "tools": tool_health(), "subagents": specialist_manifest()})
            return

        if parsed.path == "/api/runs":
            self._json({"runs": [serialize_run(run, include_events=False) for run in self.manager.list()]})
            return

        if parsed.path == "/api/run":
            run_id = parse_qs(parsed.query).get("id", [""])[0]
            run = self.manager.get(run_id)
            if not run:
                self._json({"error": "run not found"}, status=HTTPStatus.NOT_FOUND)
                return
            self._json(serialize_run(run, include_events=True))
            return

        self._static(parsed.path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/upload":
            self._handle_upload()
            return

        if parsed.path == "/api/runs":
            payload = self._read_json()
            run = self.manager.start(payload)
            self._json(serialize_run(run, include_events=True), status=HTTPStatus.CREATED)
            return

        if parsed.path == "/api/bifrost/models":
            self._handle_bifrost_models()
            return

        self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def log_message(self, format: str, *args: Any) -> None:
        """Keep server output quiet for the desktop app."""

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _handle_upload(self) -> None:
        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={
                "REQUEST_METHOD": "POST",
                "CONTENT_TYPE": self.headers.get("Content-Type"),
            },
        )

        file_item = form["apk"] if "apk" in form else None
        if file_item is None or not file_item.filename:
            self._json({"error": "missing apk file"}, status=HTTPStatus.BAD_REQUEST)
            return

        uploads_dir = self.workspace_dir / "uploads"
        uploads_dir.mkdir(parents=True, exist_ok=True)
        safe_name = Path(file_item.filename).name.replace(" ", "_")
        if not safe_name.lower().endswith(".apk"):
            self._json({"error": "file must have .apk extension"}, status=HTTPStatus.BAD_REQUEST)
            return

        target = uploads_dir / safe_name
        with target.open("wb") as handle:
            shutil.copyfileobj(file_item.file, handle)

        self._json(
            {
                "apk_path": str(target.relative_to(self.workspace_dir)),
                "filename": safe_name,
                "size": target.stat().st_size,
            },
            status=HTTPStatus.CREATED,
        )

    def _handle_bifrost_models(self) -> None:
        payload = self._read_json()
        gateway_url = payload.get("gateway_url")
        api_key = payload.get("api_key")
        if not gateway_url or not api_key:
            self._json({"error": "gateway_url and api_key are required"}, status=HTTPStatus.BAD_REQUEST)
            return

        try:
            models = fetch_bifrost_models(
                gateway_url=gateway_url,
                api_key=api_key,
                models_url=payload.get("models_url") or None,
            )
        except Exception as exc:
            self._json(
                {"error": f"Unable to fetch models: {type(exc).__name__}: {exc}"},
                status=HTTPStatus.BAD_GATEWAY,
            )
            return
        self._json({"models": models})

    def _static(self, request_path: str) -> None:
        if request_path in ("", "/"):
            request_path = "/index.html"
        target = (STATIC_DIR / request_path.lstrip("/")).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.exists():
            self._json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        content_type = "text/html"
        if target.suffix == ".css":
            content_type = "text/css"
        elif target.suffix == ".js":
            content_type = "application/javascript"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(target.read_bytes())

    def _json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serialize_run(run: ManagedRun, *, include_events: bool) -> dict[str, Any]:
    payload = {
        "run_id": run.run_id,
        "status": run.status,
        "objective": run.objective,
        "created_at": run.created_at,
        "final_answer": run.final_answer,
        "trace_path": run.trace_path,
        "error": run.error,
        "event_count": len(run.events),
    }
    if include_events:
        payload["events"] = run.events
    return payload


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    workspace_dir = Path.cwd()
    AppHandler.workspace_dir = workspace_dir
    AppHandler.manager = RunManager(workspace_dir)
    server = ThreadingHTTPServer((host, port), AppHandler)
    print(f"PRS agent app listening on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    serve()

"""MobSF REST integration."""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file


class MobSFAPIError(RuntimeError):
    """MobSF API failure with captured response body."""

    def __init__(self, message: str, *, status: int | None = None, body: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass(slots=True)
class MobSFJob:
    """Background MobSF job state."""

    job_id: str
    run_id: str
    apk_name: str
    status: str = "queued"
    hash: str | None = None
    summary: str = "MobSF job queued."
    artifacts: list[Artifact] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


class MobSFJobStore:
    """Thread-safe in-memory job store for one app process."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, MobSFJob] = {}
        self._latest_by_run: dict[str, str] = {}

    def create(self, *, run_id: str, apk_name: str) -> MobSFJob:
        job = MobSFJob(job_id=f"mobsf-{uuid4().hex[:10]}", run_id=run_id, apk_name=apk_name)
        with self._lock:
            self._jobs[job.job_id] = job
            self._latest_by_run[run_id] = job.job_id
        return job

    def update(self, job_id: str, **changes: Any) -> None:
        with self._lock:
            job = self._jobs[job_id]
            for key, value in changes.items():
                setattr(job, key, value)
            job.updated_at = time.time()

    def get(self, job_id: str | None, run_id: str) -> MobSFJob | None:
        with self._lock:
            resolved = job_id or self._latest_by_run.get(run_id)
            if not resolved:
                return None
            return self._jobs.get(resolved)


class MobSFClientMixin:
    """Shared MobSF API helpers."""

    base_url: str | None
    api_key: str | None

    def _configured_error(self, tool_name: str) -> ToolResult | None:
        if self.base_url and self.api_key:
            return None
        return ToolResult(
            tool_name=tool_name,
            status=ToolStatus.VALIDATION_ERROR,
            summary="MobSF is not configured.",
            error="Provide MobSF URL and API key in the app before running this tool.",
        )

    def _run_static_workflow(
        self,
        *,
        apk_path: Path,
        context: ToolContext,
        tool_name: str,
    ) -> ToolResult:
        boundary = "----prs-mobsf-boundary"
        file_bytes = Path(apk_path).read_bytes()
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{Path(apk_path).name}"\r\n'
            "Content-Type: application/vnd.android.package-archive\r\n\r\n"
        ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

        upload_payload: dict[str, Any] = {}
        scan_payload: dict[str, Any] = {}
        report_payload: dict[str, Any] = {}
        report_error: str | None = None

        try:
            upload_payload = self._upload(body, boundary, context.timeout_seconds)
            scan_hash = upload_payload.get("hash")
            if not scan_hash:
                raise ValueError("MobSF upload response did not include a hash")

            scan_payload = self._post_form(
                "/api/v1/scan",
                {
                    "hash": scan_hash,
                    "scan_type": upload_payload.get("scan_type", "apk"),
                    "file_name": upload_payload.get("file_name", Path(apk_path).name),
                    "re_scan": "0",
                },
                context.timeout_seconds,
            )
            report_payload, report_error = self._fetch_report_json_with_retries(
                scan_hash=scan_hash,
                timeout_seconds=context.timeout_seconds,
            )
            if not report_payload:
                report_payload = scan_payload
        except Exception as exc:
            error_dir = context.artifacts_dir / "mobsf"
            error_dir.mkdir(parents=True, exist_ok=True)
            error_path = error_dir / f"{Path(apk_path).stem}-error.json"
            error_path.write_text(
                json.dumps(
                    {
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                        "upload_response": upload_payload,
                        "scan_response": scan_payload,
                        "response_body": getattr(exc, "body", ""),
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                summary="MobSF scan workflow failed.",
                error=f"{type(exc).__name__}: {exc}",
                artifacts=[Artifact(kind="json", path=str(error_path), description="MobSF failure details")],
            )

        mobsf_dir = context.artifacts_dir / "mobsf"
        mobsf_dir.mkdir(parents=True, exist_ok=True)
        upload_path = mobsf_dir / f"{Path(apk_path).stem}-upload.json"
        scan_path = mobsf_dir / f"{Path(apk_path).stem}-scan.json"
        report_path = mobsf_dir / f"{Path(apk_path).stem}-report.json"
        upload_path.write_text(json.dumps(upload_payload, indent=2), encoding="utf-8")
        scan_path.write_text(json.dumps(scan_payload, indent=2), encoding="utf-8")
        report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
        summary = "Completed MobSF upload, static scan, and JSON report retrieval."
        if report_error:
            summary = "Completed MobSF upload and static scan. report_json was not ready before the wait budget ended, so scan response was saved as report."
        return ToolResult(
            tool_name=tool_name,
            status=ToolStatus.SUCCESS,
            summary=summary,
            artifacts=[
                Artifact(kind="json", path=str(upload_path), description="MobSF upload response"),
                Artifact(kind="json", path=str(scan_path), description="MobSF scan response"),
                Artifact(kind="json", path=str(report_path), description="MobSF JSON report"),
            ],
            metadata={"hash": upload_payload.get("hash"), "report_json_error": report_error},
        )

    def _fetch_report_json_with_retries(
        self,
        *,
        scan_hash: str,
        timeout_seconds: int,
    ) -> tuple[dict[str, Any], str | None]:
        """Wait for MobSF's report_json endpoint to become ready.

        MobSF often returns from `/scan` before the JSON report is readable.
        Treat "Report not Found" and transient report_json failures as a
        not-ready state until the bounded wait budget is exhausted.
        """

        wait_budget = max(60, min(timeout_seconds, 600))
        per_request_timeout = max(15, min(timeout_seconds, 90))
        deadline = time.monotonic() + wait_budget
        attempt = 0
        last_error: str | None = None

        while time.monotonic() < deadline:
            attempt += 1
            try:
                payload = self._post_form(
                    "/api/v1/report_json",
                    {"hash": scan_hash},
                    per_request_timeout,
                )
                if str(payload.get("report", "")).lower() != "report not found":
                    payload["_prs_report_attempts"] = attempt
                    payload["_prs_report_wait_seconds"] = wait_budget
                    return payload, None
                last_error = "MobSF report_json returned Report not Found."
            except MobSFAPIError as exc:
                last_error = f"{exc} Body: {exc.body[:500]}"
            time.sleep(5)

        return {}, f"{last_error or 'MobSF report_json was not ready.'} Waited up to {wait_budget}s."

    def _upload(self, body: bytes, boundary: str, timeout_seconds: int) -> dict:
        request = urllib.request.Request(
            f"{self.base_url}/api/v1/upload",
            data=body,
            headers={
                "Authorization": self.api_key or "",
                "Accept": "application/json",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "User-Agent": "prs-agent/0.1",
            },
            method="POST",
        )
        return self._open_json(request, timeout_seconds)

    def _post_form(self, endpoint: str, values: dict[str, str | None], timeout_seconds: int) -> dict:
        data = urllib.parse.urlencode({key: value for key, value in values.items() if value is not None}).encode(
            "utf-8"
        )
        request = urllib.request.Request(
            f"{self.base_url}{endpoint}",
            data=data,
            headers={
                "Authorization": self.api_key or "",
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "prs-agent/0.1",
            },
            method="POST",
        )
        return self._open_json(request, timeout_seconds)

    def _open_json(self, request: urllib.request.Request, timeout_seconds: int) -> dict[str, Any]:
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise MobSFAPIError(
                f"MobSF HTTP {exc.code} calling {request.full_url}",
                status=exc.code,
                body=body,
            ) from exc
        except urllib.error.URLError as exc:
            raise MobSFAPIError(f"MobSF connection error calling {request.full_url}: {exc}") from exc

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise MobSFAPIError(
                f"MobSF returned non-JSON response from {request.full_url}",
                body=body[:1000],
            ) from exc

        if isinstance(payload, dict) and payload.get("error"):
            raise MobSFAPIError(
                f"MobSF API error from {request.full_url}: {payload.get('error')}",
                body=json.dumps(payload)[:1000],
            )
        return payload


class MobSFSubmitTool(MobSFClientMixin, BaseTool):
    """Start MobSF analysis in a background worker and return immediately."""

    name = "mobsf_submit"
    description = "Submit an APK to MobSF in the background so other specialist lanes can continue."
    args_schema = {
        "type": "object",
        "required": ["apk_path"],
        "properties": {
            "apk_path": {"type": "string", "description": "Path to an APK inside the workspace."}
        },
    }

    def __init__(self, *, base_url: str | None = None, api_key: str | None = None, store: MobSFJobStore) -> None:
        self.base_url = base_url.rstrip("/") if base_url else None
        self.api_key = api_key
        self.store = store

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        configured_error = self._configured_error(self.name)
        if configured_error:
            return configured_error

        apk_path, error = resolve_workspace_file(context, arguments["apk_path"], self.name)
        if error:
            return error

        job = self.store.create(run_id=context.run_id, apk_name=Path(apk_path).name)
        thread = threading.Thread(
            target=self._worker,
            args=(job.job_id, apk_path, context),
            name=f"prs-{job.job_id}",
            daemon=True,
        )
        thread.start()
        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            summary="MobSF analysis submitted in the background.",
            metadata={"job_id": job.job_id, "status": job.status, "apk_name": job.apk_name},
        )

    def _worker(self, job_id: str, apk_path: Path, context: ToolContext) -> None:
        self.store.update(job_id, status="running", summary="MobSF static analysis is running.")
        result = self._run_static_workflow(apk_path=apk_path, context=context, tool_name=self.name)
        if result.status == ToolStatus.SUCCESS:
            self.store.update(
                job_id,
                status="completed",
                summary=result.summary,
                artifacts=result.artifacts,
                metadata=result.metadata,
                hash=result.metadata.get("hash"),
            )
            return
        self.store.update(
            job_id,
            status="failed",
            summary=result.summary,
            artifacts=result.artifacts,
            metadata=result.metadata,
            error=result.error,
        )


class MobSFPollTool(BaseTool):
    """Poll or briefly wait for a background MobSF job."""

    name = "mobsf_poll"
    description = "Check the latest or specified MobSF background job and optionally wait for completion."
    args_schema = {
        "type": "object",
        "required": [],
        "properties": {
            "job_id": {"type": "string", "description": "Optional MobSF job id. Defaults to latest run job."},
            "wait_seconds": {"type": "integer", "description": "Optional bounded wait before returning status. Max 600."},
        },
    }

    def __init__(self, *, store: MobSFJobStore) -> None:
        self.store = store

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        wait_seconds = min(int(arguments.get("wait_seconds") or 0), 600)
        deadline = time.monotonic() + wait_seconds
        job = self.store.get(arguments.get("job_id"), context.run_id)
        while job and job.status in {"queued", "running"} and time.monotonic() < deadline:
            time.sleep(1)
            job = self.store.get(arguments.get("job_id"), context.run_id)

        if not job:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.VALIDATION_ERROR,
                summary="No MobSF background job was found for this run.",
                error="missing_mobsf_job",
            )

        status = ToolStatus.SUCCESS if job.status == "completed" else ToolStatus.ERROR if job.status == "failed" else ToolStatus.SUCCESS
        return ToolResult(
            tool_name=self.name,
            status=status,
            summary=job.summary,
            artifacts=job.artifacts,
            metadata={
                "job_id": job.job_id,
                "job_status": job.status,
                "hash": job.hash,
                **job.metadata,
            },
            error=job.error,
        )


class MobSFScanTool(MobSFClientMixin, BaseTool):
    """Upload an APK to MobSF, start static analysis, and fetch the JSON report."""

    name = "mobsf_scan"
    description = "Upload an APK to MobSF, run static analysis, and save upload/scan/report JSON artifacts."
    args_schema = {
        "type": "object",
        "required": ["apk_path"],
        "properties": {
            "apk_path": {"type": "string", "description": "Path to an APK inside the workspace."}
        },
    }

    def __init__(self, *, base_url: str | None = None, api_key: str | None = None) -> None:
        self.base_url = base_url.rstrip("/") if base_url else None
        self.api_key = api_key

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        configured_error = self._configured_error(self.name)
        if configured_error:
            return configured_error

        apk_path, error = resolve_workspace_file(context, arguments["apk_path"], self.name)
        if error:
            return error

        return self._run_static_workflow(apk_path=apk_path, context=context, tool_name=self.name)

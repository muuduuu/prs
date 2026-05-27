"""MobSF REST integration."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file


class MobSFAPIError(RuntimeError):
    """MobSF API failure with captured response body."""

    def __init__(self, message: str, *, status: int | None = None, body: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class MobSFScanTool(BaseTool):
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
        if not self.base_url or not self.api_key:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.VALIDATION_ERROR,
                summary="MobSF is not configured.",
                error="Provide MobSF URL and API key in the app before running this tool.",
            )

        apk_path, error = resolve_workspace_file(context, arguments["apk_path"], self.name)
        if error:
            return error

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
            try:
                report_payload = self._post_form(
                    "/api/v1/report_json",
                    {"hash": scan_hash},
                    context.timeout_seconds,
                )
                if str(report_payload.get("report", "")).lower() == "report not found":
                    report_error = "MobSF report_json returned Report not Found; using scan response as report."
                    report_payload = scan_payload
            except MobSFAPIError as exc:
                report_error = f"{exc} Body: {exc.body[:500]}"
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
                tool_name=self.name,
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
            summary = "Completed MobSF upload and static scan. report_json failed, so scan response was saved as report."
        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            summary=summary,
            artifacts=[
                Artifact(kind="json", path=str(upload_path), description="MobSF upload response"),
                Artifact(kind="json", path=str(scan_path), description="MobSF scan response"),
                Artifact(kind="json", path=str(report_path), description="MobSF JSON report"),
            ],
            metadata={"hash": upload_payload.get("hash"), "report_json_error": report_error},
        )

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

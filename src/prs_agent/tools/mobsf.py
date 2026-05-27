"""MobSF REST integration."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file


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
            report_payload = self._post_form(
                "/api/v1/report_json",
                {"hash": scan_hash},
                context.timeout_seconds,
            )
        except Exception as exc:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                summary="MobSF scan workflow failed.",
                error=f"{type(exc).__name__}: {exc}",
            )

        mobsf_dir = context.artifacts_dir / "mobsf"
        mobsf_dir.mkdir(parents=True, exist_ok=True)
        upload_path = mobsf_dir / f"{Path(apk_path).stem}-upload.json"
        scan_path = mobsf_dir / f"{Path(apk_path).stem}-scan.json"
        report_path = mobsf_dir / f"{Path(apk_path).stem}-report.json"
        upload_path.write_text(json.dumps(upload_payload, indent=2), encoding="utf-8")
        scan_path.write_text(json.dumps(scan_payload, indent=2), encoding="utf-8")
        report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            summary="Completed MobSF upload, static scan, and JSON report retrieval.",
            artifacts=[
                Artifact(kind="json", path=str(upload_path), description="MobSF upload response"),
                Artifact(kind="json", path=str(scan_path), description="MobSF scan response"),
                Artifact(kind="json", path=str(report_path), description="MobSF JSON report"),
            ],
            metadata={"hash": upload_payload.get("hash")},
        )

    def _upload(self, body: bytes, boundary: str, timeout_seconds: int) -> dict:
        request = urllib.request.Request(
            f"{self.base_url}/api/v1/upload",
            data=body,
            headers={
                "Authorization": self.api_key or "",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))

    def _post_form(self, endpoint: str, values: dict[str, str | None], timeout_seconds: int) -> dict:
        data = urllib.parse.urlencode({key: value for key, value in values.items() if value is not None}).encode(
            "utf-8"
        )
        request = urllib.request.Request(
            f"{self.base_url}{endpoint}",
            data=data,
            headers={
                "Authorization": self.api_key or "",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))

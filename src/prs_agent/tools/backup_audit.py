"""Backup audit that confirms whether private app data can be extracted via adb backup."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool


class BackupAuditTool(BaseTool):
    """Attempt `adb backup -f out.ab` against a package to confirm allowBackup risk."""

    name = "backup_audit"
    description = (
        "Confirm whether private app data is reachable via `adb backup`. Runs a non-interactive "
        "backup against the target package (requires a device with backup service available) and "
        "reports whether the resulting .ab archive contains app data."
    )
    args_schema = {
        "type": "object",
        "required": ["package"],
        "properties": {
            "package": {"type": "string", "description": "Target application package id."},
            "timeout_seconds": {"type": "integer", "description": "adb backup timeout (default 45)."},
        },
    }

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        if not shutil.which("adb"):
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                summary="adb is required for backup audit.",
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
        timeout_seconds = max(10, int(arguments.get("timeout_seconds") or 45))

        out_dir = context.artifacts_dir / "exploits" / "backup"
        out_dir.mkdir(parents=True, exist_ok=True)
        archive = out_dir / f"{_safe(package)}.ab"

        argv = [
            "adb",
            "backup",
            "-f",
            str(archive),
            "-noapk",
            "-noshared",
            "-nosystem",
            package,
        ]
        try:
            completed = subprocess.run(  # noqa: S603 - bounded argv
                argv,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.TIMEOUT,
                summary="adb backup timed out (likely waiting for on-device confirmation).",
                stdout_excerpt=(exc.stdout or "")[:400],
                stderr_excerpt=(exc.stderr or "")[:400],
                error="timeout",
                metadata={"package": package, "timeout_seconds": timeout_seconds},
            )
        except (FileNotFoundError, PermissionError, OSError) as exc:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                summary="adb backup could not be launched.",
                error=str(exc),
                metadata={"argv": argv},
            )

        size = archive.stat().st_size if archive.exists() else 0
        findings: list[dict[str, Any]] = []
        backup_succeeded = size > 1024  # Empty backups are typically ~1KB headers.

        if backup_succeeded:
            findings.append(
                {
                    "id": "BACKUP-EXTRACTABLE",
                    "title": f"adb backup extracted {size} bytes of private data for {package}",
                    "severity": "high",
                    "category": "data_protection",
                    "source": "backup_audit",
                    "description": (
                        "The application allowed an automated `adb backup` to capture its private "
                        "data. On devices without disk encryption or a backup passphrase, an attacker "
                        "with USB debugging access can extract credentials, tokens, and user content."
                    ),
                    "evidence": {"package": package, "archive_bytes": size, "archive_path": str(archive)},
                    "cwe": "CWE-200",
                    "package": package,
                }
            )

        findings_dir = context.artifacts_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = findings_dir / "backup_audit.json"
        findings_path.write_text(
            json.dumps(
                {
                    "source": "backup_audit",
                    "package": package,
                    "archive_path": str(archive),
                    "archive_bytes": size,
                    "extracted": backup_succeeded,
                    "exit_code": completed.returncode,
                    "stdout": completed.stdout.strip()[:400],
                    "stderr": completed.stderr.strip()[:400],
                    "findings": findings,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            summary=(
                f"adb backup completed; archive {size} bytes; "
                f"data_extracted={backup_succeeded}."
            ),
            stdout_excerpt=completed.stdout.strip()[:400],
            stderr_excerpt=completed.stderr.strip()[:400],
            artifacts=[
                Artifact(kind="binary", path=str(archive), description="adb backup archive"),
                Artifact(kind="json", path=str(findings_path), description="Backup audit findings"),
            ],
            metadata={
                "package": package,
                "archive_bytes": size,
                "extracted": backup_succeeded,
                "findings": findings,
            },
        )


def _safe(value: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in value)

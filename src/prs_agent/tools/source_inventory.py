"""Broad source and artifact inventory over decompiled APK output."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file


CHECKS: tuple[dict[str, Any], ...] = (
    {
        "id": "URL-INVENTORY",
        "category": "network",
        "severity": "info",
        "title": "URLs and network endpoints embedded in APK artifacts",
        "pattern": r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+",
    },
    {
        "id": "DEEPLINK-INVENTORY",
        "category": "deeplink",
        "severity": "info",
        "title": "Custom schemes and deep link style URIs",
        "pattern": r"\b[a-zA-Z][a-zA-Z0-9+.-]{2,24}://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+",
    },
    {
        "id": "FIREBASE-INVENTORY",
        "category": "cloud",
        "severity": "medium",
        "title": "Firebase project or database references",
        "pattern": r"(?:[a-z0-9-]+\.firebaseio\.com|firebaseapp\.com|google_app_id|gcm_defaultSenderId)",
    },
    {
        "id": "AWS-S3-INVENTORY",
        "category": "cloud",
        "severity": "low",
        "title": "AWS S3 bucket or endpoint references",
        "pattern": r"(?:s3[.-][a-z0-9-]+\.amazonaws\.com|[a-z0-9.\-_]{3,63}\.s3\.amazonaws\.com)",
    },
    {
        "id": "GRAPHQL-INVENTORY",
        "category": "api",
        "severity": "info",
        "title": "GraphQL endpoint or query references",
        "pattern": r"(?:/graphql\b|query\s+[A-Za-z0-9_]+\s*\{|mutation\s+[A-Za-z0-9_]+\s*\{)",
    },
    {
        "id": "LOCAL-STORAGE-INVENTORY",
        "category": "storage",
        "severity": "info",
        "title": "Local storage APIs and sensitive file paths",
        "pattern": r"(?:SharedPreferences|getSharedPreferences|MODE_WORLD_READABLE|openFileOutput|SQLiteDatabase|RoomDatabase|/sdcard/|WRITE_EXTERNAL_STORAGE)",
    },
    {
        "id": "CRYPTO-INVENTORY",
        "category": "crypto",
        "severity": "info",
        "title": "Cryptographic API usage",
        "pattern": r"(?:Cipher\.getInstance|MessageDigest\.getInstance|SecretKeySpec|KeyStore\.getInstance|AES/ECB|DES|RC4|MD5|SHA-1)",
    },
    {
        "id": "AUTH-INVENTORY",
        "category": "auth",
        "severity": "info",
        "title": "Authentication, token, and session handling references",
        "pattern": r"(?:Authorization|Bearer|OAuth|refresh[_-]?token|access[_-]?token|session[_-]?id|JWT|biometric|FingerprintManager|BiometricPrompt)",
    },
    {
        "id": "NATIVE-LIB-INVENTORY",
        "category": "native",
        "severity": "info",
        "title": "Native library loading and JNI references",
        "pattern": r"(?:System\.loadLibrary|JNIEXPORT|Java_[A-Za-z0-9_]+|\.so\b)",
    },
    {
        "id": "IPC-INVENTORY",
        "category": "ipc",
        "severity": "info",
        "title": "IPC, intents, broadcasts, and content provider references",
        "pattern": r"(?:Intent\.|sendBroadcast|startActivity|startService|ContentResolver|content://|BroadcastReceiver|ContentProvider)",
    },
)


SUFFIXES = {
    ".java",
    ".kt",
    ".smali",
    ".xml",
    ".json",
    ".properties",
    ".txt",
    ".js",
    ".ts",
    ".html",
    ".gradle",
    ".cfg",
    ".conf",
}
SKIP_DIRS = {".git", "build", "out", "node_modules", "kotlin", "META-INF"}


class SourceInventoryTool(BaseTool):
    """Search decompiled APK output for broad pentest-relevant artifacts."""

    name = "source_inventory"
    description = (
        "Broadly inventory decompiled APK artifacts for URLs, endpoints, deeplinks, Firebase/S3 hints, "
        "GraphQL, storage APIs, crypto APIs, auth/token references, native libraries, and IPC usage. "
        "Produces grouped JSON evidence for manual review and later attack-path chaining."
    )
    args_schema = {
        "type": "object",
        "required": ["source_dir"],
        "properties": {
            "source_dir": {
                "type": "string",
                "description": "Workspace-relative decompiled source/resource directory from JADX or apktool.",
            },
            "max_files": {"type": "integer", "description": "Maximum files to scan. Default 8000."},
            "max_file_bytes": {"type": "integer", "description": "Per-file byte cap. Default 1_000_000."},
            "max_hits_per_check": {"type": "integer", "description": "Evidence cap per inventory category. Default 80."},
        },
    }

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        source_dir, error = resolve_workspace_file(context, arguments["source_dir"], self.name)
        if error:
            return error
        if not source_dir.is_dir():
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.VALIDATION_ERROR,
                summary="source_dir must point to a directory.",
                error=f"not a directory: {source_dir}",
            )

        max_files = int(arguments.get("max_files") or 8000)
        max_bytes = int(arguments.get("max_file_bytes") or 1_000_000)
        max_hits = int(arguments.get("max_hits_per_check") or 80)
        compiled = [(check, re.compile(check["pattern"], re.IGNORECASE)) for check in CHECKS]

        grouped: dict[str, dict[str, Any]] = {
            check["id"]: {
                "id": check["id"],
                "title": check["title"],
                "severity": check["severity"],
                "category": check["category"],
                "source": "source_inventory",
                "description": "Inventory evidence found in decompiled APK artifacts.",
                "evidence": {"hits": []},
            }
            for check in CHECKS
        }

        files_scanned = 0
        files_skipped = 0
        for path in _iter_source_files(source_dir, max_files=max_files):
            files_scanned += 1
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size == 0 or size > max_bytes:
                files_skipped += 1
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = str(path.relative_to(context.workspace_dir.resolve()))
            for check, regex in compiled:
                bucket = grouped[check["id"]]["evidence"]["hits"]
                if len(bucket) >= max_hits:
                    continue
                for match in regex.finditer(text):
                    value = _clean(match.group(0))
                    if not value or _seen(bucket, rel, value):
                        continue
                    bucket.append(
                        {
                            "file": rel,
                            "line": text.count("\n", 0, match.start()) + 1,
                            "value": _truncate(value),
                            "snippet": _line_snippet(text, match.start()),
                        }
                    )
                    if len(bucket) >= max_hits:
                        break

        findings = [
            finding
            for finding in grouped.values()
            if finding["evidence"]["hits"]
        ]
        counts = {finding["id"]: len(finding["evidence"]["hits"]) for finding in findings}

        findings_dir = context.artifacts_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = findings_dir / "source_inventory.json"
        findings_path.write_text(
            json.dumps(
                {
                    "source": "source_inventory",
                    "source_dir": str(source_dir.relative_to(context.workspace_dir.resolve())),
                    "files_scanned": files_scanned,
                    "files_skipped": files_skipped,
                    "counts": counts,
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
                f"Source inventory scanned {files_scanned} file(s), skipped {files_skipped}, "
                f"and produced {len(findings)} grouped artifact finding(s)."
            ),
            artifacts=[Artifact(kind="json", path=str(findings_path), description="Broad source inventory findings")],
            metadata={
                "source_dir": str(source_dir.relative_to(context.workspace_dir.resolve())),
                "files_scanned": files_scanned,
                "files_skipped": files_skipped,
                "counts": counts,
                "findings": findings[:40],
            },
        )


def _iter_source_files(root: Path, *, max_files: int) -> Iterable[Path]:
    count = 0
    for path in root.rglob("*"):
        if count >= max_files:
            return
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in SUFFIXES:
            continue
        count += 1
        yield path


def _seen(bucket: list[dict[str, Any]], rel: str, value: str) -> bool:
    return any(hit.get("file") == rel and hit.get("value") == _truncate(value) for hit in bucket)


def _clean(value: str) -> str:
    return value.strip().strip('"').strip("'").strip()


def _truncate(value: str, *, limit: int = 240) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _line_snippet(text: str, offset: int, *, width: int = 180) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    line = " ".join(text[start:end].strip().split())
    return _truncate(line, limit=width)

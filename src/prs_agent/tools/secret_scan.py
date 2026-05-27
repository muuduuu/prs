"""Secret and risky-string scanner over decompiled source trees."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any, Iterable

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file


SECRET_PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    ("AWS-ACCESS-KEY", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "high", "AWS access key id"),
    ("AWS-SECRET-KEY", r"(?i)aws.{0,20}(secret|access).{0,20}['\"][A-Za-z0-9/+=]{40}['\"]", "high", "AWS secret access key context"),
    ("GCP-API-KEY", r"\bAIza[0-9A-Za-z\-_]{35}\b", "high", "Google API key"),
    ("GITHUB-PAT", r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b", "high", "GitHub personal access token"),
    ("SLACK-TOKEN", r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b", "high", "Slack token"),
    ("STRIPE-LIVE", r"\bsk_live_[0-9A-Za-z]{20,}\b", "high", "Stripe live secret key"),
    ("STRIPE-TEST", r"\bsk_test_[0-9A-Za-z]{20,}\b", "medium", "Stripe test secret key"),
    ("FIREBASE-DB", r"https://[a-z0-9-]+\.firebaseio\.com", "medium", "Firebase realtime database URL"),
    ("PRIVATE-KEY", r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |)PRIVATE KEY-----", "high", "Embedded private key"),
    ("JWT", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", "medium", "JSON Web Token literal"),
    ("BASIC-AUTH-URL", r"https?://[^\s:'\"]+:[^\s@'\"]+@[^\s/'\"]+", "high", "URL with embedded credentials"),
    ("BEARER-LITERAL", r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}", "medium", "Bearer token literal"),
    ("PASSWORD-ASSIGN", r"(?i)(password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*['\"][^'\"\s]{6,}['\"]", "medium", "Hardcoded credential assignment"),
    ("INTERNAL-URL", r"https?://[a-z0-9-]+\.(?:internal|corp|local|intra|prod|dev|staging|qa)(?:\.[a-z0-9-]+)*", "low", "Internal-looking hostname"),
    ("IP-LITERAL", r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)(?:\.[0-9]{1,3}){2}\b", "low", "Private IP literal"),
)


CODE_SUFFIXES = {".java", ".kt", ".smali", ".xml", ".json", ".properties", ".txt", ".js", ".ts", ".html", ".gradle"}
SKIP_DIRS = {".git", "node_modules", "build", "out", "kotlin"}


class SecretScanTool(BaseTool):
    """Walk a decompiled output directory and surface embedded secrets."""

    name = "secret_scan"
    description = (
        "Recursively scan a decompiled APK directory (jadx or apktool output) for hardcoded "
        "secrets, API keys, tokens, private keys, embedded credentials, and risky URLs."
    )
    args_schema = {
        "type": "object",
        "required": ["source_dir"],
        "properties": {
            "source_dir": {
                "type": "string",
                "description": "Workspace-relative directory containing decompiled sources (jadx/apktool output).",
            },
            "max_files": {
                "type": "integer",
                "description": "Cap on files scanned. Default 4000.",
            },
            "max_file_bytes": {
                "type": "integer",
                "description": "Per-file byte cap. Default 1_000_000.",
            },
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

        max_files = int(arguments.get("max_files") or 4000)
        max_bytes = int(arguments.get("max_file_bytes") or 1_000_000)

        compiled = [(name, re.compile(pattern), severity, description) for name, pattern, severity, description in SECRET_PATTERNS]

        findings: list[dict[str, Any]] = []
        scanned = 0
        skipped = 0
        seen_keys: set[tuple[str, str, str]] = set()

        for path in _iter_source_files(source_dir, max_files=max_files):
            scanned += 1
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size == 0 or size > max_bytes:
                skipped += 1
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel = str(path.relative_to(context.workspace_dir.resolve()))
            for name, regex, severity, description in compiled:
                for match in regex.finditer(text):
                    snippet = _redact(match.group(0))
                    line_no = text.count("\n", 0, match.start()) + 1
                    key = (name, rel, snippet)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    findings.append(
                        {
                            "id": f"SECRET-{name}",
                            "title": description,
                            "severity": severity,
                            "category": "secret",
                            "source": "secret_scan",
                            "file": rel,
                            "line": line_no,
                            "match": snippet,
                            "cwe": "CWE-798",
                        }
                    )

        high = sum(1 for f in findings if f["severity"] == "high")
        medium = sum(1 for f in findings if f["severity"] == "medium")
        low = sum(1 for f in findings if f["severity"] == "low")

        findings_dir = context.artifacts_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = findings_dir / "secret_scan.json"
        findings_path.write_text(
            json.dumps(
                {
                    "source": "secret_scan",
                    "source_dir": str(source_dir.relative_to(context.workspace_dir.resolve())),
                    "findings": findings,
                    "counts": {"high": high, "medium": medium, "low": low, "total": len(findings)},
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            summary=(
                f"Secret scan over {scanned} files found {len(findings)} candidate(s) "
                f"(high={high} medium={medium} low={low}, skipped={skipped})."
            ),
            artifacts=[
                Artifact(kind="json", path=str(findings_path), description="Secret scan findings JSON"),
            ],
            metadata={
                "source_dir": str(source_dir.relative_to(context.workspace_dir.resolve())),
                "files_scanned": scanned,
                "files_skipped": skipped,
                "findings": findings,
                "counts": {"high": high, "medium": medium, "low": low, "total": len(findings)},
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
        if path.suffix.lower() not in CODE_SUFFIXES:
            continue
        count += 1
        yield path


def _redact(value: str) -> str:
    if len(value) <= 12:
        return value
    return value[:6] + "..." + value[-4:]


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    frequencies = {char: data.count(char) for char in set(data)}
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())

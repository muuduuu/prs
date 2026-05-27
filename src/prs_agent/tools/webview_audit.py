"""WebView and JavaScript bridge audit over decompiled APK sources."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file


CHECKS: tuple[tuple[str, str, str, str, str, str], ...] = (
    (
        "WEBVIEW-JS-INTERFACE",
        r"\baddJavascriptInterface\s*\(",
        "high",
        "WebView exposes a Java interface to JavaScript",
        "addJavascriptInterface bridges JavaScript into native code. Combined with loadUrl of untrusted content this enables remote code execution on devices below API 17 and account-level data theft on later versions.",
        "CWE-749",
    ),
    (
        "WEBVIEW-JS-ENABLED",
        r"setJavaScriptEnabled\s*\(\s*true\s*\)",
        "medium",
        "WebView has JavaScript execution enabled",
        "Enabling JavaScript greatly expands the attack surface of a WebView. Pair this with strict origin checks and content sanitization.",
        "CWE-79",
    ),
    (
        "WEBVIEW-FILE-ACCESS",
        r"setAllowFileAccess(?:FromFileURLs|FromFileURLs)?\s*\(\s*true\s*\)|setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)",
        "high",
        "WebView allows access to local file:// resources",
        "Permitting file URL access lets a malicious page read local files via JavaScript and leaks data such as cookies, preferences, and cached tokens.",
        "CWE-200",
    ),
    (
        "WEBVIEW-LOAD-FILE-URL",
        r"loadUrl\s*\(\s*\"file://",
        "medium",
        "WebView explicitly loads file:// URLs",
        "Loading local file URLs from a WebView can be abused if the input is influenced by user content or deep links.",
        "CWE-22",
    ),
    (
        "WEBVIEW-PROCEED-SSL",
        r"onReceivedSslError[\s\S]{0,200}\.proceed\s*\(",
        "high",
        "Custom SSL error handler unconditionally calls proceed()",
        "An onReceivedSslError handler that calls handler.proceed() ignores certificate validation failures and allows TLS interception.",
        "CWE-295",
    ),
    (
        "WEBVIEW-MIXED-CONTENT",
        r"setMixedContentMode\s*\(\s*WebSettings\.MIXED_CONTENT_ALWAYS_ALLOW\s*\)",
        "medium",
        "WebView allows mixed cleartext content",
        "MIXED_CONTENT_ALWAYS_ALLOW lets HTTPS pages load HTTP subresources, enabling network attackers to inject scripts.",
        "CWE-319",
    ),
    (
        "WEBVIEW-DEBUGGABLE",
        r"WebView\.setWebContentsDebuggingEnabled\s*\(\s*true\s*\)",
        "medium",
        "WebView remote Chrome debugging is enabled",
        "Enabling remote debugging in a release build exposes the JavaScript context to anyone with adb access.",
        "CWE-489",
    ),
)


SUFFIXES = {".java", ".kt", ".smali"}
SKIP_DIRS = {".git", "kotlin", "META-INF"}


class WebViewAuditTool(BaseTool):
    """Audit decompiled Java/Kotlin/smali for risky WebView patterns."""

    name = "webview_audit"
    description = (
        "Scan a decompiled APK directory for unsafe WebView configurations (addJavascriptInterface, "
        "JavaScript enabled, file:// access, SSL error proceed, mixed content, debugging). Emits "
        "findings with file and line references."
    )
    args_schema = {
        "type": "object",
        "required": ["source_dir"],
        "properties": {
            "source_dir": {"type": "string", "description": "Workspace-relative decompiled source directory."},
            "max_files": {"type": "integer", "description": "Cap on files scanned. Default 6000."},
            "max_file_bytes": {"type": "integer", "description": "Per-file byte cap. Default 1_000_000."},
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

        max_files = int(arguments.get("max_files") or 6000)
        max_bytes = int(arguments.get("max_file_bytes") or 1_000_000)

        compiled = [
            (fid, re.compile(pattern), severity, title, description, cwe)
            for (fid, pattern, severity, title, description, cwe) in CHECKS
        ]

        findings: list[dict[str, Any]] = []
        scanned = 0
        seen: set[tuple[str, str, int]] = set()

        for path in _iter_source_files(source_dir, max_files=max_files):
            scanned += 1
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size == 0 or size > max_bytes:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = str(path.relative_to(context.workspace_dir.resolve()))
            for fid, regex, severity, title, description, cwe in compiled:
                for match in regex.finditer(text):
                    line_no = text.count("\n", 0, match.start()) + 1
                    key = (fid, rel, line_no)
                    if key in seen:
                        continue
                    seen.add(key)
                    snippet = _line_snippet(text, match.start())
                    findings.append(
                        {
                            "id": fid,
                            "title": title,
                            "severity": severity,
                            "category": "webview",
                            "source": "webview_audit",
                            "description": description,
                            "evidence": {
                                "file": rel,
                                "line": line_no,
                                "snippet": snippet,
                            },
                            "cwe": cwe,
                        }
                    )

        findings_dir = context.artifacts_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = findings_dir / "webview_audit.json"
        findings_path.write_text(
            json.dumps({"source": "webview_audit", "findings": findings, "files_scanned": scanned}, indent=2),
            encoding="utf-8",
        )

        high = sum(1 for f in findings if f["severity"] == "high")
        medium = sum(1 for f in findings if f["severity"] == "medium")

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            summary=(
                f"WebView audit scanned {scanned} files and produced {len(findings)} finding(s) "
                f"(high={high} medium={medium})."
            ),
            artifacts=[
                Artifact(kind="json", path=str(findings_path), description="WebView audit findings"),
            ],
            metadata={
                "files_scanned": scanned,
                "findings": findings,
                "counts": {"high": high, "medium": medium, "total": len(findings)},
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


def _line_snippet(text: str, offset: int, *, width: int = 160) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    line = text[start:end].strip()
    if len(line) > width:
        line = line[: width - 1] + "..."
    return line

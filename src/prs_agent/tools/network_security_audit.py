"""Network Security Config audit for apktool output."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file


class NetworkSecurityAuditTool(BaseTool):
    """Inspect Android Network Security Config files from apktool output."""

    name = "network_security_audit"
    description = (
        "Parse apktool output for Android Network Security Config XML. Reports cleartext domains, "
        "debug overrides, user/system trust anchors, certificate pinning, and risky trust policy."
    )
    args_schema = {
        "type": "object",
        "required": ["apktool_dir"],
        "properties": {
            "apktool_dir": {"type": "string", "description": "Workspace-relative apktool output directory."},
            "config_path": {
                "type": "string",
                "description": "Optional workspace-relative Network Security Config XML path.",
            },
        },
    }

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        apktool_dir, error = resolve_workspace_file(context, arguments["apktool_dir"], self.name)
        if error:
            return error
        if not apktool_dir.is_dir():
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.VALIDATION_ERROR,
                summary="apktool_dir must point to a directory.",
                error=f"not a directory: {apktool_dir}",
            )

        config_paths: list[Path] = []
        if arguments.get("config_path"):
            config_path, path_error = resolve_workspace_file(context, arguments["config_path"], self.name)
            if path_error:
                return path_error
            config_paths.append(config_path)
        else:
            config_paths = _discover_configs(apktool_dir)

        findings: list[dict[str, Any]] = []
        configs: list[dict[str, Any]] = []
        for config_path in config_paths:
            parsed, parse_findings = _parse_config(config_path, context)
            configs.append(parsed)
            findings.extend(parse_findings)

        if not config_paths:
            findings.append(
                _finding(
                    finding_id="NSC-MISSING",
                    title="No Network Security Config file found in apktool output",
                    severity="info",
                    description=(
                        "No network security config XML was discovered under res/xml. For apps targeting older "
                        "SDKs, platform defaults may still allow cleartext traffic."
                    ),
                    evidence={"apktool_dir": str(apktool_dir.relative_to(context.workspace_dir.resolve()))},
                    cwe="CWE-319",
                )
            )

        findings_dir = context.artifacts_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = findings_dir / "network_security_audit.json"
        findings_path.write_text(
            json.dumps(
                {
                    "source": "network_security_audit",
                    "configs": configs,
                    "findings": findings,
                    "counts": _counts(findings),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            summary=f"Audited {len(config_paths)} network security config file(s); produced {len(findings)} finding(s).",
            artifacts=[Artifact(kind="json", path=str(findings_path), description="Network Security Config audit")],
            metadata={"config_count": len(config_paths), "findings": findings, "counts": _counts(findings)},
        )


def _discover_configs(apktool_dir: Path) -> list[Path]:
    candidates = []
    for path in sorted((apktool_dir / "res" / "xml").glob("*.xml")) if (apktool_dir / "res" / "xml").exists() else []:
        name = path.name.lower()
        text = path.read_text(encoding="utf-8", errors="replace")[:2000].lower()
        if "network-security-config" in text or "domain-config" in text or "trust-anchors" in text or "network" in name:
            candidates.append(path)
    return candidates


def _parse_config(path: Path, context: ToolContext) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rel = str(path.relative_to(context.workspace_dir.resolve()))
    try:
        root = ET.fromstring(path.read_text(encoding="utf-8", errors="replace"))
    except ET.ParseError as exc:
        return {"path": rel, "parse_error": str(exc)}, [
            _finding(
                finding_id="NSC-PARSE-ERROR",
                title="Network Security Config XML could not be parsed",
                severity="low",
                description="The config file exists but is malformed or uses constructs the parser could not read.",
                evidence={"file": rel, "error": str(exc)},
            )
        ]

    domains: list[dict[str, Any]] = []
    pins: list[dict[str, Any]] = []
    trust_sources: set[str] = set()
    cleartext_domains: list[str] = []
    debug_overrides = root.find("debug-overrides") is not None

    for element in root.iter():
        tag = _tag(element.tag)
        if tag == "domain":
            domain = (element.text or "").strip()
            if domain:
                domains.append(
                    {
                        "domain": domain,
                        "include_subdomains": element.attrib.get("includeSubdomains") == "true",
                    }
                )
        elif tag in {"base-config", "domain-config"}:
            if element.attrib.get("cleartextTrafficPermitted") == "true":
                cleartext_domains.extend(_domains_under(element) or ["<base-config>"])
        elif tag == "certificates":
            src = element.attrib.get("src")
            if src:
                trust_sources.add(src)
        elif tag == "pin":
            pins.append({"digest": element.attrib.get("digest"), "value_prefix": (element.text or "").strip()[:16]})

    findings: list[dict[str, Any]] = []
    if cleartext_domains:
        findings.append(
            _finding(
                finding_id="NSC-CLEARTEXT-DOMAINS",
                title=f"Network Security Config permits cleartext for {len(cleartext_domains)} domain scope(s)",
                severity="high",
                description="Explicit cleartext permission allows plaintext HTTP traffic for the listed scope.",
                evidence={"file": rel, "domains": cleartext_domains[:50]},
                cwe="CWE-319",
            )
        )
    if "user" in trust_sources:
        findings.append(
            _finding(
                finding_id="NSC-USER-CA-TRUST",
                title="Network Security Config trusts user-installed CAs",
                severity="medium",
                description="Trusting user CAs can allow TLS interception on compromised or managed devices.",
                evidence={"file": rel, "trust_sources": sorted(trust_sources)},
                cwe="CWE-295",
            )
        )
    if debug_overrides:
        findings.append(
            _finding(
                finding_id="NSC-DEBUG-OVERRIDES",
                title="Network Security Config contains debug-overrides",
                severity="low",
                description="Debug-only trust anchors are present. Confirm release builds do not enable debug behavior.",
                evidence={"file": rel},
                cwe="CWE-489",
            )
        )
    if not pins:
        findings.append(
            _finding(
                finding_id="NSC-NO-PINNING",
                title="No certificate pinning declarations found in Network Security Config",
                severity="info",
                description="Pinning is not mandatory for every app, but high-risk apps should consider scoped pinning.",
                evidence={"file": rel, "domains": domains[:50]},
                cwe="CWE-295",
            )
        )

    return {
        "path": rel,
        "domains": domains,
        "cleartext_domains": cleartext_domains,
        "trust_sources": sorted(trust_sources),
        "pin_count": len(pins),
        "debug_overrides": debug_overrides,
    }, findings


def _tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _domains_under(element: ET.Element) -> list[str]:
    domains = []
    for child in element.iter():
        if _tag(child.tag) == "domain" and child.text:
            domains.append(child.text.strip())
    return domains


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    description: str,
    evidence: dict[str, Any],
    cwe: str | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "category": "network",
        "source": "network_security_audit",
        "description": description,
        "evidence": evidence,
        "cwe": cwe,
    }


def _counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0, "total": len(findings)}
    for finding in findings:
        severity = str(finding.get("severity") or "info").lower()
        if severity in counts:
            counts[severity] += 1
    return counts

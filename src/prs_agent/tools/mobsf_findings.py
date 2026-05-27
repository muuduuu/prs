"""Parse MobSF JSON reports into the unified findings shape."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file


SEVERITY_NORMALIZE = {
    "high": "high",
    "critical": "high",
    "warning": "medium",
    "medium": "medium",
    "good": "info",
    "info": "info",
    "secure": "info",
    "low": "low",
    "hotspot": "medium",
}


class MobSFFindingsTool(BaseTool):
    """Convert a MobSF JSON report into normalized findings."""

    name = "mobsf_findings"
    description = (
        "Parse a saved MobSF JSON report (from mobsf_scan or mobsf_poll) and extract "
        "structured findings across code, manifest, network, permissions, and trackers."
    )
    args_schema = {
        "type": "object",
        "required": ["report_path"],
        "properties": {
            "report_path": {
                "type": "string",
                "description": "Workspace-relative path to a MobSF report JSON file.",
            }
        },
    }

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        report_path, error = resolve_workspace_file(context, arguments["report_path"], self.name)
        if error:
            return error

        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                summary="MobSF report is not valid JSON.",
                error=f"{type(exc).__name__}: {exc}",
            )
        except OSError as exc:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                summary="Failed to read MobSF report.",
                error=str(exc),
            )

        findings: list[dict[str, Any]] = []
        package = payload.get("package_name") or payload.get("app_name")

        findings.extend(_parse_code_analysis(payload.get("code_analysis"), package))
        findings.extend(_parse_manifest_analysis(payload.get("manifest_analysis"), package))
        findings.extend(_parse_binary_analysis(payload.get("binary_analysis"), package))
        findings.extend(_parse_network_security(payload.get("network_security"), package))
        findings.extend(_parse_trackers(payload.get("trackers"), package))
        findings.extend(_parse_certificate_analysis(payload.get("certificate_analysis"), package))
        findings.extend(_parse_permissions(payload.get("permissions"), package))
        findings.extend(_parse_secrets(payload.get("secrets"), package))
        findings.extend(_parse_urls(payload, package))
        findings.extend(_parse_emails(payload.get("emails"), package))

        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1

        findings_dir = context.artifacts_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = findings_dir / "mobsf_findings.json"
        findings_path.write_text(
            json.dumps(
                {
                    "source": "mobsf",
                    "package": package,
                    "findings": findings,
                    "counts": {**counts, "total": len(findings)},
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            summary=(
                f"Parsed MobSF report into {len(findings)} finding(s) "
                f"(high={counts.get('high', 0)} medium={counts.get('medium', 0)} "
                f"low={counts.get('low', 0)} info={counts.get('info', 0)})."
            ),
            artifacts=[
                Artifact(kind="json", path=str(findings_path), description="MobSF findings JSON"),
            ],
            metadata={
                "report_path": str(report_path.relative_to(context.workspace_dir)),
                "package": package,
                "findings": findings,
                "counts": {**counts, "total": len(findings)},
            },
        )


def _normalize_severity(value: Any, default: str = "info") -> str:
    if not isinstance(value, str):
        return default
    return SEVERITY_NORMALIZE.get(value.strip().lower(), default)


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    evidence: dict[str, Any],
    package: str | None,
    cwe: str | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "category": category,
        "source": "mobsf",
        "description": description,
        "evidence": evidence,
        "cwe": cwe,
        "package": package,
    }


def _parse_code_analysis(section: Any, package: str | None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not isinstance(section, dict):
        return findings
    findings_dict = section.get("findings") if isinstance(section.get("findings"), dict) else section
    for key, value in (findings_dict or {}).items():
        if not isinstance(value, dict):
            continue
        metadata = value.get("metadata") or {}
        files = value.get("files") if isinstance(value.get("files"), dict) else {}
        severity = _normalize_severity(metadata.get("severity") or value.get("severity"), "medium")
        findings.append(
            _finding(
                finding_id=f"MOBSF-CODE-{_slug(key)}",
                title=metadata.get("description") or key,
                severity=severity,
                category="code",
                description=metadata.get("description") or "MobSF code analysis rule triggered.",
                evidence={
                    "rule": key,
                    "files": list(files.keys())[:20] if isinstance(files, dict) else files,
                    "owasp": metadata.get("owasp-mobile"),
                    "masvs": metadata.get("masvs"),
                    "ref": metadata.get("ref"),
                },
                package=package,
                cwe=metadata.get("cwe"),
            )
        )
    return findings


def _parse_manifest_analysis(section: Any, package: str | None) -> list[dict[str, Any]]:
    if not isinstance(section, dict):
        return []
    issues = section.get("manifest_findings") or section.get("findings") or []
    findings: list[dict[str, Any]] = []
    if isinstance(issues, list):
        for entry in issues:
            if not isinstance(entry, dict):
                continue
            rule = entry.get("rule") or entry.get("title") or "manifest_issue"
            findings.append(
                _finding(
                    finding_id=f"MOBSF-MANIFEST-{_slug(rule)}",
                    title=entry.get("title") or rule,
                    severity=_normalize_severity(entry.get("severity"), "medium"),
                    category="manifest",
                    description=entry.get("description") or "MobSF manifest analysis finding.",
                    evidence={"name": entry.get("name"), "component": entry.get("component")},
                    package=package,
                )
            )
    return findings


def _parse_binary_analysis(section: Any, package: str | None) -> list[dict[str, Any]]:
    if not isinstance(section, list):
        return []
    findings: list[dict[str, Any]] = []
    for entry in section:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or "binary"
        for key in ("nx", "stack_canary", "rpath", "runpath", "fortify", "pie", "relro", "symbol"):
            value = entry.get(key)
            if isinstance(value, dict) and (value.get("severity") or "").lower() in {"high", "warning", "medium"}:
                findings.append(
                    _finding(
                        finding_id=f"MOBSF-BIN-{_slug(name)}-{key.upper()}",
                        title=value.get("description") or f"{key} weakness in {name}",
                        severity=_normalize_severity(value.get("severity"), "medium"),
                        category="binary",
                        description=value.get("description") or "Binary hardening mitigation missing.",
                        evidence={"binary": name, "check": key, "value": value.get("is_nx") or value.get("has_canary")},
                        package=package,
                    )
                )
    return findings


def _parse_network_security(section: Any, package: str | None) -> list[dict[str, Any]]:
    if not isinstance(section, dict):
        return []
    findings: list[dict[str, Any]] = []
    for key in ("network_findings", "network_security_findings", "scope"):
        entries = section.get(key)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            scope = entry.get("scope") or entry.get("domains") or entry.get("data") or entry.get("description")
            findings.append(
                _finding(
                    finding_id=f"MOBSF-NSC-{_slug(entry.get('description') or 'nsc')}",
                    title=entry.get("description") or "Network security configuration issue",
                    severity=_normalize_severity(entry.get("severity"), "medium"),
                    category="network",
                    description=entry.get("description") or "Network security configuration weakness reported by MobSF.",
                    evidence={"scope": scope},
                    package=package,
                )
            )
    return findings


def _parse_trackers(section: Any, package: str | None) -> list[dict[str, Any]]:
    if not isinstance(section, dict):
        return []
    trackers = section.get("trackers") or section.get("detected_trackers") or []
    if not trackers:
        return []
    return [
        _finding(
            finding_id="MOBSF-TRACKERS",
            title=f"App embeds {len(trackers)} third-party tracker(s)",
            severity="low",
            category="privacy",
            description="Third-party SDKs that collect analytics/advertising data. Confirm disclosure in the privacy notice.",
            evidence={"trackers": [t.get("name") if isinstance(t, dict) else t for t in trackers][:25]},
            package=package,
        )
    ]


def _parse_certificate_analysis(section: Any, package: str | None) -> list[dict[str, Any]]:
    if not isinstance(section, dict):
        return []
    findings_list = section.get("certificate_findings") or section.get("findings") or []
    findings: list[dict[str, Any]] = []
    if isinstance(findings_list, list):
        for entry in findings_list:
            if not isinstance(entry, list) or len(entry) < 2:
                continue
            severity = _normalize_severity(entry[0], "info")
            description = entry[1]
            title = entry[2] if len(entry) > 2 else description
            findings.append(
                _finding(
                    finding_id=f"MOBSF-CERT-{_slug(title)}",
                    title=title,
                    severity=severity,
                    category="signing",
                    description=description,
                    evidence={},
                    package=package,
                )
            )
    return findings


def _parse_permissions(section: Any, package: str | None) -> list[dict[str, Any]]:
    if not isinstance(section, dict):
        return []
    dangerous = [name for name, meta in section.items()
                 if isinstance(meta, dict) and (meta.get("status") or "").lower() in {"dangerous", "signature_or_system"}]
    if not dangerous:
        return []
    return [
        _finding(
            finding_id="MOBSF-DANGEROUS-PERMISSIONS",
            title=f"MobSF flagged {len(dangerous)} dangerous permission(s)",
            severity="medium",
            category="permissions",
            description="MobSF marked these permissions as dangerous or system level.",
            evidence={"permissions": dangerous[:30]},
            package=package,
        )
    ]


def _parse_secrets(section: Any, package: str | None) -> list[dict[str, Any]]:
    if not isinstance(section, list) or not section:
        return []
    return [
        _finding(
            finding_id="MOBSF-POSSIBLE-SECRETS",
            title=f"MobSF detected {len(section)} possible secret(s) in the APK",
            severity="medium",
            category="secret",
            description="Strings that look like API keys, tokens, or credentials baked into the build.",
            evidence={"samples": section[:15]},
            package=package,
            cwe="CWE-798",
        )
    ]


def _parse_urls(payload: dict[str, Any], package: str | None) -> list[dict[str, Any]]:
    urls_section = payload.get("urls")
    if not isinstance(urls_section, list):
        return []
    hosts: list[str] = []
    for entry in urls_section:
        if not isinstance(entry, dict):
            continue
        for url in entry.get("urls", []) or []:
            hosts.append(url)
    if not hosts:
        return []
    return [
        _finding(
            finding_id="MOBSF-URL-INVENTORY",
            title=f"MobSF observed {len(hosts)} URL(s) inside the APK",
            severity="info",
            category="network",
            description="Inventory of URLs found in resources/code. Review for internal endpoints, debug servers, or credentials in query strings.",
            evidence={"sample": hosts[:25]},
            package=package,
        )
    ]


def _parse_emails(section: Any, package: str | None) -> list[dict[str, Any]]:
    if not isinstance(section, list) or not section:
        return []
    return [
        _finding(
            finding_id="MOBSF-EMAILS",
            title=f"MobSF found {len(section)} email address(es) in the APK",
            severity="low",
            category="privacy",
            description="Email addresses embedded in code/resources may leak internal contacts or test accounts.",
            evidence={"sample": [e.get("emails") if isinstance(e, dict) else e for e in section][:20]},
            package=package,
        )
    ]


def _slug(value: Any) -> str:
    text = str(value or "rule")
    safe = "".join(ch if ch.isalnum() else "-" for ch in text)
    return safe.strip("-")[:48].upper() or "RULE"

"""Aggregate findings from prior tools into a single assessment report."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


class FindingCompileTool(BaseTool):
    """Combine findings produced by manifest, secret, and MobSF tools into one report."""

    name = "finding_compile"
    description = (
        "Aggregate all findings produced earlier in this run (manifest, secret_scan, mobsf_findings, "
        "etc.) into a deduplicated executive report grouped by severity and category. Writes a "
        "JSON report artifact and returns counts."
    )
    args_schema = {
        "type": "object",
        "required": [],
        "properties": {
            "findings": {
                "type": "array",
                "description": (
                    "Optional explicit list of findings to compile. Each item should follow the "
                    "schema {id, title, severity, category, description, evidence}. If omitted, "
                    "the tool collects findings from JSON artifacts in this run."
                ),
                "items": {"type": "object"},
            },
            "extra_artifacts": {
                "type": "array",
                "description": "Optional list of workspace-relative paths to additional findings JSON files.",
                "items": {"type": "string"},
            },
        },
    }

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        collected: list[dict[str, Any]] = []
        sources: list[str] = []

        explicit = arguments.get("findings") or []
        if isinstance(explicit, list):
            for entry in explicit:
                if isinstance(entry, dict):
                    collected.append(entry)
            if explicit:
                sources.append("inline")

        # Walk this run's artifacts directory for any findings JSON we previously wrote.
        for path in _iter_findings_files(context.artifacts_dir):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            entries = payload.get("findings") if isinstance(payload, dict) else None
            if isinstance(entries, list):
                for entry in entries:
                    if isinstance(entry, dict):
                        collected.append(entry)
                sources.append(str(path.relative_to(context.workspace_dir)))

        extra = arguments.get("extra_artifacts") or []
        if isinstance(extra, list):
            for rel in extra:
                if not isinstance(rel, str):
                    continue
                candidate = (context.workspace_dir / rel).resolve()
                if not str(candidate).startswith(str(context.workspace_dir.resolve())) or not candidate.exists():
                    continue
                try:
                    payload = json.loads(candidate.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if isinstance(payload, dict):
                    entries = payload.get("findings")
                    if isinstance(entries, list):
                        collected.extend(e for e in entries if isinstance(e, dict))
                        sources.append(rel)

        deduped = _dedupe(collected)
        deduped.sort(key=lambda f: (SEVERITY_ORDER.get(_severity(f), 9), f.get("category") or "", f.get("title") or ""))

        counts: dict[str, int] = defaultdict(int)
        category_counts: dict[str, int] = defaultdict(int)
        for finding in deduped:
            counts[_severity(finding)] += 1
            category_counts[finding.get("category") or "uncategorized"] += 1

        executive = _executive_summary(deduped, counts)

        report = {
            "summary": executive,
            "counts": {
                "total": len(deduped),
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
                "info": counts.get("info", 0),
            },
            "by_category": dict(category_counts),
            "findings": deduped,
            "sources": sorted(set(sources)),
        }

        report_dir = context.artifacts_dir / "report"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "findings.json"
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            summary=(
                f"Compiled {len(deduped)} unique finding(s) from {len(set(sources))} source(s). "
                f"high={counts.get('high', 0)} medium={counts.get('medium', 0)} "
                f"low={counts.get('low', 0)} info={counts.get('info', 0)}."
            ),
            artifacts=[
                Artifact(kind="json", path=str(report_path), description="Compiled assessment findings"),
            ],
            metadata={
                "counts": report["counts"],
                "by_category": report["by_category"],
                "findings": deduped[:60],
                "findings_total": len(deduped),
                "executive_summary": executive,
            },
        )


def _iter_findings_files(artifacts_dir: Path):
    findings_dir = artifacts_dir / "findings"
    if not findings_dir.exists():
        return []
    return sorted(findings_dir.glob("*.json"))


def _severity(finding: dict[str, Any]) -> str:
    severity = finding.get("severity")
    if isinstance(severity, str) and severity.lower() in SEVERITY_ORDER:
        return severity.lower()
    return "info"


def _dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    for finding in findings:
        finding_id = str(finding.get("id") or finding.get("title") or "FINDING")
        title = str(finding.get("title") or finding_id)
        evidence_key = json.dumps(finding.get("evidence") or {}, sort_keys=True, default=str)[:200]
        key = (finding_id, title, evidence_key)
        existing = seen.get(key)
        if existing is None:
            seen[key] = dict(finding)
        else:
            existing_severity = SEVERITY_ORDER.get(_severity(existing), 9)
            new_severity = SEVERITY_ORDER.get(_severity(finding), 9)
            if new_severity < existing_severity:
                existing["severity"] = finding.get("severity")
            existing_sources = existing.setdefault("sources", [existing.get("source")] if existing.get("source") else [])
            source = finding.get("source")
            if source and source not in existing_sources:
                existing_sources.append(source)
    return list(seen.values())


def _executive_summary(findings: list[dict[str, Any]], counts: dict[str, int]) -> str:
    if not findings:
        return "No findings were produced during this assessment."
    pieces = [
        f"Identified {len(findings)} unique findings across the static, secrets, and scanner lanes "
        f"(high={counts.get('high', 0)}, medium={counts.get('medium', 0)}, "
        f"low={counts.get('low', 0)}, info={counts.get('info', 0)})."
    ]
    top = [f for f in findings if _severity(f) == "high"][:3]
    if top:
        pieces.append("Top high-severity items: " + "; ".join(f.get("title", f.get("id", "?")) for f in top) + ".")
    else:
        med = [f for f in findings if _severity(f) == "medium"][:3]
        if med:
            pieces.append("Top medium-severity items: " + "; ".join(f.get("title", f.get("id", "?")) for f in med) + ".")
    return " ".join(pieces)

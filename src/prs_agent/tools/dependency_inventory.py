"""Dependency, SDK, namespace, and native library inventory."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file


SDK_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("Firebase", r"\bcom\.google\.firebase\b|firebaseio\.com|google_app_id", "cloud"),
    ("Google Play Services", r"\bcom\.google\.android\.gms\b", "platform"),
    ("OkHttp", r"\bokhttp3\b|com\.squareup\.okhttp", "network"),
    ("Retrofit", r"\bretrofit2\b|com\.squareup\.retrofit", "network"),
    ("Facebook SDK", r"\bcom\.facebook\b", "social"),
    ("Adjust", r"\bcom\.adjust\.sdk\b", "analytics"),
    ("AppsFlyer", r"\bcom\.appsflyer\b", "analytics"),
    ("Branch", r"\bio\.branch\b", "deeplink"),
    ("Sentry", r"\bio\.sentry\b", "telemetry"),
    ("Crashlytics", r"\bcom\.crashlytics\b|firebase\.crashlytics", "telemetry"),
    ("RootBeer", r"\bcom\.scottyab\.rootbeer\b", "root_detection"),
    ("SQLCipher", r"\bnet\.sqlcipher\b", "storage"),
    ("React Native", r"\bcom\.facebook\.react\b|ReactNative", "framework"),
    ("Flutter", r"\bio\.flutter\b|libflutter\.so", "framework"),
    ("Cordova", r"\borg\.apache\.cordova\b|cordova\.js", "framework"),
    ("Unity", r"\bcom\.unity3d\b|libunity\.so", "game"),
    ("Chucker HTTP Inspector", r"\bcom\.chuckerteam\.chucker\b|ChuckerInterceptor|chucker_library", "debug_tooling"),
    ("Flipper", r"\bcom\.facebook\.flipper\b|SoLoader\.init|FlipperClient", "debug_tooling"),
    ("Stetho", r"\bcom\.facebook\.stetho\b|Stetho\.initialize", "debug_tooling"),
    ("LeakCanary", r"\bleakcanary\b|LeakCanary\.install", "debug_tooling"),
    ("StrictMode", r"\bStrictMode\.setThreadPolicy\b|\bStrictMode\.setVmPolicy\b", "debug_tooling"),
)


RELEASE_DEBUG_TOOLING = {
    "Chucker HTTP Inspector": {
        "severity": "high",
        "cwe": "CWE-489",
        "description": (
            "Chucker is an in-app HTTP inspector. In a release fintech/mobile banking build it can expose "
            "request and response metadata, headers, tokens, PII, and backend behavior to local users or "
            "anyone with app/device access."
        ),
    },
    "Flipper": {
        "severity": "medium",
        "cwe": "CWE-489",
        "description": "Flipper is a debug inspection framework and should not be active in release builds.",
    },
    "Stetho": {
        "severity": "medium",
        "cwe": "CWE-489",
        "description": "Stetho exposes debug inspection capabilities and should not be active in release builds.",
    },
    "LeakCanary": {
        "severity": "medium",
        "cwe": "CWE-489",
        "description": "LeakCanary is a debug memory-leak tool and should not ship in release builds.",
    },
}


SOURCE_SUFFIXES = {".java", ".kt", ".smali", ".xml", ".json", ".properties", ".gradle"}
SKIP_DIRS = {".git", "build", "out", "node_modules", "META-INF"}


class DependencyInventoryTool(BaseTool):
    """Inventory third-party SDKs, namespaces, and native libraries."""

    name = "dependency_inventory"
    description = (
        "Scan decompiled JADX/apktool output for third-party SDKs, package namespaces, Gradle coordinates, "
        "and native .so libraries. Produces dependency and supply-chain inventory findings."
    )
    args_schema = {
        "type": "object",
        "required": ["source_dir"],
        "properties": {
            "source_dir": {"type": "string", "description": "Workspace-relative decompiled source/resource directory."},
            "max_files": {"type": "integer", "description": "Maximum text files to scan. Default 10000."},
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

        max_files = int(arguments.get("max_files") or 10000)
        max_bytes = int(arguments.get("max_file_bytes") or 1_000_000)
        sdk_hits: dict[str, dict[str, Any]] = {}
        namespaces: Counter[str] = Counter()
        gradle_coordinates: set[str] = set()
        files_scanned = 0
        skipped = 0

        compiled = [(name, re.compile(pattern, re.IGNORECASE), category) for name, pattern, category in SDK_PATTERNS]
        for path in _iter_text_files(source_dir, max_files=max_files):
            files_scanned += 1
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
            for name, regex, category in compiled:
                if regex.search(text):
                    hit = sdk_hits.setdefault(name, {"name": name, "category": category, "files": []})
                    if len(hit["files"]) < 20:
                        hit["files"].append(rel)
            for namespace in _extract_namespaces(text):
                namespaces[namespace] += 1
            gradle_coordinates.update(_extract_gradle_coordinates(text))

        native_libs = [
            str(path.relative_to(context.workspace_dir.resolve()))
            for path in source_dir.rglob("*.so")
            if path.is_file()
        ]

        findings = _findings(sdk_hits, namespaces, gradle_coordinates, native_libs)
        findings_dir = context.artifacts_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = findings_dir / "dependency_inventory.json"
        findings_path.write_text(
            json.dumps(
                {
                    "source": "dependency_inventory",
                    "source_dir": str(source_dir.relative_to(context.workspace_dir.resolve())),
                    "files_scanned": files_scanned,
                    "files_skipped": skipped,
                    "sdk_hits": sorted(sdk_hits.values(), key=lambda item: item["name"]),
                    "top_namespaces": namespaces.most_common(50),
                    "gradle_coordinates": sorted(gradle_coordinates),
                    "native_libraries": native_libs[:500],
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
                f"Inventoried {len(sdk_hits)} SDK/library signal(s), {len(native_libs)} native library file(s), "
                f"and {len(gradle_coordinates)} Gradle coordinate(s)."
            ),
            artifacts=[Artifact(kind="json", path=str(findings_path), description="Dependency and native library inventory")],
            metadata={
                "sdk_count": len(sdk_hits),
                "native_library_count": len(native_libs),
                "gradle_coordinate_count": len(gradle_coordinates),
                "findings": findings,
                "top_namespaces": namespaces.most_common(25),
            },
        )


def _iter_text_files(root: Path, *, max_files: int) -> Iterable[Path]:
    count = 0
    for path in root.rglob("*"):
        if count >= max_files:
            return
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        count += 1
        yield path


def _extract_namespaces(text: str) -> list[str]:
    namespaces: list[str] = []
    for match in re.finditer(r"\b(?:import|package)\s+([a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*){1,})", text):
        parts = match.group(1).split(".")
        if len(parts) >= 3:
            namespaces.append(".".join(parts[:3]))
    for match in re.finditer(r"\bL([a-zA-Z_][\w]*(?:/[a-zA-Z_][\w]*){2,})/", text):
        parts = match.group(1).replace("/", ".").split(".")
        if len(parts) >= 3:
            namespaces.append(".".join(parts[:3]))
    return namespaces


def _extract_gradle_coordinates(text: str) -> set[str]:
    coords: set[str] = set()
    for match in re.finditer(r"['\"]([a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+:[^'\"]{2,80})['\"]", text):
        coords.add(match.group(1))
    return coords


def _findings(
    sdk_hits: dict[str, dict[str, Any]],
    namespaces: Counter[str],
    gradle_coordinates: set[str],
    native_libs: list[str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if sdk_hits:
        findings.append(
            _finding(
                finding_id="DEP-SDK-INVENTORY",
                title=f"Detected {len(sdk_hits)} third-party SDK/library signal(s)",
                severity="info",
                category="dependency",
                description="Third-party SDKs affect privacy, attack surface, and supply-chain risk.",
                evidence={"sdks": sorted(sdk_hits.values(), key=lambda item: item["name"])},
            )
        )
    debug_tooling = [
        sdk
        for sdk in sorted(sdk_hits.values(), key=lambda item: item["name"])
        if sdk["name"] in RELEASE_DEBUG_TOOLING
    ]
    for sdk in debug_tooling:
        meta = RELEASE_DEBUG_TOOLING[sdk["name"]]
        findings.append(
            _finding(
                finding_id=f"DEP-RELEASE-DEBUG-TOOL-{_slug(sdk['name'])}",
                title=f"{sdk['name']} appears to be present in the release APK",
                severity=meta["severity"],
                category="debug_tooling",
                description=meta["description"],
                evidence={"tool": sdk["name"], "files": sdk["files"][:20]},
                cwe=meta["cwe"],
            )
        )
    if native_libs:
        findings.append(
            _finding(
                finding_id="DEP-NATIVE-LIBRARIES",
                title=f"APK includes {len(native_libs)} native .so library file(s)",
                severity="medium",
                category="native",
                description=(
                    "Native libraries add memory-safety and reverse-engineering risk. Review hardening, exported symbols, "
                    "and sensitive JNI boundaries with native-analysis tooling."
                ),
                evidence={"libraries": native_libs[:100]},
                cwe="CWE-119",
            )
        )
    if gradle_coordinates:
        findings.append(
            _finding(
                finding_id="DEP-GRADLE-COORDINATES",
                title=f"Recovered {len(gradle_coordinates)} Gradle dependency coordinate(s)",
                severity="info",
                category="dependency",
                description="Recovered build coordinates can be checked against SCA tooling for known CVEs and license risk.",
                evidence={"coordinates": sorted(gradle_coordinates)[:100]},
            )
        )
    if namespaces:
        findings.append(
            _finding(
                finding_id="DEP-NAMESPACE-INVENTORY",
                title="Top package namespaces observed in decompiled sources",
                severity="info",
                category="dependency",
                description="Package namespace frequency helps identify embedded SDKs and code ownership boundaries.",
                evidence={"top_namespaces": namespaces.most_common(50)},
            )
        )
    return findings


def _slug(value: str) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in value).strip("-").upper()


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    evidence: dict[str, Any],
    cwe: str | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "category": category,
        "source": "dependency_inventory",
        "description": description,
        "evidence": evidence,
        "cwe": cwe,
    }

"""Manifest-driven static findings for an APK."""

from __future__ import annotations

import json
from typing import Any

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file


DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.WRITE_SETTINGS",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.READ_LOGS",
}


class ManifestFindingsTool(BaseTool):
    """Parse AndroidManifest.xml and emit structured static findings."""

    name = "manifest_findings"
    description = (
        "Analyze an APK's AndroidManifest for risky flags (debuggable, allowBackup, "
        "cleartextTraffic), dangerous permissions, exported components, custom permissions, "
        "and missing network security config. Returns structured findings."
    )
    args_schema = {
        "type": "object",
        "required": ["apk_path"],
        "properties": {
            "apk_path": {"type": "string", "description": "Path to an APK inside the workspace."}
        },
    }

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        apk_path, error = resolve_workspace_file(context, arguments["apk_path"], self.name)
        if error:
            return error

        try:
            from pyaxmlparser import APK  # type: ignore[import-untyped]
        except ImportError:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                summary="pyaxmlparser is required for manifest analysis.",
                error="Run: pip install pyaxmlparser",
            )

        try:
            apk = APK(str(apk_path))
        except Exception as exc:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                summary="Failed to parse APK manifest.",
                error=f"{type(exc).__name__}: {exc}",
            )

        findings: list[dict[str, Any]] = []
        package = apk.get_package()
        permissions = sorted(apk.get_permissions() or [])

        findings.extend(_check_application_flags(apk, package))
        findings.extend(_check_dangerous_permissions(permissions, package))
        findings.extend(_check_exported_components(apk, package))
        findings.extend(_check_custom_permissions(apk, package))
        findings.extend(_check_network_security_config(apk, package))
        findings.extend(_check_sdk_versions(apk, package))

        severities = [f["severity"] for f in findings]
        high = sum(1 for s in severities if s == "high")
        medium = sum(1 for s in severities if s == "medium")
        low = sum(1 for s in severities if s == "low")
        info = sum(1 for s in severities if s == "info")

        findings_dir = context.artifacts_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = findings_dir / "manifest_findings.json"
        findings_path.write_text(
            json.dumps(
                {
                    "source": "manifest",
                    "package": package,
                    "findings": findings,
                    "counts": {"high": high, "medium": medium, "low": low, "info": info, "total": len(findings)},
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            summary=(
                f"Manifest analysis produced {len(findings)} findings "
                f"(high={high} medium={medium} low={low} info={info})."
            ),
            artifacts=[
                Artifact(kind="json", path=str(findings_path), description="Manifest findings JSON"),
            ],
            metadata={
                "package": package,
                "findings": findings,
                "counts": {"high": high, "medium": medium, "low": low, "info": info, "total": len(findings)},
                "permissions_total": len(permissions),
            },
        )


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    evidence: dict[str, Any],
    cwe: str | None = None,
    package: str | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "category": category,
        "source": "manifest",
        "description": description,
        "evidence": evidence,
        "cwe": cwe,
        "package": package,
    }


def _check_application_flags(apk: Any, package: str | None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        element = apk.get_android_manifest_xml().find("application")
    except Exception:
        element = None
    if element is None:
        return findings

    ns = "{http://schemas.android.com/apk/res/android}"
    debuggable = element.get(f"{ns}debuggable") or element.get("debuggable")
    allow_backup = element.get(f"{ns}allowBackup") or element.get("allowBackup")
    cleartext = element.get(f"{ns}usesCleartextTraffic") or element.get("usesCleartextTraffic")
    nsc = element.get(f"{ns}networkSecurityConfig") or element.get("networkSecurityConfig")

    if str(debuggable).lower() == "true":
        findings.append(
            _finding(
                finding_id="MANIFEST-DEBUGGABLE",
                title="Application is debuggable in release build",
                severity="high",
                category="configuration",
                description=(
                    "android:debuggable=true exposes the JDWP debug interface and lets an attacker "
                    "with adb access run code in app context and read sensitive memory."
                ),
                evidence={"attribute": "android:debuggable", "value": debuggable},
                cwe="CWE-489",
                package=package,
            )
        )

    if allow_backup is None or str(allow_backup).lower() == "true":
        findings.append(
            _finding(
                finding_id="MANIFEST-ALLOW-BACKUP",
                title="Application allows ADB/cloud backup of private data",
                severity="medium",
                category="configuration",
                description=(
                    "android:allowBackup is enabled (default true). adb backup can extract the app's "
                    "private data on devices without disk encryption or a user passphrase."
                ),
                evidence={"attribute": "android:allowBackup", "value": allow_backup or "true (default)"},
                cwe="CWE-200",
                package=package,
            )
        )

    if str(cleartext).lower() == "true":
        findings.append(
            _finding(
                finding_id="MANIFEST-CLEARTEXT",
                title="Application permits cleartext HTTP traffic",
                severity="high",
                category="network",
                description=(
                    "android:usesCleartextTraffic=true allows the app to make plaintext HTTP "
                    "connections, exposing data to network attackers."
                ),
                evidence={"attribute": "android:usesCleartextTraffic", "value": cleartext},
                cwe="CWE-319",
                package=package,
            )
        )

    return findings


def _check_dangerous_permissions(permissions: list[str], package: str | None) -> list[dict[str, Any]]:
    requested_dangerous = sorted(p for p in permissions if p in DANGEROUS_PERMISSIONS)
    if not requested_dangerous:
        return []
    severity = "high" if len(requested_dangerous) >= 5 else "medium"
    return [
        _finding(
            finding_id="MANIFEST-DANGEROUS-PERMS",
            title=f"App requests {len(requested_dangerous)} privacy-sensitive permissions",
            severity=severity,
            category="permissions",
            description=(
                "Each dangerous permission expands the app's attack surface and triggers runtime "
                "consent. Confirm every permission is justified by a feature and that the data is "
                "handled per the privacy policy."
            ),
            evidence={"permissions": requested_dangerous},
            cwe="CWE-250",
            package=package,
        )
    ]


def _check_exported_components(apk: Any, package: str | None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        manifest = apk.get_android_manifest_xml()
    except Exception:
        return findings

    ns = "{http://schemas.android.com/apk/res/android}"
    exported_components: list[dict[str, Any]] = []

    for component_kind in ("activity", "service", "receiver", "provider"):
        for app in manifest.findall("application"):
            for element in app.findall(component_kind):
                name = element.get(f"{ns}name") or element.get("name")
                exported_attr = element.get(f"{ns}exported") or element.get("exported")
                permission = element.get(f"{ns}permission") or element.get("permission")
                has_intent_filter = element.find("intent-filter") is not None

                exported: bool | None
                if exported_attr is not None:
                    exported = str(exported_attr).lower() == "true"
                else:
                    exported = has_intent_filter

                if exported:
                    exported_components.append(
                        {
                            "type": component_kind,
                            "name": name,
                            "exported_explicit": exported_attr is not None,
                            "permission": permission,
                            "has_intent_filter": has_intent_filter,
                        }
                    )

    unprotected = [c for c in exported_components if not c["permission"]]
    if unprotected:
        findings.append(
            _finding(
                finding_id="MANIFEST-EXPORTED-UNPROTECTED",
                title=f"{len(unprotected)} exported component(s) lack signature permission protection",
                severity="high",
                category="components",
                description=(
                    "Exported components without a signature-level permission can be reached by "
                    "other installed apps and may allow intent injection, privilege escalation, or "
                    "leaking of internal functionality."
                ),
                evidence={"components": unprotected[:30]},
                cwe="CWE-926",
                package=package,
            )
        )

    if exported_components:
        findings.append(
            _finding(
                finding_id="MANIFEST-EXPORTED-INVENTORY",
                title=f"App exposes {len(exported_components)} exported component(s)",
                severity="info",
                category="components",
                description="Inventory of components reachable from other apps. Audit each for input validation.",
                evidence={"components": exported_components[:50]},
                package=package,
            )
        )
    return findings


def _check_custom_permissions(apk: Any, package: str | None) -> list[dict[str, Any]]:
    try:
        manifest = apk.get_android_manifest_xml()
    except Exception:
        return []
    ns = "{http://schemas.android.com/apk/res/android}"

    issues: list[dict[str, Any]] = []
    for perm in manifest.findall("permission"):
        name = perm.get(f"{ns}name")
        level = perm.get(f"{ns}protectionLevel") or "normal"
        if "signature" not in level.lower():
            issues.append({"name": name, "protection_level": level})

    if not issues:
        return []
    return [
        _finding(
            finding_id="MANIFEST-CUSTOM-PERM-WEAK",
            title=f"{len(issues)} custom permission(s) declared without signature protection",
            severity="medium",
            category="permissions",
            description=(
                "Custom permissions below signature level can be claimed by any installed app. "
                "Use protectionLevel=\"signature\" for permissions that gate sensitive components."
            ),
            evidence={"permissions": issues[:30]},
            cwe="CWE-275",
            package=package,
        )
    ]


def _check_network_security_config(apk: Any, package: str | None) -> list[dict[str, Any]]:
    try:
        manifest = apk.get_android_manifest_xml()
    except Exception:
        return []
    ns = "{http://schemas.android.com/apk/res/android}"
    app = manifest.find("application")
    if app is None:
        return []
    nsc = app.get(f"{ns}networkSecurityConfig") or app.get("networkSecurityConfig")
    target_sdk = apk.get_target_sdk_version()
    try:
        target = int(target_sdk) if target_sdk else 0
    except (TypeError, ValueError):
        target = 0

    if not nsc and target < 28:
        return [
            _finding(
                finding_id="MANIFEST-NO-NSC",
                title="No networkSecurityConfig declared and targetSdk < 28",
                severity="medium",
                category="network",
                description=(
                    "Without a Network Security Config and with targetSdk below 28, cleartext "
                    "traffic is permitted by platform default. Add an explicit config that denies "
                    "cleartext and pins critical certificates."
                ),
                evidence={"target_sdk": target_sdk},
                cwe="CWE-319",
                package=package,
            )
        ]
    return []


def _check_sdk_versions(apk: Any, package: str | None) -> list[dict[str, Any]]:
    try:
        min_sdk = int(apk.get_min_sdk_version() or 0)
    except (TypeError, ValueError):
        min_sdk = 0
    try:
        target_sdk = int(apk.get_target_sdk_version() or 0)
    except (TypeError, ValueError):
        target_sdk = 0
    findings: list[dict[str, Any]] = []
    if min_sdk and min_sdk < 23:
        findings.append(
            _finding(
                finding_id="MANIFEST-LOW-MIN-SDK",
                title=f"minSdkVersion={min_sdk} supports devices without runtime permissions",
                severity="medium",
                category="configuration",
                description=(
                    "Devices below API 23 grant all manifest permissions at install time and lack "
                    "many modern security mitigations. Raise minSdk to 23 or higher if the user base allows."
                ),
                evidence={"min_sdk": min_sdk},
                package=package,
            )
        )
    if target_sdk and target_sdk < 30:
        findings.append(
            _finding(
                finding_id="MANIFEST-OLD-TARGET-SDK",
                title=f"targetSdkVersion={target_sdk} disables recent platform protections",
                severity="medium",
                category="configuration",
                description=(
                    "Targeting an old SDK opts the app out of scoped storage, package visibility "
                    "restrictions, and other security defaults."
                ),
                evidence={"target_sdk": target_sdk},
                package=package,
            )
        )
    return findings

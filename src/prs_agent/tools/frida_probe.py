"""Frida probe runner for runtime security checks (SSL pinning, root detection, crypto)."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool


PROBES: dict[str, dict[str, Any]] = {
    "ssl_pinning": {
        "title": "Universal SSL pinning probe",
        "description": (
            "Attempts to bypass common SSL pinning implementations (OkHttp CertificatePinner, "
            "TrustManagerImpl, javax.net.ssl.HostnameVerifier). If hooks fire, the app's pinning "
            "is reachable from a Frida agent and not strongly enforced."
        ),
        "cwe": "CWE-295",
        "script": r"""
Java.perform(function() {
  var hits = [];
  try {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
      name: 'com.prs.PinBypass',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function() {},
        checkServerTrusted: function() {},
        getAcceptedIssuers: function() { return []; }
      }
    });
    var init = SSLContext.init.overload(
      '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
    );
    init.implementation = function(km, tm, sr) {
      hits.push('SSLContext.init replaced trust managers');
      init.call(this, km, [TrustManager.$new()], sr);
    };
  } catch (e) { hits.push('SSLContext hook error: ' + e.message); }

  try {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(a, b) {
      hits.push('okhttp3.CertificatePinner.check bypassed for ' + a);
    };
  } catch (e) {}

  setTimeout(function() {
    send({ probe: 'ssl_pinning', hits: hits, completed: true });
  }, 4000);
});
""",
    },
    "root_detection": {
        "title": "Root/Magisk detection probe",
        "description": (
            "Hooks common root-detection points (RootBeer, file existence checks for su, "
            "Build.TAGS) to surface and bypass anti-root logic."
        ),
        "cwe": "CWE-693",
        "script": r"""
Java.perform(function() {
  var hits = [];
  try {
    var File = Java.use('java.io.File');
    var origExists = File.exists;
    origExists.implementation = function() {
      var path = this.getAbsolutePath();
      if (path.indexOf('/su') >= 0 || path.indexOf('magisk') >= 0 || path.indexOf('busybox') >= 0) {
        hits.push('File.exists masked: ' + path);
        return false;
      }
      return origExists.call(this);
    };
  } catch (e) { hits.push('File hook error: ' + e.message); }

  try {
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';
  } catch (e) {}

  try {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() { hits.push('RootBeer.isRooted -> false'); return false; };
  } catch (e) {}

  setTimeout(function() {
    send({ probe: 'root_detection', hits: hits, completed: true });
  }, 4000);
});
""",
    },
    "crypto": {
        "title": "Weak crypto and key handling probe",
        "description": (
            "Records uses of javax.crypto.Cipher and java.security.MessageDigest to surface "
            "weak algorithms (DES, RC4, ECB, MD5, SHA-1) and hardcoded key material."
        ),
        "cwe": "CWE-327",
        "script": r"""
Java.perform(function() {
  var hits = [];
  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function(t) {
      hits.push('Cipher.getInstance(' + t + ')');
      return this.getInstance(t);
    };
  } catch (e) { hits.push('Cipher hook error: ' + e.message); }

  try {
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.getInstance.overload('java.lang.String').implementation = function(t) {
      hits.push('MessageDigest.getInstance(' + t + ')');
      return this.getInstance(t);
    };
  } catch (e) {}

  setTimeout(function() {
    send({ probe: 'crypto', hits: hits, completed: true });
  }, 5000);
});
""",
    },
}


WEAK_CRYPTO_TOKENS = ("des/", "des ", "rc4", "/ecb", "md5", "sha-1", "sha1")


class FridaProbeTool(BaseTool):
    """Run a canned Frida probe against a target package on a connected device."""

    name = "frida_probe"
    description = (
        "Run a canned Frida instrumentation probe (ssl_pinning, root_detection, crypto) against "
        "a connected device or emulator. Spawns the target package, attaches the probe, and "
        "summarizes hooks that fired into structured findings."
    )
    args_schema = {
        "type": "object",
        "required": ["package", "probe"],
        "properties": {
            "package": {"type": "string", "description": "Target application package id."},
            "probe": {"type": "string", "enum": list(PROBES.keys())},
            "duration_seconds": {"type": "integer", "description": "Wall-clock window for the probe (default 12)."},
        },
    }

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        package = str(arguments.get("package") or "").strip()
        probe_key = str(arguments.get("probe") or "").strip()
        probe = PROBES.get(probe_key)

        if not package:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.VALIDATION_ERROR,
                summary="package is required.",
                error="missing_argument:package",
            )
        if probe is None:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.VALIDATION_ERROR,
                summary=f"Unknown probe: {probe_key}",
                error="unknown_probe",
            )
        if not shutil.which("frida"):
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                summary="frida is required to run probes.",
                error="missing_binary:frida",
            )

        duration = max(5, min(60, int(arguments.get("duration_seconds") or 12)))
        scripts_dir = context.artifacts_dir / "exploits" / "frida"
        scripts_dir.mkdir(parents=True, exist_ok=True)
        script_path = scripts_dir / f"{probe_key}.js"
        script_path.write_text(probe["script"], encoding="utf-8")
        log_path = scripts_dir / f"{probe_key}_{_safe(package)}.log"

        argv = ["frida", "-U", "-f", package, "-l", str(script_path), "--runtime=v8", "--no-pause"]
        started = time.monotonic()
        try:
            completed = subprocess.run(  # noqa: S603 - bounded argv
                argv,
                capture_output=True,
                text=True,
                timeout=duration,
                check=False,
            )
            stdout = completed.stdout
            stderr = completed.stderr
            returncode = completed.returncode
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            returncode = 0  # Frida is meant to be killed.
            timed_out = True
        except (FileNotFoundError, PermissionError, OSError) as exc:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                summary="Frida could not be launched.",
                error=str(exc),
                metadata={"argv": argv},
            )
        duration_ms = int((time.monotonic() - started) * 1000)

        log_path.write_text(stdout + "\n--- stderr ---\n" + stderr, encoding="utf-8")

        hits = _parse_hits(stdout)
        findings: list[dict[str, Any]] = []
        if hits:
            severity = "high" if probe_key in {"ssl_pinning", "root_detection"} else "medium"
            findings.append(
                {
                    "id": f"FRIDA-{probe_key.upper()}",
                    "title": probe["title"],
                    "severity": severity,
                    "category": "runtime",
                    "source": "frida_probe",
                    "description": probe["description"],
                    "evidence": {"package": package, "hits": hits[:30], "hit_count": len(hits)},
                    "cwe": probe["cwe"],
                    "package": package,
                }
            )

        if probe_key == "crypto":
            weak = [h for h in hits if any(token in h.lower() for token in WEAK_CRYPTO_TOKENS)]
            if weak:
                findings.append(
                    {
                        "id": "FRIDA-WEAK-CRYPTO",
                        "title": "Application invoked weak cryptographic primitives at runtime",
                        "severity": "high",
                        "category": "crypto",
                        "source": "frida_probe",
                        "description": (
                            "Runtime crypto hooks captured the application using deprecated "
                            "algorithms (DES, RC4, ECB, MD5 or SHA-1). Replace with AES-GCM "
                            "and SHA-256+ to meet modern guidance."
                        ),
                        "evidence": {"package": package, "hits": weak[:20]},
                        "cwe": "CWE-327",
                        "package": package,
                    }
                )

        findings_dir = context.artifacts_dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        findings_path = findings_dir / f"frida_{probe_key}.json"
        findings_path.write_text(
            json.dumps(
                {
                    "source": "frida_probe",
                    "probe": probe_key,
                    "package": package,
                    "hits": hits,
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
                f"Frida probe '{probe_key}' against {package}: {len(hits)} hook event(s), "
                f"{len(findings)} finding(s), duration {duration_ms}ms (timed_out={timed_out})."
            ),
            stdout_excerpt=stdout[:600],
            stderr_excerpt=stderr[:600],
            artifacts=[
                Artifact(kind="log", path=str(log_path), description="Frida probe log"),
                Artifact(kind="script", path=str(script_path), description="Probe script"),
                Artifact(kind="json", path=str(findings_path), description="Probe findings"),
            ],
            metadata={
                "probe": probe_key,
                "package": package,
                "hits": hits,
                "findings": findings,
                "duration_ms": duration_ms,
                "timed_out": timed_out,
                "exit_code": returncode,
            },
        )


def _parse_hits(stdout: str) -> list[str]:
    hits: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if "hits" in line and line.startswith("{"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and isinstance(payload.get("hits"), list):
                hits.extend(str(h) for h in payload["hits"])
        elif line.startswith("[*]") or line.startswith("[+]"):
            hits.append(line)
    return hits


def _safe(value: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in value)

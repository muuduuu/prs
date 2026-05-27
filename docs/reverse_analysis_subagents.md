# Reverse-Analysis Subagents

This scaffold gives PRS a set of bounded specialist lanes without giving the
model direct shell or device control. When Bifrost is enabled, PRS runs these as
separate specialist lanes with role prompts, restricted toolsets, and independent
memory. The orchestrator still executes only registered tools with validated
arguments.

## Roles

- `static_reverse`: inspects APK metadata, manifests, resources, and decompiled
  code using `apk_metadata`, `manifest_findings`, `apktool_decompile`, and
  `jadx_decompile`.
- `secret_webview`: consumes decompiled source directories and emits focused
  findings from `source_inventory`, `secret_scan`, and `webview_audit` with
  redacted evidence. This lane inventories URLs, endpoints, deeplinks, cloud
  references, auth/token handling, storage, crypto, native loading, and IPC
  usage before the report is compiled.
- `dynamic_device`: checks authorized device readiness and bounded runtime
  observations through `adb`, `frida`, `emulator`, and `frida_probe`.
- `mobsf_triage`: submits MobSF early with `mobsf_submit`, lets it run in the
  background, and later uses `mobsf_poll` to collect results without blocking
  static reverse work. `mobsf_findings` can normalize the JSON report into PRS
  findings.
- `exploitability_validation`: compiles findings and confirms practical
  reachability where safe with `finding_compile`, `exploit_verify`,
  `exploit_chain`, `intent_fuzzer`, `backup_audit`, and `frida_probe`.
- `report_synthesis`: combines specialist outputs into confirmed findings,
  hypotheses, blocked checks, evidence references, and next steps.

## Orchestrator Integration

The `reverse_analysis_plan` tool returns these roles, workflows, handoffs, and
guardrails as metadata. It is intentionally non-invasive: it does not run
reverse-engineering commands, call MobSF, or alter device state. Bifrost can use
the returned plan to decide which existing bounded tool to call next.

In Bifrost crew mode, PRS starts static reverse, MobSF triage, and dynamic
device readiness as parallel primary lanes. It then starts dependent
secrets/WebView and exploitability validation lanes after primary artifacts and
findings have had a chance to land. The validation lane then builds CWE/CVSS
enriched attack paths that connect findings into realistic chains with
preconditions, confidence, impact, bounded validation steps, and remediation.
This keeps slow MobSF work asynchronous while avoiding source-scanner races
against missing decompiler output.

## Docker

Build and run PRS with optional MobSF:

```bash
docker compose up --build
```

Open `http://127.0.0.1:8787`. MobSF is exposed at
`http://127.0.0.1:8000` and is reachable from the PRS container at
`http://mobsf:8000`.

For USB device workflows, run PRS on the host or extend the compose file with
the host-specific USB device mounts and permissions required by your platform.

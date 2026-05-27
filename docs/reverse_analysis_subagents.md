# Reverse-Analysis Subagents

This scaffold gives PRS a set of bounded specialist lanes without giving the
model direct shell or device control. The orchestrator still executes only
registered tools with validated arguments.

## Roles

- `static_reverse`: inspects APK metadata, manifests, resources, and decompiled
  code using `apk_metadata`, `apktool_decompile`, and `jadx_decompile`.
- `dynamic_device`: checks authorized device readiness and bounded runtime
  observations through `adb` and `frida`.
- `mobsf_triage`: submits MobSF early with `mobsf_submit`, lets it run in the
  background, and later uses `mobsf_poll` to collect results without blocking
  static reverse work.
- `report_synthesis`: combines specialist outputs into confirmed findings,
  hypotheses, blocked checks, evidence references, and next steps.

## Orchestrator Integration

The `reverse_analysis_plan` tool returns these roles, workflows, handoffs, and
guardrails as metadata. It is intentionally non-invasive: it does not run
reverse-engineering commands, call MobSF, or alter device state. Bifrost can use
the returned plan to decide which existing bounded tool to call next.

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

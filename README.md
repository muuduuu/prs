# PRS Mobile Pentest Agent

PRS is a local, API-driven ReAct orchestrator for authorized Android application assessment. It coordinates a Bifrost LLM gateway with controlled tool wrappers for device checks, APK metadata extraction, decompilation, MobSF upload, finding normalization, and bounded exploitability validation.

## Current Capabilities

- Local web dashboard for APK upload, Bifrost setup, model selection, MobSF config, live trace viewing, and final report output.
- Bifrost model discovery from an OpenAI-compatible `/models` endpoint.
- Bifrost crew mode: when the gateway is enabled, PRS runs specialist lanes for static reversing, MobSF triage, dynamic/device checks, secrets/WebView review, exploitability validation, and report synthesis.
- Deterministic no-key planner for local smoke tests.
- Tool registry with allow-listed wrappers for:
  - `adb`: devices, version, third-party package listing.
  - `apk_metadata`: APK package metadata via `pyaxmlparser`, with `aapt` fallback when available.
  - `manifest_findings`: manifest risk findings for debug flags, backups, cleartext, exported components, permissions, SDK levels, and network security config.
  - `apktool`: resources and smali decompilation.
  - `jadx`: Java/Kotlin-like source decompilation.
  - `secret_scan`: decompiled source scanner with redacted secret evidence.
  - `webview_audit`: risky WebView/JavaScript bridge configuration scanner.
  - `frida`: CLI readiness and USB process listing.
  - `emulator`: AVD list/boot/wait/install/launch/uninstall/device-state helper.
  - `frida_probe`: bounded runtime probes for SSL pinning, root detection, and crypto observations.
  - `intent_fuzzer`: bounded exported-component probing on an authorized connected device or emulator.
  - `backup_audit`: controlled `adb backup` confirmation for allowBackup risk.
  - `mobsf_submit` / `mobsf_poll`: asynchronous MobSF analysis lane.
  - `mobsf_scan`: synchronous MobSF fallback for direct scans.
  - `mobsf_findings`: MobSF JSON report parser into the unified findings shape.
  - `finding_compile` / `exploit_verify`: consolidated report and confirmed/unverified validation table.
- JSONL and final JSON traces in `runs/<run_id>/logs/` for later SFT dataset conversion.
- Reverse-analysis subagent scaffold exposed through `reverse_analysis_plan` for
  static reverse, dynamic/device checks, MobSF triage, secrets/WebView review,
  exploitability validation, and report synthesis.

## Run Locally

```bash
cd prs
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
prs-agent-app
```

Open `http://127.0.0.1:8787`.

## Run with Docker

```bash
docker compose up --build
```

Open PRS at `http://127.0.0.1:8787`.

Open MobSF at `http://127.0.0.1:8000`, copy the MobSF API key, then put this in the PRS MobSF panel:

```text
Server URL: http://mobsf:8000
API key: <MobSF API key>
```

Use `http://mobsf:8000` from inside Docker Compose. If you run PRS directly on your host, use `http://127.0.0.1:8000`.

See `docs/reverse_analysis_subagents.md` for the subagent scaffold and Docker notes.

If you do not install the package, run directly:

```bash
PYTHONPATH=src python -m prs_agent.app
```

## macOS Tooling Setup

Install Homebrew first if it is not already present.

```bash
brew install --cask android-platform-tools
brew install --cask android-commandlinetools
brew install apktool jadx
python3 -m pip install --user frida-tools
```

Install Android SDK build-tools so `aapt` is available:

```bash
export ANDROID_HOME="$(brew --prefix)/share/android-commandlinetools"
yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" "build-tools;36.0.0" "platforms;android-36"
export PATH="$ANDROID_HOME/build-tools/36.0.0:$PATH"
```

For MobSF, Docker is the simplest local option:

```bash
docker run --rm -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Then put `http://127.0.0.1:8000` and your MobSF API key into the app.

## Phone Setup

1. Enable Developer Options on the Android device.
2. Enable USB debugging.
3. Connect over USB and approve the trust prompt.
4. Verify:

```bash
adb devices
frida --version
frida-ps -Uai
```

Frida process listing requires a compatible Frida server on rooted devices or another valid Frida runtime path. Keep the Frida client/server versions aligned.

## Bifrost Setup

1. Check `Use gateway`.
2. Enter the Bifrost chat endpoint, for example `https://bifrost.example/v1/chat/completions`. You can also enter a base `/v1` URL or a `/models` URL; PRS normalizes common OpenAI-compatible URLs for chat calls.
3. Enter the API key.
4. Optionally enter a models endpoint. If blank, PRS derives `/v1/models` from common chat endpoint paths. Model loading uses GET; agent planning uses POST to the chat endpoint.
5. Click `Load`.
6. Choose a model.
7. Start the run.

The gateway is expected to return strict JSON decisions with either `type: "tool_call"` or `type: "final"`.

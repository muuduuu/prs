# PRS Mobile Pentest Agent

PRS is a local, API-driven ReAct orchestrator for authorized Android application assessment. It coordinates a Bifrost LLM gateway with controlled tool wrappers for device checks, APK metadata extraction, decompilation, MobSF upload, and runtime readiness checks.

## Current Capabilities

- Local web dashboard for APK upload, Bifrost setup, model selection, MobSF config, live trace viewing, and final report output.
- Bifrost model discovery from an OpenAI-compatible `/models` endpoint.
- Deterministic no-key planner for local smoke tests.
- Tool registry with allow-listed wrappers for:
  - `adb`: devices, version, third-party package listing.
  - `aapt`: APK package metadata and manifest badging.
  - `apktool`: resources and smali decompilation.
  - `jadx`: Java/Kotlin-like source decompilation.
  - `frida`: CLI readiness and USB process listing.
  - `mobsf_scan`: APK upload to a configured MobSF server.
- JSONL and final JSON traces in `runs/<run_id>/logs/` for later SFT dataset conversion.

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

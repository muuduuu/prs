# Mobile Tool Runtime

PRS can run in a prepared Docker toolbox inspired by Strix's sandbox model:
the app runs inside a repeatable container with mobile assessment tools already
installed, while MobSF runs as a sibling service.

## Reference Tooling

The mobile references point to a common baseline stack:

- Static/reverse: MobSF, apktool, JADX, QARK-style checks, backup extraction.
- Dynamic/runtime: ADB, Frida, Objection, emulator/device workflows.
- IPC and app surface: Drozer-style component review, intent fuzzing, content
  provider checks.
- Network: Burp/MITM proxy workflows, TLS/cleartext review, pinning checks.
- Native/reversing: radare2/Ghidra-class review for `.so` libraries.
- Code review: Semgrep/Gitleaks-style pattern scanning.

PRS implements the safe automated subset directly through registered tools and
keeps invasive runtime actions bounded to authorized devices and packages.

## Start The Mobile Toolbox

PowerShell:

```powershell
.\scripts\prs-docker-mobile.ps1 -MobSFApiKey "<MobSF API key>"
```

Bash:

```bash
export PRS_MOBSF_API_KEY="<MobSF API key>"
./scripts/prs-docker-mobile.sh
```

Or directly:

```bash
docker compose -f docker-compose.mobile.yml up --build
```

Open PRS at `http://127.0.0.1:8787` and MobSF at
`http://127.0.0.1:8000`.

Inside Docker, PRS uses:

```text
PRS_MOBSF_URL=http://mobsf:8000
PRS_MOBSF_API_KEY=<your key>
```

If the UI MobSF fields are blank, PRS falls back to these environment values.

## Installed In `Dockerfile.mobile`

- `adb`
- `aapt`
- `apktool`
- `jadx`
- Java runtime
- `frida-tools`
- `objection`
- `semgrep`
- supporting utilities: `curl`, `wget`, `git`, `openssl`, `file`, `binutils`

Some workflows still require host access:

- USB Android devices usually need host-side ADB or platform-specific USB
  passthrough into Docker.
- Burp GUI is intentionally not embedded; use Burp on the host and configure
  device/emulator proxying separately.
- Native deep-dive tools such as Ghidra are better run as separate GUI tools;
  PRS currently inventories native libraries and points to artifacts.

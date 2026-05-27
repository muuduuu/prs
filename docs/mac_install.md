# macOS Install and Run Guide

## 1. Install PRS

```bash
git clone https://github.com/muuduuu/prs.git
cd prs
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
prs-agent-app
```

Open `http://127.0.0.1:8787`.

## 2. Install Analysis Tools

```bash
brew install --cask android-platform-tools
brew install --cask android-commandlinetools
brew install apktool jadx
python3 -m pip install --user frida-tools
```

`android-platform-tools` provides `adb`. `apktool` and `jadx` are Homebrew formulae. Frida recommends installing CLI tools through PyPI.

## 3. Install Android Build Tools for `aapt`

```bash
export ANDROID_HOME="$(brew --prefix)/share/android-commandlinetools"
yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses
"$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" "build-tools;36.0.0" "platforms;android-36"
export PATH="$ANDROID_HOME/build-tools/36.0.0:$PATH"
```

Add the `ANDROID_HOME` and `PATH` exports to your shell profile after confirming the build-tools version installed.

## 4. Optional MobSF

```bash
docker run --rm -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Use `http://127.0.0.1:8000` in the PRS MobSF panel.

## 5. Validate

```bash
adb devices
aapt version
apktool --version
jadx --version
frida --version
frida-ps -Uai
```

The app also shows readiness for each tool in the left sidebar.

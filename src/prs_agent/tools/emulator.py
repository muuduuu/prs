"""Android emulator/AVD controller and APK install/launch helper."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from prs_agent.contracts import Artifact, ToolContext, ToolResult, ToolStatus
from prs_agent.tools.base import BaseTool
from prs_agent.tools.pathing import resolve_workspace_file
from prs_agent.tools.subprocess_tool import SubprocessRunner


SUBCOMMANDS = (
    "list_avds",
    "boot",
    "wait_ready",
    "shutdown",
    "install_apk",
    "launch_package",
    "uninstall_package",
    "device_state",
)


class EmulatorTool(BaseTool):
    """Drive the Android emulator and adb for runtime exploit verification.

    Subcommands:
      - list_avds: enumerate installed AVDs
      - boot: start named AVD in the background
      - wait_ready: block until adb device finishes booting
      - shutdown: emu kill the connected device
      - install_apk: adb install workspace-relative APK
      - launch_package: monkey-launch a package
      - uninstall_package: adb uninstall
      - device_state: adb getprop snapshot
    """

    name = "emulator"
    description = (
        "Control an Android emulator/AVD for runtime exploit verification: list/boot AVDs, "
        "wait for boot, install/launch/uninstall the target APK, and capture device state."
    )
    args_schema = {
        "type": "object",
        "required": ["subcommand"],
        "properties": {
            "subcommand": {"type": "string", "enum": list(SUBCOMMANDS)},
            "avd_name": {"type": "string", "description": "AVD name for boot/shutdown."},
            "apk_path": {"type": "string", "description": "Workspace-relative APK path for install_apk."},
            "package": {"type": "string", "description": "Package id for launch/uninstall."},
            "wait_seconds": {"type": "integer", "description": "Max seconds to wait_ready (default 180)."},
            "headless": {"type": "boolean", "description": "Boot the emulator with -no-window (default true)."},
        },
    }

    def __init__(self, runner: SubprocessRunner | None = None) -> None:
        self.runner = runner or SubprocessRunner()

    def run(self, *, arguments: dict, context: ToolContext) -> ToolResult:
        sub = arguments["subcommand"]
        if sub == "list_avds":
            return self._list_avds(context)
        if sub == "boot":
            return self._boot(arguments, context)
        if sub == "wait_ready":
            return self._wait_ready(arguments, context)
        if sub == "shutdown":
            return self._shutdown(context)
        if sub == "install_apk":
            return self._install_apk(arguments, context)
        if sub == "launch_package":
            return self._launch_package(arguments, context)
        if sub == "uninstall_package":
            return self._uninstall_package(arguments, context)
        if sub == "device_state":
            return self._device_state(context)
        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.VALIDATION_ERROR,
            summary="Unknown subcommand.",
            error=f"unknown subcommand: {sub}",
        )

    def _list_avds(self, context: ToolContext) -> ToolResult:
        if not shutil.which("emulator"):
            return _missing_binary(self.name, "emulator")
        return self.runner.run(
            tool_name=self.name,
            argv=["emulator", "-list-avds"],
            cwd=context.workspace_dir,
            timeout_seconds=min(context.timeout_seconds, 30),
        )

    def _boot(self, arguments: dict, context: ToolContext) -> ToolResult:
        avd = arguments.get("avd_name")
        if not avd:
            return _missing_arg(self.name, "avd_name")
        if not shutil.which("emulator"):
            return _missing_binary(self.name, "emulator")

        headless = bool(arguments.get("headless", True))
        logs_dir = context.artifacts_dir / "emulator"
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_path = logs_dir / f"{_safe(avd)}.log"

        argv = ["emulator", "-avd", avd, "-no-snapshot-save", "-no-boot-anim"]
        if headless:
            argv.append("-no-window")

        try:
            proc = subprocess.Popen(  # noqa: S603 - bounded argv
                argv,
                cwd=str(context.workspace_dir),
                stdout=log_path.open("ab"),
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
        except (FileNotFoundError, PermissionError, OSError) as exc:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.ERROR,
                summary="Failed to launch emulator process.",
                error=str(exc),
                metadata={"argv": argv},
            )

        pid_file = logs_dir / f"{_safe(avd)}.pid"
        pid_file.write_text(str(proc.pid), encoding="utf-8")
        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            summary=f"Launched emulator '{avd}' (pid {proc.pid}). Use wait_ready to confirm boot.",
            artifacts=[
                Artifact(kind="log", path=str(log_path), description="Emulator stdout/stderr"),
            ],
            metadata={"avd_name": avd, "pid": proc.pid, "log_path": str(log_path), "argv": argv},
        )

    def _wait_ready(self, arguments: dict, context: ToolContext) -> ToolResult:
        if not shutil.which("adb"):
            return _missing_binary(self.name, "adb")
        wait_seconds = max(10, int(arguments.get("wait_seconds") or 180))
        deadline = time.monotonic() + wait_seconds

        # Poll boot completion via getprop.
        while time.monotonic() < deadline:
            check = subprocess.run(  # noqa: S603,S607 - fixed argv
                ["adb", "shell", "getprop", "sys.boot_completed"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if check.returncode == 0 and check.stdout.strip() == "1":
                return ToolResult(
                    tool_name=self.name,
                    status=ToolStatus.SUCCESS,
                    summary="Device reported sys.boot_completed=1.",
                    stdout_excerpt=check.stdout.strip(),
                    metadata={"waited_seconds": wait_seconds},
                )
            time.sleep(3)

        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.TIMEOUT,
            summary=f"Device did not finish booting within {wait_seconds}s.",
            error="boot_timeout",
            metadata={"waited_seconds": wait_seconds},
        )

    def _shutdown(self, context: ToolContext) -> ToolResult:
        if not shutil.which("adb"):
            return _missing_binary(self.name, "adb")
        return self.runner.run(
            tool_name=self.name,
            argv=["adb", "emu", "kill"],
            cwd=context.workspace_dir,
            timeout_seconds=min(context.timeout_seconds, 30),
        )

    def _install_apk(self, arguments: dict, context: ToolContext) -> ToolResult:
        if not shutil.which("adb"):
            return _missing_binary(self.name, "adb")
        apk_arg = arguments.get("apk_path")
        if not apk_arg:
            return _missing_arg(self.name, "apk_path")
        apk_path, error = resolve_workspace_file(context, apk_arg, self.name)
        if error:
            return error
        return self.runner.run(
            tool_name=self.name,
            argv=["adb", "install", "-r", "-t", str(apk_path)],
            cwd=context.workspace_dir,
            timeout_seconds=context.timeout_seconds,
        )

    def _launch_package(self, arguments: dict, context: ToolContext) -> ToolResult:
        if not shutil.which("adb"):
            return _missing_binary(self.name, "adb")
        package = arguments.get("package")
        if not package:
            return _missing_arg(self.name, "package")
        return self.runner.run(
            tool_name=self.name,
            argv=["adb", "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1"],
            cwd=context.workspace_dir,
            timeout_seconds=min(context.timeout_seconds, 60),
        )

    def _uninstall_package(self, arguments: dict, context: ToolContext) -> ToolResult:
        if not shutil.which("adb"):
            return _missing_binary(self.name, "adb")
        package = arguments.get("package")
        if not package:
            return _missing_arg(self.name, "package")
        return self.runner.run(
            tool_name=self.name,
            argv=["adb", "uninstall", package],
            cwd=context.workspace_dir,
            timeout_seconds=min(context.timeout_seconds, 60),
        )

    def _device_state(self, context: ToolContext) -> ToolResult:
        if not shutil.which("adb"):
            return _missing_binary(self.name, "adb")
        props = ("ro.build.version.release", "ro.build.version.sdk", "ro.product.model", "ro.product.cpu.abi", "service.bootanim.exit")
        collected: dict[str, str] = {}
        for prop in props:
            try:
                completed = subprocess.run(  # noqa: S603,S607
                    ["adb", "shell", "getprop", prop],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                collected[prop] = completed.stdout.strip()
            except Exception as exc:
                collected[prop] = f"error: {exc}"

        state_dir = context.artifacts_dir / "emulator"
        state_dir.mkdir(parents=True, exist_ok=True)
        snapshot = state_dir / "device_state.json"
        snapshot.write_text(json.dumps(collected, indent=2), encoding="utf-8")
        return ToolResult(
            tool_name=self.name,
            status=ToolStatus.SUCCESS,
            summary="Captured adb getprop snapshot.",
            artifacts=[Artifact(kind="json", path=str(snapshot), description="Device property snapshot")],
            metadata={"properties": collected},
        )


def _missing_binary(tool_name: str, binary: str) -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        status=ToolStatus.ERROR,
        summary=f"Required binary not found on PATH: {binary}.",
        error=f"missing_binary:{binary}",
    )


def _missing_arg(tool_name: str, argument: str) -> ToolResult:
    return ToolResult(
        tool_name=tool_name,
        status=ToolStatus.VALIDATION_ERROR,
        summary=f"Required argument missing: {argument}.",
        error=f"missing_argument:{argument}",
    )


def _safe(value: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in value)

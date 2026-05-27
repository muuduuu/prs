"""Safe subprocess helper for CLI-backed tools."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from prs_agent.context import OutputReducer
from prs_agent.contracts import ToolResult, ToolStatus


class SubprocessRunner:
    """Run command argument vectors with timeout and bounded observations."""

    def __init__(self, reducer: OutputReducer | None = None) -> None:
        self.reducer = reducer or OutputReducer()

    def run(
        self,
        *,
        tool_name: str,
        argv: list[str],
        cwd: Path,
        timeout_seconds: int,
    ) -> ToolResult:
        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except (FileNotFoundError, PermissionError, OSError) as exc:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                summary="Executable could not be started.",
                error=str(exc),
                metadata={"argv": argv},
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            stdout_excerpt, stdout_truncated = self.reducer.excerpt(stdout)
            stderr_excerpt, stderr_truncated = self.reducer.excerpt(stderr)
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.TIMEOUT,
                summary=f"Tool timed out after {timeout_seconds} seconds.",
                stdout_excerpt=stdout_excerpt,
                stderr_excerpt=stderr_excerpt,
                error="timeout",
                metadata={
                    "argv": argv,
                    "timeout_seconds": timeout_seconds,
                    "stdout_truncated": stdout_truncated,
                    "stderr_truncated": stderr_truncated,
                },
            )

        duration_ms = int((time.monotonic() - started) * 1000)
        stdout_excerpt, stdout_truncated = self.reducer.excerpt(completed.stdout)
        stderr_excerpt, stderr_truncated = self.reducer.excerpt(completed.stderr)
        status = ToolStatus.SUCCESS if completed.returncode == 0 else ToolStatus.ERROR

        return ToolResult(
            tool_name=tool_name,
            status=status,
            exit_code=completed.returncode,
            summary=(
                "Command completed successfully."
                if status == ToolStatus.SUCCESS
                else "Command exited with a non-zero status."
            ),
            stdout_excerpt=stdout_excerpt,
            stderr_excerpt=stderr_excerpt,
            metadata={
                "argv": argv,
                "duration_ms": duration_ms,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
            },
            error=None if status == ToolStatus.SUCCESS else "non_zero_exit",
        )

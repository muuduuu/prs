"""Context and output reduction helpers."""

from __future__ import annotations

from collections import deque
from typing import Any

from prs_agent.contracts import ToolResult


class OutputReducer:
    """Reduce noisy tool output before it is shown to Bifrost.

    The first implementation is deterministic and deliberately conservative.
    Later versions can add parsers for MobSF JSON, AndroidManifest XML, jadx
    output, and Frida traces without changing the orchestrator loop.
    """

    def __init__(self, max_chars: int = 4_000) -> None:
        self.max_chars = max_chars

    def excerpt(self, text: str) -> tuple[str, bool]:
        """Return a bounded excerpt and whether truncation occurred."""

        if len(text) <= self.max_chars:
            return text, False

        head_budget = self.max_chars // 2
        tail_budget = self.max_chars - head_budget
        excerpt = (
            text[:head_budget]
            + "\n\n[... output truncated by context manager ...]\n\n"
            + text[-tail_budget:]
        )
        return excerpt, True


class MemoryBuffer:
    """Short-term memory for recent ReAct steps."""

    def __init__(self, max_items: int = 12) -> None:
        self._items: deque[dict[str, Any]] = deque(maxlen=max_items)

    def append(self, item: dict[str, Any]) -> None:
        self._items.append(item)

    def snapshot(self) -> list[dict[str, Any]]:
        return list(self._items)


def compact_tool_result(result: ToolResult) -> dict[str, Any]:
    """Convert a tool result into the observation sent to Bifrost."""

    return result.to_observation()


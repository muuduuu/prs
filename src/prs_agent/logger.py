"""Structured ReAct trace logging."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Callable

from prs_agent.contracts import utc_now_iso


class TraceLogger:
    """Append-only JSONL logger for operational traces and SFT conversion."""

    schema_version = "react_trace.v1"

    def __init__(
        self,
        *,
        run_id: str,
        objective: str,
        log_path: Path,
        bifrost_model: str,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.run_id = run_id
        self.objective = objective
        self.log_path = log_path
        self.bifrost_model = bifrost_model
        self.on_event = on_event
        self._step_index = 0
        self._events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def step_index(self) -> int:
        return self._step_index

    def event(
        self,
        *,
        phase: str,
        thought: str = "",
        action: dict[str, Any] | None = None,
        observation: dict[str, Any] | None = None,
        labels: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            record = {
                "schema_version": self.schema_version,
                "run_id": self.run_id,
                "step_index": self._step_index,
                "timestamp": utc_now_iso(),
                "phase": phase,
                "objective": self.objective,
                "bifrost_model": self.bifrost_model,
                "thought": thought,
                "action": action,
                "observation": observation,
                "labels": labels or {},
            }
            self._events.append(record)
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        if self.on_event:
            self.on_event(record)
        return record

    def next_step(self) -> None:
        with self._lock:
            self._step_index += 1

    def write_final_trace(self, path: Path, final_answer: dict[str, Any]) -> None:
        payload = {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "objective": self.objective,
            "bifrost_model": self.bifrost_model,
            "events": self._events,
            "final_answer": final_answer,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

"""Base classes for tool wrappers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from prs_agent.contracts import ToolContext, ToolResult


class BaseTool(ABC):
    """Common interface every callable capability must implement."""

    name: str
    description: str
    args_schema: dict[str, Any]

    def schema_for_model(self) -> dict[str, Any]:
        """Expose only the model-safe tool schema."""

        return {
            "name": self.name,
            "description": self.description,
            "args_schema": self.args_schema,
        }

    def validate(self, arguments: dict[str, Any]) -> str | None:
        """Minimal schema validation.

        This intentionally covers the skeleton use case. In production, swap
        this for Pydantic or jsonschema validation with richer error reporting.
        """

        required = self.args_schema.get("required", [])
        missing = [field for field in required if field not in arguments]
        if missing:
            return f"Missing required arguments: {missing}"

        properties = self.args_schema.get("properties", {})
        unknown = [field for field in arguments if field not in properties]
        if unknown:
            return f"Unknown arguments: {unknown}"

        for field, spec in properties.items():
            if field not in arguments:
                continue
            allowed = spec.get("enum")
            if allowed and arguments[field] not in allowed:
                return f"Argument {field!r} must be one of {allowed}"

        return None

    @abstractmethod
    def run(self, *, arguments: dict[str, Any], context: ToolContext) -> ToolResult:
        """Execute the tool and return a normalized result."""


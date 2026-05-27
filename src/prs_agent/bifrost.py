"""Client abstractions for the Bifrost LLM gateway."""

from __future__ import annotations

import json
from typing import Any, Protocol
import urllib.error
import urllib.request
from urllib.parse import urlparse

from prs_agent.contracts import BifrostDecision


class BifrostClient(Protocol):
    """Protocol for a mockable Bifrost gateway client."""

    model_name: str

    def decide(
        self,
        *,
        objective: str,
        tool_schemas: list[dict[str, Any]],
        memory: list[dict[str, Any]],
    ) -> BifrostDecision:
        """Return the next ReAct decision.

        Production implementations should call the internal Bifrost API and
        parse a strict JSON response into `BifrostDecision`.
        """


class BifrostHTTPClient:
    """Small HTTP client for an OpenAI-compatible Bifrost gateway.

    The app accepts the gateway URL and key at runtime. This client expects the
    gateway to expose a chat-completions-like endpoint and to return a JSON
    object in the assistant message content that matches `BifrostDecision`.
    """

    def __init__(
        self,
        *,
        gateway_url: str,
        api_key: str,
        model_name: str,
        timeout_seconds: int = 60,
    ) -> None:
        self.gateway_url = gateway_url
        self.api_key = api_key
        self.model_name = model_name
        self.timeout_seconds = timeout_seconds

    def decide(
        self,
        *,
        objective: str,
        tool_schemas: list[dict[str, Any]],
        memory: list[dict[str, Any]],
    ) -> BifrostDecision:
        system_prompt = (
            "You are the planning brain for an authorized mobile application "
            "security assessment agent. Return only strict JSON. Choose exactly "
            "one registered tool call or a final answer. Never invent tools. "
            "Never return shell commands."
        )
        user_payload = {
            "objective": objective,
            "available_tools": tool_schemas,
            "recent_memory": memory,
            "response_schema": {
                "tool_call": {
                    "type": "tool_call",
                    "thought": "short rationale",
                    "tool_name": "registered tool name",
                    "arguments": {},
                },
                "final": {
                    "type": "final",
                    "thought": "short rationale",
                    "answer": {
                        "summary": "assessment summary",
                        "findings": [],
                        "artifacts": [],
                    },
                },
            },
        }
        body = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_payload)},
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }
        request = urllib.request.Request(
            self.gateway_url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            return BifrostDecision(
                type="final",
                thought="Bifrost gateway request failed.",
                answer={"summary": f"Bifrost gateway error: {exc}", "findings": []},
            )

        content = self._extract_content(payload)
        try:
            decision = json.loads(content)
        except json.JSONDecodeError:
            return BifrostDecision(
                type="final",
                thought="Bifrost returned non-JSON content.",
                answer={"summary": content[:1000], "findings": []},
            )

        return BifrostDecision(
            type=decision.get("type", "final"),
            thought=decision.get("thought", ""),
            tool_name=decision.get("tool_name"),
            arguments=decision.get("arguments") or {},
            answer=decision.get("answer") or {},
        )

    def _extract_content(self, payload: dict[str, Any]) -> str:
        if "choices" in payload:
            return payload["choices"][0]["message"]["content"]
        if "content" in payload:
            return payload["content"]
        return json.dumps(payload)


def derive_models_url(gateway_url: str) -> str:
    """Infer an OpenAI-compatible models endpoint from a chat endpoint."""

    clean = gateway_url.rstrip("/")
    for suffix in ("/chat/completions", "/responses"):
        if clean.endswith(suffix):
            return clean[: -len(suffix)] + "/models"
    parsed = urlparse(clean)
    if parsed.path.endswith("/models"):
        return clean
    return clean + "/models"


def fetch_bifrost_models(
    *,
    gateway_url: str,
    api_key: str,
    models_url: str | None = None,
    timeout_seconds: int = 30,
) -> list[str]:
    """Fetch model ids from Bifrost.

    Supports OpenAI-style `{"data": [{"id": "..."}]}` responses and a few
    common internal variants such as `{"models": ["..."]}`.
    """

    request = urllib.request.Request(
        models_url or derive_models_url(gateway_url),
        headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        payload = json.loads(response.read().decode("utf-8"))

    if isinstance(payload.get("data"), list):
        return sorted(
            item["id"]
            for item in payload["data"]
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        )
    if isinstance(payload.get("models"), list):
        models = [
            item if isinstance(item, str) else item.get("id")
            for item in payload["models"]
            if isinstance(item, str) or isinstance(item, dict)
        ]
        return sorted(model for model in models if isinstance(model, str))
    if isinstance(payload, list):
        models = [item if isinstance(item, str) else item.get("id") for item in payload]
        return sorted(model for model in models if isinstance(model, str))
    return []


class MockBifrostClient:
    """Deterministic client for local development and tests."""

    model_name = "mock-bifrost"

    def __init__(self) -> None:
        self._step = 0

    def decide(
        self,
        *,
        objective: str,
        tool_schemas: list[dict[str, Any]],
        memory: list[dict[str, Any]],
    ) -> BifrostDecision:
        self._step += 1

        available = {tool["name"] for tool in tool_schemas}

        if self._step == 1 and "adb" in available:
            return BifrostDecision(
                type="tool_call",
                thought="Start by checking whether an Android device is visible.",
                tool_name="adb",
                arguments={"subcommand": "devices"},
            )

        if self._step == 2 and "apktool_decompile" in available:
            return BifrostDecision(
                type="tool_call",
                thought="Decompile the APK if a sample path was provided.",
                tool_name="apktool_decompile",
                arguments={"apk_path": "samples/example.apk"},
            )

        return BifrostDecision(
            type="final",
            thought="The initial orchestration demonstration is complete.",
            answer={
                "summary": "Mock run completed. Replace MockBifrostClient with the real Bifrost API client.",
                "objective": objective,
                "steps_observed": len(memory),
            },
        )


class AssessmentPlannerClient:
    """Deterministic planner for running the app without an LLM key.

    This gives the UI a complete local flow: discover devices, optionally
    inspect ADB version, decompile the uploaded APK, then produce a report.
    """

    model_name = "deterministic-assessment-planner"

    def __init__(self, *, apk_path: str | None, include_device_checks: bool = True) -> None:
        self.apk_path = apk_path
        self.include_device_checks = include_device_checks
        self._step = 0
        self._plan: list[tuple[str, str, dict[str, Any]]] | None = None

    def decide(
        self,
        *,
        objective: str,
        tool_schemas: list[dict[str, Any]],
        memory: list[dict[str, Any]],
    ) -> BifrostDecision:
        available = {tool["name"] for tool in tool_schemas}
        if self._plan is None:
            self._plan = self._build_plan(available)

        if self._step < len(self._plan):
            tool_name, thought, arguments = self._plan[self._step]
            self._step += 1
            return BifrostDecision(
                type="tool_call",
                thought=thought,
                tool_name=tool_name,
                arguments=arguments,
            )

        return BifrostDecision(
            type="final",
            thought="Initial automated assessment flow is complete.",
            answer={
                "summary": (
                    "Initial assessment completed. Review observations for missing local tools, "
                    "connected devices, and generated artifacts."
                ),
                "objective": objective,
                "findings": [],
                "artifacts": self._collect_artifacts(memory),
                "next_steps": [
                    "Configure Bifrost for adaptive planning across all registered tools.",
                    "Connect MobSF for deeper static analysis.",
                    "Run with a real Android device for dynamic ADB and Frida checks.",
                    "Add parsers that convert artifacts into normalized findings.",
                ],
            },
        )

    def _build_plan(self, available: set[str]) -> list[tuple[str, str, dict[str, Any]]]:
        plan: list[tuple[str, str, dict[str, Any]]] = []
        if self.include_device_checks and "adb" in available:
            plan.extend(
                [
                    (
                        "adb",
                        "Check whether an Android device is connected before dynamic checks.",
                        {"subcommand": "devices"},
                    ),
                    (
                        "adb",
                        "Capture the installed ADB version for reproducibility.",
                        {"subcommand": "version"},
                    ),
                    (
                        "frida",
                        "Check whether Frida tooling is available for runtime instrumentation.",
                        {"subcommand": "version"},
                    ),
                ]
            )

        if self.apk_path:
            if "apk_metadata" in available:
                plan.append(
                    (
                        "apk_metadata",
                        "Extract package metadata, permissions, and launchable activity.",
                        {"apk_path": self.apk_path},
                    )
                )
            if "apktool_decompile" in available:
                plan.append(
                    (
                        "apktool_decompile",
                        "Decompile resources and smali for static review.",
                        {"apk_path": self.apk_path},
                    )
                )
            if "jadx_decompile" in available:
                plan.append(
                    (
                        "jadx_decompile",
                        "Decompile Java/Kotlin sources for code-level review.",
                        {"apk_path": self.apk_path},
                    )
                )
            if "mobsf_scan" in available:
                plan.append(
                    (
                        "mobsf_scan",
                        "Submit the APK to MobSF when configured for vulnerability triage.",
                        {"apk_path": self.apk_path},
                    )
                )
        return plan

    def _collect_artifacts(self, memory: list[dict[str, Any]]) -> list[dict[str, Any]]:
        artifacts: list[dict[str, Any]] = []
        for item in memory:
            observation = item.get("observation", {})
            artifacts.extend(observation.get("artifacts") or [])
        return artifacts

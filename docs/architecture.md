# Autonomous Mobile Pentest Agent Architecture

## Scope

This phase builds an API-driven ReAct orchestrator for authorized mobile application security testing. The orchestrator coordinates Bifrost, an internal LLM gateway, with plug-in tools such as ADB, apktool, MobSF, Frida, and future dynamic analysis helpers. It focuses on planning, execution control, normalized observations, safe failure handling, and durable trace logging.

Exploit development, bypass payloads, and target-specific offensive logic are intentionally outside this foundation. Tools are treated as controlled capabilities exposed through narrow schemas.

## 1. ReAct Loop

The agent cycles through:

1. Objective
   - User or API submits a bounded assessment goal.
   - Example: "Perform initial static triage on this APK and identify high-risk components."
   - The orchestrator creates a run id, policy envelope, working directory, initial memory, and trace log.

2. Thought
   - Bifrost receives the current objective, compact memory, available tool schemas, recent observations, and policy constraints.
   - Bifrost returns structured JSON, not free-form shell text.
   - The response is either:
     - `tool_call`: invoke one registered tool with validated arguments.
     - `final`: conclude with findings, evidence, and next recommended steps.

3. Action
   - The orchestrator validates the selected tool name and arguments against the registry.
   - The tool wrapper executes the real capability through a controlled interface.
   - CLI tools run through subprocess controls.
   - REST tools use dedicated clients.
   - Device hooks use explicit session abstractions.

4. Observation
   - Every tool returns a normalized `ToolResult`.
   - Raw output is stored on disk when needed.
   - Bifrost receives a compact observation containing status, summary, key artifacts, important excerpts, error category, and metadata.

5. Next Thought
   - The orchestrator appends the normalized observation to short-term memory.
   - Context manager compacts older steps.
   - The loop continues until Bifrost returns `final`, max iterations are reached, budget expires, or a fatal policy/runtime condition occurs.

### ReAct Message Contract

Bifrost should return one of these shapes:

```json
{
  "type": "tool_call",
  "thought": "I need to inspect connected Android devices before using ADB actions.",
  "tool_name": "adb",
  "arguments": {
    "subcommand": "devices"
  }
}
```

```json
{
  "type": "final",
  "thought": "The static triage is complete.",
  "answer": {
    "summary": "No connected device was available, so dynamic analysis was skipped.",
    "findings": [],
    "artifacts": []
  }
}
```

The orchestrator owns validation and execution. Bifrost proposes actions; it never directly executes commands.

## 2. Tool Registry Design

Tools are plug-ins implementing a common `BaseTool` interface:

- `name`: stable machine-readable identifier.
- `description`: concise capability description for Bifrost.
- `args_schema`: JSON-schema-like dictionary for arguments.
- `run(arguments, context) -> ToolResult`: execute and return normalized result.

### Tool Categories

CLI tools:

- Examples: `apktool`, `jadx`, `adb`, `semgrep`, `trufflehog`.
- Wrapper responsibilities:
  - Build commands from validated structured arguments.
  - Avoid arbitrary shell execution.
  - Set timeout, working directory, environment, and output limits.
  - Capture exit code, stdout, stderr, duration, and generated artifacts.

REST API tools:

- Examples: MobSF upload/scan/report endpoints.
- Wrapper responsibilities:
  - Keep auth and base URL outside Bifrost context.
  - Normalize HTTP failures.
  - Return stable artifact references to reports and JSON payloads.

Device/session tools:

- Examples: Frida scripts, ADB shell sessions, emulator controls.
- Wrapper responsibilities:
  - Track target device/session id.
  - Enforce allow-listed operations.
  - Bound runtime and output volume.
  - Tear down sessions on timeout or run completion.

### Plug-and-Play Contract

The registry exposes tool descriptions to Bifrost, but keeps execution details private. Adding a tool should not require changing the orchestrator loop.

Each tool returns:

```json
{
  "tool_name": "apktool_decompile",
  "status": "success",
  "exit_code": 0,
  "summary": "Decompiled APK to artifacts/decompiled/example.",
  "stdout_excerpt": "...",
  "stderr_excerpt": "",
  "artifacts": [
    {
      "kind": "directory",
      "path": "artifacts/decompiled/example",
      "description": "apktool output directory"
    }
  ],
  "metadata": {
    "duration_ms": 8120
  },
  "error": null
}
```

## 3. Context and Memory Management

Mobile security tools can emit megabytes of logs, decompiled code, manifests, smali, stack traces, and JSON reports. The orchestrator separates durable storage from model context.

### Output Pipeline

1. Capture
   - Full stdout/stderr can be written to artifact files.
   - The tool result stores only excerpts and artifact references.

2. Classify
   - Detect output type where possible:
     - AndroidManifest XML
     - MobSF JSON
     - stack trace
     - dependency list
     - decompiler progress log
     - vulnerability finding table

3. Extract
   - Prefer structured parsers:
     - XML parser for manifest.
     - JSON parser for MobSF reports.
     - Regex only for narrow, stable CLI patterns.

4. Reduce
   - Keep security-relevant lines:
     - exported components
     - permissions
     - deep links
     - secrets indicators
     - network security config
     - crypto/API misuse findings
     - command failures
   - Drop repetitive progress logs.

5. Summarize
   - Use local deterministic summarization first.
   - Optional Bifrost summarization can compact large structured reports into findings.

6. Reference
   - Provide artifact paths and hashes so future steps can request specific follow-up parsing.

### Memory Layers

Short-term memory:

- Recent thoughts, actions, observations.
- Kept within a strict token/character budget.

Run memory:

- Summaries of completed phases.
- Key facts such as package name, APK path, connected device id, app id, findings, generated artifact paths.

Artifact store:

- Full raw outputs and generated files.
- Not sent to Bifrost unless specifically parsed or summarized.

Fine-tuning trace:

- Complete structured sequence of thought/action/observation/final records.
- Can include raw artifact references, but should not blindly inline massive raw content.

## 4. Data Logging for Future Fine-Tuning

Every run writes append-only JSONL events and a final consolidated JSON trace. JSONL is operationally useful during long runs; the final trace is useful for dataset generation.

### Event Record

```json
{
  "schema_version": "react_trace.v1",
  "run_id": "20260527-173000-abc123",
  "step_index": 3,
  "timestamp": "2026-05-27T17:30:12Z",
  "phase": "observation",
  "objective": "Perform initial static triage on the APK.",
  "bifrost_model": "bifrost-prod",
  "thought": "I need the decompiled manifest to inspect exported components.",
  "action": {
    "tool_name": "apktool_decompile",
    "arguments": {
      "apk_path": "samples/app.apk"
    }
  },
  "observation": {
    "status": "success",
    "summary": "Decompiled APK.",
    "artifacts": [
      {
        "kind": "directory",
        "path": "artifacts/decompiled/app"
      }
    ]
  },
  "labels": {
    "success": true,
    "error_category": null,
    "requires_human_review": false
  }
}
```

### SFT Conversion

Later, successful traces can be converted into examples such as:

- Input:
  - Objective
  - Tool schemas
  - Prior compact observations
- Output:
  - Next valid thought and tool call

Final-answer examples can train report synthesis:

- Input:
  - Objective
  - Findings memory
  - Artifact summaries
- Output:
  - Final assessment summary

### Data Hygiene

- Redact secrets, API keys, tokens, device identifiers, and customer names before dataset export.
- Log policy decisions separately from model thoughts.
- Include tool versions and environment metadata to make traces reproducible.
- Mark failed or manually corrected traces so they are not accidentally used as positive SFT examples.

## 5. Error Recovery

The orchestrator should not die because a tool fails. Failures become observations unless the orchestrator itself is compromised or storage is unavailable.

### Tool Crash

- Capture non-zero exit code, stderr excerpt, duration, and command metadata.
- Categorize as `tool_error`.
- Let Bifrost decide whether to retry, choose another tool, or conclude.
- Apply retry limits per tool/action signature.

### Hallucinated Tool or Arguments

- Registry validation rejects unknown tools and invalid arguments.
- The observation states available tool names and validation errors.
- This teaches the loop to self-correct without exposing shell execution.

### Timeout

- Subprocess/session wrapper kills the child process.
- Return `status = "timeout"`.
- Preserve partial output excerpts and artifact references.
- Include timeout value in metadata.

### Oversized Output

- Store raw output as an artifact.
- Return summarized excerpts and `truncated = true`.
- Bifrost can request a parser tool or artifact inspection tool if it needs targeted details.

### Repeated Failure

- Maintain a failure counter keyed by tool name plus normalized arguments.
- Stop retry loops after a configured threshold.
- Escalate to final answer with blocked reason if no progress is possible.

### Safety Controls

- No arbitrary shell strings from Bifrost.
- Tool wrappers build argument vectors.
- Workspace paths are normalized and checked.
- Each run has a bounded working directory.
- Network/device tools require explicit configuration.
- All actions are auditable through the trace log.

#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from typing import Any


TOOL_ALIASES = {
    "Bash": "terminal.exec",
    "Edit": "write_file",
    "MultiEdit": "write_file",
    "Write": "write_file",
    "NotebookEdit": "write_file",
    "Task": "spawn_agent",
    "WebFetch": "web.fetch",
    "WebSearch": "web.search",
}


def read_payload() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        return {}
    return {}


def first_non_empty(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def compact(value: Any, limit: int = 500) -> str:
    try:
        text = json.dumps(value, separators=(",", ":"), ensure_ascii=True)
    except Exception:
        text = str(value)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def normalize_tool(name: str) -> str:
    stripped = name.strip()
    if not stripped:
        return ""
    return TOOL_ALIASES.get(stripped, stripped)


def split_csv_env(var_name: str) -> list[str]:
    raw = os.environ.get(var_name, "")
    if not raw.strip():
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def extract_prompt(payload: dict[str, Any]) -> str:
    message = payload.get("message")
    if isinstance(message, dict):
        msg_prompt = first_non_empty(message.get("content"), message.get("text"))
        if msg_prompt:
            return msg_prompt

    messages = payload.get("messages")
    if isinstance(messages, list):
        for item in reversed(messages):
            if isinstance(item, dict):
                role = str(item.get("role", "")).lower()
                if role == "user":
                    from_history = first_non_empty(item.get("content"), item.get("text"))
                    if from_history:
                        return from_history

    return first_non_empty(
        payload.get("prompt"),
        payload.get("user_prompt"),
        payload.get("userPrompt"),
        payload.get("input"),
        payload.get("text"),
    )


def extract_tool(payload: dict[str, Any]) -> tuple[str, str]:
    tool_block = payload.get("tool")
    raw_name = first_non_empty(
        payload.get("tool_name"),
        payload.get("toolName"),
        tool_block.get("name") if isinstance(tool_block, dict) else "",
        tool_block if isinstance(tool_block, str) else "",
        payload.get("name"),
    )
    return raw_name, normalize_tool(raw_name)


def build_gate_command(prompt: str, requested_tools: list[str], confirmed_tools: list[str]) -> list[str]:
    command = [
        "ai-sec",
        "agent",
        "gate",
        "--prompt",
        prompt,
        "--session-id",
        os.environ.get("AI_SEC_SESSION_ID", "sess_claude_hook"),
        "--user-id",
        os.environ.get("AI_SEC_USER_ID", "claude_user"),
    ]

    gateway_url = os.environ.get("AI_SEC_GATEWAY_URL", "").strip()
    if gateway_url:
        command.extend(["--base-url", gateway_url])

    bearer = os.environ.get("AI_SEC_BEARER_TOKEN", "").strip() or os.environ.get("SERVICE_API_TOKEN", "").strip()
    if bearer:
        command.extend(["--token", bearer])

    for tool in requested_tools:
        command.extend(["--tool", tool])

    for tool in confirmed_tools:
        command.extend(["--confirmed-tool", tool])

    return command


def run_gate(prompt: str, requested_tools: list[str], confirmed_tools: list[str]) -> tuple[int, str, dict[str, Any]]:
    command = build_gate_command(prompt, requested_tools, confirmed_tools)
    proc = subprocess.run(command, capture_output=True, text=True)
    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    raw = stdout if stdout else stderr
    parsed: dict[str, Any] = {}
    if stdout:
        try:
            maybe = json.loads(stdout)
            if isinstance(maybe, dict):
                parsed = maybe
        except Exception:
            parsed = {}
    return proc.returncode, raw, parsed


def fail_closed() -> bool:
    return os.environ.get("AI_SEC_FAIL_CLOSED", "0").strip().lower() in {"1", "true", "yes", "on"}


def tool_input_summary(payload: dict[str, Any]) -> str:
    tool_input = payload.get("tool_input", payload.get("toolInput", payload.get("input")))
    if tool_input is None:
        return ""
    return compact(tool_input)


def emit_pretool_decision(permission_decision: str, reason: str) -> None:
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission_decision,
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(payload))


def handle_pre_tool(payload: dict[str, Any], prompt_hint: str, raw_tool: str, mapped_tool: str) -> int:
    if not mapped_tool and not prompt_hint:
        return 0

    details = [f"Claude Code tool request: {raw_tool or mapped_tool}"]
    if mapped_tool and raw_tool and mapped_tool != raw_tool:
        details.append(f"Mapped tool: {mapped_tool}")
    if prompt_hint:
        details.append(f"User prompt: {prompt_hint}")
    input_summary = tool_input_summary(payload)
    if input_summary:
        details.append(f"Tool input: {input_summary}")

    gate_prompt = "\n".join(details)
    requested_tools = [mapped_tool] if mapped_tool else []
    confirmed_tools = [normalize_tool(tool) for tool in split_csv_env("AI_SEC_CONFIRMED_TOOLS")]

    gate_code, gate_text, gate_json = run_gate(gate_prompt, requested_tools, confirmed_tools)
    if gate_code == 0:
        return 0

    if gate_code in (20, 30):
        decision = "ask" if gate_code == 20 else "deny"
        risk = gate_json.get("risk_score")
        reason = f"ai-sec {gate_json.get('status', 'review')} for {raw_tool or mapped_tool}"
        if isinstance(risk, int):
            reason += f" (risk={risk})"
        emit_pretool_decision(decision, reason)
        return 0

    if fail_closed():
        emit_pretool_decision("deny", "ai-sec validation failed in fail-closed mode")
        return 0

    if gate_text:
        print(f"ai-sec hook warning (allowing tool): {gate_text}", file=sys.stderr)
    return 0


def handle_user_prompt(prompt: str) -> int:
    if not prompt:
        return 0

    confirmed_tools = [normalize_tool(tool) for tool in split_csv_env("AI_SEC_CONFIRMED_TOOLS")]
    gate_code, gate_text, gate_json = run_gate(prompt, [], confirmed_tools)
    if gate_code == 0:
        return 0

    if gate_code in (20, 30):
        status = gate_json.get("status", "review")
        print(f"ai-sec blocked prompt submit ({status})", file=sys.stderr)
        if gate_text:
            print(gate_text, file=sys.stderr)
        return 2

    if fail_closed():
        print("ai-sec error in fail-closed mode; blocking prompt submit", file=sys.stderr)
        if gate_text:
            print(gate_text, file=sys.stderr)
        return 2

    if gate_text:
        print(f"ai-sec hook warning (allowing prompt): {gate_text}", file=sys.stderr)
    return 0


def main() -> int:
    payload = read_payload()
    event_name = first_non_empty(payload.get("hook_event_name"), payload.get("hookEventName"))
    prompt = extract_prompt(payload)
    raw_tool, mapped_tool = extract_tool(payload)

    if event_name == "PreToolUse" or raw_tool:
        return handle_pre_tool(payload, prompt, raw_tool, mapped_tool)

    if event_name == "UserPromptSubmit" or prompt:
        return handle_user_prompt(prompt)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

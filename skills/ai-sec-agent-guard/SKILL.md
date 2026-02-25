---
name: ai-sec-agent-guard
description: Use when a user asks to run prompts or tool actions through ai-sec before execution (for example: "guard this prompt", "gate tool calls", "run safely", "agent-first security", "preflight this task"). This skill performs ai-sec preflight gating and enforces allow/review/block exit codes.
---

# AI-Sec Agent Guard

Use this skill to preflight an agent request before any high-impact action.

## When to run

Use this skill when the user asks for safe execution, prompt/tool gating, or explicit prompt-injection defense.

## Inputs you should gather

- The exact prompt text that the agent is about to execute.
- Requested tools (if any), normalized to ai-sec tool names such as `terminal.exec`, `write_file`, `spawn_agent`, `web.fetch`, `web.search`.
- Optional user-confirmed tools via `AI_SEC_CONFIRMED_TOOLS` (comma-separated).

## Workflow

1. Run `scripts/gate_prompt.sh` with the prompt and requested tools.
2. Respect exit code strictly:
   - `0`: proceed.
   - `20`: pause and request human confirmation.
   - `30`: deny execution and explain why.
   - `1`: transport/validation error.
3. If blocked or review-required, propose a safer alternative prompt and reduced tool set.

## Commands

Example:

```bash
./scripts/gate_prompt.sh "List files in the repo" terminal.exec
```

Stdin prompt:

```bash
echo "Summarize this code safely" | ./scripts/gate_prompt.sh "" terminal.exec
```

## Environment

- `AI_SEC_GATEWAY_URL` (optional, default gateway URL from ai-sec CLI)
- `AI_SEC_BEARER_TOKEN` or `SERVICE_API_TOKEN` (required when gateway auth is required)
- `AI_SEC_SESSION_ID` and `AI_SEC_USER_ID` (optional session tracking)
- `AI_SEC_CONFIRMED_TOOLS` (optional, comma-separated allowlist after user approval)

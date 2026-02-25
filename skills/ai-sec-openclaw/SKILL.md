---
name: ai-sec-openclaw
description: Use when the user wants to integrate ai-sec into an OpenClaw bot (for example: "add ai-sec to openclaw", "guard openclaw tools", "openclaw prompt injection defense", "scaffold openclaw security middleware"). This skill scaffolds OpenClaw guard code using @codegrammer/ai-sec-openclaw-adapter with autonomous mode by default and optional human approval mode.
---

# AI-Sec OpenClaw

Use this skill to scaffold and wire ai-sec into OpenClaw bot workflows.

## When to run

Run when the user asks to protect OpenClaw tool execution or prompt flow with ai-sec.

## Workflow

1. Generate integration helper with `scripts/scaffold_openclaw_integration.sh`.
2. Choose review mode:
   - `autonomous` (default): continue on `review/challenge`.
   - `human_approval`: require approval callback before re-gating.
3. Wire generated helper around each sensitive tool execution path.
4. Run a gate sanity check using `ai-sec agent gate`.

## Commands

Scaffold into current project:

```bash
./scripts/scaffold_openclaw_integration.sh --target ./src/guards --review-mode autonomous
```

Scaffold strict approval version:

```bash
./scripts/scaffold_openclaw_integration.sh --target ./src/guards --review-mode human_approval
```

## Runtime environment

- `AI_SEC_GATEWAY_URL` (example: `http://127.0.0.1:8080`)
- `AI_SEC_BEARER_TOKEN` or `SERVICE_API_TOKEN` when auth is required
- Optional: `AI_SEC_SESSION_ID`, `AI_SEC_USER_ID`

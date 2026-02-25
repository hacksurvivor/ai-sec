---
name: ai-sec-bootstrap
description: Use when the user asks to install or configure ai-sec for coding agents (for example: Claude hooks, Codex wrapper, agent-first setup, local integration install). This skill installs and verifies ai-sec integrations for Claude Code and Codex CLI.
---

# AI-Sec Bootstrap

Use this skill to install ai-sec integrations for agent CLIs with minimal manual steps.

## When to run

Run when the user asks to set up ai-sec in Claude Code or Codex CLI.

## Workflow

1. Run `scripts/install_integrations.sh`.
2. Verify expected artifacts:
   - `~/.claude/hooks/claude-ai-sec-hook.py`
   - `~/.claude/settings.json` contains `UserPromptSubmit` and `PreToolUse` hook entries.
   - `~/.local/bin/codex-ai-sec`
3. Ensure runtime env vars are set for the user shell.

## Commands

Install both:

```bash
./scripts/install_integrations.sh
```

Install only Claude:

```bash
./scripts/install_integrations.sh --claude-only
```

Install only Codex wrapper:

```bash
./scripts/install_integrations.sh --codex-only
```

## Required runtime env vars

- `AI_SEC_GATEWAY_URL`
- `AI_SEC_BEARER_TOKEN` (or `SERVICE_API_TOKEN`)

Optional:

- `AI_SEC_FAIL_CLOSED=1` (recommended for strict environments)

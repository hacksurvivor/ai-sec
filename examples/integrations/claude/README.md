# Claude Code Integration

Native hook integration for `UserPromptSubmit` and `PreToolUse`.

## Install

```bash
bash ./examples/integrations/claude/install.sh
```

Then export runtime env vars:

```bash
export AI_SEC_GATEWAY_URL="http://127.0.0.1:8080"
export AI_SEC_BEARER_TOKEN="token-analyst"
```

Optional:

```bash
export AI_SEC_FAIL_CLOSED=1
```

## Behavior

- `UserPromptSubmit`: blocks suspicious prompts before submit.
- `PreToolUse`: asks/denies tool execution based on ai-sec gate decision.

## Template

See `examples/integrations/claude/settings.snippet.json`.

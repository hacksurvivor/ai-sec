---
name: ai-sec-security-ops
description: Use when the user asks to operate, validate, or monitor ai-sec (for example: check gateway health, run red-team suite, inspect security events, or validate policy behavior). This skill runs deterministic ai-sec operations via helper scripts.
---

# AI-Sec Security Ops

Use this skill for operator-style security checks and regression runs.

## When to run

- User asks to verify gateway status.
- User asks to run prompt-injection tests.
- User asks to inspect event history or investigate blocked/challenged decisions.

## Workflow

1. Check health with `scripts/health_check.sh`.
2. If requested, run regression tests with `scripts/run_redteam_core.sh`.
3. Inspect recent events with `scripts/list_events.sh`.
4. Summarize results with key failures, risk signals, and next actions.

## Commands

Health:

```bash
./scripts/health_check.sh
```

Red-team core suite:

```bash
./scripts/run_redteam_core.sh mock-model
```

Events:

```bash
./scripts/list_events.sh 20
```

## Environment

- `AI_SEC_GATEWAY_URL` (default: `http://127.0.0.1:8080`)
- `AI_SEC_BEARER_TOKEN` or `SERVICE_API_TOKEN` for authenticated `/v1/*` requests.

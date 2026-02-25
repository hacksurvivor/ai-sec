# OpenClaw Adapter

`@codegrammer/ai-sec-openclaw-adapter` provides an OpenClaw-friendly integration layer for `/v1/agent/gate`.

## Why use it

- Guard prompts and tool calls before execution.
- Keep autonomous behavior by default (`reviewMode: "autonomous"`).
- Optionally enforce human approval (`reviewMode: "human_approval"`).
- Add a local execution firewall to block dangerous tool intents and commands.
- Add canary leak sentinel for silent exfiltration detection.
- Add autonomy budget controls for bounded autonomous operation.
- Add context shield to quarantine suspicious retrieved context chunks.
- Add tamper-evident decision receipt chaining for auditability.

## Install

```bash
npm install @codegrammer/ai-sec-openclaw-adapter
```

## Core behavior

- Gateway `allow` => execute.
- Gateway `block/fail/quarantine` => deny.
- Gateway `review/challenge`:
  - `autonomous` mode (default): continue and mark `reviewBypassed=true`.
  - `human_approval` mode: pause until approved, then re-gate with confirmed tools.
- Execution firewall (`executionFirewall.mode`):
  - `enforce` (default): local block on dangerous command/tool patterns.
  - `audit`: record findings without blocking.
  - `off`: disable local firewall checks.
- Canary sentinel (`canary.mode`):
  - `enforce` (default): block when canary appears in prompt/tool payloads.
  - `audit`: report canary findings without blocking.
  - `off`: disable canary checks.
- Autonomy budget (`autonomyBudget.mode`):
  - `enforce` (default): block autonomous bypass when count/risk limits are exceeded.
  - `audit`: continue but emit exceeded-state signals/reasons.
  - `off`: disable budget checks.
- Context shield (`contextShield.mode`):
  - `enforce` (default): quarantine risky context chunks before gateway call.
  - `audit`: keep all chunks but emit findings/signals.
  - `off`: disable context shielding.
- Decision receipts (`decisionReceipt.enabled`):
  - `true` (default): emit signed-style hash receipts per decision.
  - `chain: true` (default): each receipt references previous hash.
  - `includeInputHashes: true` (default): include prompt/context/tool hashes (not raw content).

## Minimal usage

```ts
import { OpenClawAiSecAdapter } from "@codegrammer/ai-sec-openclaw-adapter";

const guard = new OpenClawAiSecAdapter({
  baseUrl: "http://127.0.0.1:8080",
  token: process.env.AI_SEC_BEARER_TOKEN,
  reviewMode: "autonomous",
  executionFirewall: {
    mode: "enforce"
  },
  canary: {
    mode: "enforce"
  },
  autonomyBudget: {
    mode: "enforce",
    maxReviewBypass: 5,
    maxCumulativeRisk: 220,
    maxSingleBypassRisk: 74,
    windowMs: 10 * 60 * 1000
  },
  contextShield: {
    mode: "enforce"
  },
  decisionReceipt: {
    enabled: true,
    chain: true,
    includeInputHashes: true
  }
});

const decision = await guard.gate({
  prompt: userPrompt,
  tools: [toolName],
  toolExecutions: [{ tool: toolName, input: toolInput }]
});

if (!decision.allowed) {
  throw new Error(`ai-sec denied: ${decision.gatewayDecision}`);
}
```

## Canary usage

```ts
const canaryToken = guard.getPrimaryCanaryToken();
// Place canaryToken in hidden system context/tool memory for your OpenClaw planner.
// If this token leaks into a prompt or tool input, ai-sec will block in enforce mode.
```

## Autonomy budget visibility

Each gate result includes:
- `autonomyBudgetExceeded`
- `autonomyBudgetReasons`
- `autonomyBudgetSnapshot`

Use these to surface operator alerts before the adapter hard-blocks in `enforce` mode.

## Context shield visibility

Each gate result includes:
- `contextShieldMode`
- `contextShieldQuarantinedChunks`
- `contextShieldFindings`

Use these to monitor and tune indirect prompt-injection handling for retrieved external context.

## Decision receipts

Each gate result may include `decisionReceipt` with:
- `receiptHash`
- `previousReceiptHash` (when chaining is enabled)
- `promptHash`, `contextHash`, `requestedToolsHash`, `toolExecutionsHash` (when enabled)

Use this for tamper-evident auditing and SOC pipeline ingestion.

## Firewall customization

```ts
const guard = new OpenClawAiSecAdapter({
  baseUrl: "http://127.0.0.1:8080",
  reviewMode: "autonomous",
  executionFirewall: {
    mode: "enforce",
    blockedTools: ["spawn_agent"],
    rules: [
      {
        id: "terminal.no_chmod_777_root",
        tool: "terminal.exec",
        pattern: "(?:^|\\s)chmod\\s+-R\\s+777\\s+/(?:\\s|$)",
        reason: "Root-wide chmod 777 is not allowed"
      }
    ]
  }
});
```

## Optional human approval flow

```ts
const guard = new OpenClawAiSecAdapter({
  baseUrl: "http://127.0.0.1:8080",
  token: process.env.AI_SEC_BEARER_TOKEN,
  reviewMode: "human_approval"
});

const decision = await guard.gate(
  { prompt: userPrompt, tools: [toolName] },
  async (review) => {
    const approved = await askUserForApproval(review);
    return {
      approved,
      confirmedTools: approved ? [toolName] : []
    };
  }
);
```

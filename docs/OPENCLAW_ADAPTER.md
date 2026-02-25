# OpenClaw Adapter

`@codegrammer/ai-sec-openclaw-adapter` provides an OpenClaw-friendly integration layer for `/v1/agent/gate`.

## Why use it

- Guard prompts and tool calls before execution.
- Keep autonomous behavior by default (`reviewMode: "autonomous"`).
- Optionally enforce human approval (`reviewMode: "human_approval"`).

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

## Minimal usage

```ts
import { OpenClawAiSecAdapter } from "@codegrammer/ai-sec-openclaw-adapter";

const guard = new OpenClawAiSecAdapter({
  baseUrl: "http://127.0.0.1:8080",
  token: process.env.AI_SEC_BEARER_TOKEN,
  reviewMode: "autonomous"
});

const decision = await guard.gate({
  prompt: userPrompt,
  tools: [toolName]
});

if (!decision.allowed) {
  throw new Error(`ai-sec denied: ${decision.gatewayDecision}`);
}
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

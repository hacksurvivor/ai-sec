import { OpenClawAiSecAdapter } from "@codegrammer/ai-sec-openclaw-adapter";

const guard = new OpenClawAiSecAdapter({
  baseUrl: process.env.AI_SEC_GATEWAY_URL ?? "http://127.0.0.1:8080",
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

const canaryToken = guard.getPrimaryCanaryToken();

export function getOpenClawCanaryToken(): string | undefined {
  return canaryToken;
}

export async function runOpenClawStep(params: {
  prompt: string;
  toolName: string;
  toolInput?: unknown;
  executeTool: () => Promise<unknown>;
}): Promise<unknown> {
  const decision = await guard.gate({
    prompt: params.prompt,
    tools: [params.toolName],
    toolExecutions: [{ tool: params.toolName, input: params.toolInput }]
  });

  if (!decision.allowed) {
    throw new Error(
      `ai-sec denied (status=${decision.effectiveStatus}, decision=${decision.gatewayDecision}, risk=${decision.riskScore})`
    );
  }

  return params.executeTool();
}

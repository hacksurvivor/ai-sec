import { OpenClawAiSecAdapter } from "@codegrammer/ai-sec-openclaw-adapter";

const guard = new OpenClawAiSecAdapter({
  baseUrl: process.env.AI_SEC_GATEWAY_URL ?? "http://127.0.0.1:8080",
  token: process.env.AI_SEC_BEARER_TOKEN,
  reviewMode: "autonomous"
});

export async function runOpenClawStep(params: {
  prompt: string;
  toolName: string;
  executeTool: () => Promise<unknown>;
}): Promise<unknown> {
  const decision = await guard.gate({
    prompt: params.prompt,
    tools: [params.toolName]
  });

  if (!decision.allowed) {
    throw new Error(
      `ai-sec denied (status=${decision.effectiveStatus}, decision=${decision.gatewayDecision}, risk=${decision.riskScore})`
    );
  }

  return params.executeTool();
}

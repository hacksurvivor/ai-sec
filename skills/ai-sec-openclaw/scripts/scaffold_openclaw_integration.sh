#!/usr/bin/env bash
set -euo pipefail

review_mode="autonomous"
target_dir=""
output_file_name="openclaw-ai-sec-guard.ts"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      target_dir="${2:-}"
      shift 2
      ;;
    --review-mode)
      review_mode="${2:-}"
      shift 2
      ;;
    --output)
      output_file_name="${2:-}"
      shift 2
      ;;
    --help|-h)
      cat <<'USAGE'
Usage:
  scaffold_openclaw_integration.sh --target <dir> [--review-mode autonomous|human_approval] [--output <file.ts>]
USAGE
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$target_dir" ]]; then
  echo "--target is required" >&2
  exit 1
fi

if [[ "$review_mode" != "autonomous" && "$review_mode" != "human_approval" ]]; then
  echo "--review-mode must be autonomous or human_approval" >&2
  exit 1
fi

mkdir -p "$target_dir"
out_file="${target_dir%/}/${output_file_name}"

if [[ "$review_mode" == "autonomous" ]]; then
  cat > "$out_file" <<'TS'
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

export const OPENCLAW_CANARY_TOKEN = guard.getPrimaryCanaryToken();

export async function guardOpenClawTool(params: {
  prompt: string;
  toolName: string;
  toolInput?: unknown;
  execute: () => Promise<unknown>;
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

  return params.execute();
}
TS
else
  cat > "$out_file" <<'TS'
import { OpenClawAiSecAdapter, type AiSecReviewRequest } from "@codegrammer/ai-sec-openclaw-adapter";

const guard = new OpenClawAiSecAdapter({
  baseUrl: process.env.AI_SEC_GATEWAY_URL ?? "http://127.0.0.1:8080",
  token: process.env.AI_SEC_BEARER_TOKEN,
  reviewMode: "human_approval",
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

export const OPENCLAW_CANARY_TOKEN = guard.getPrimaryCanaryToken();

async function askUserApproval(_review: AiSecReviewRequest): Promise<boolean> {
  // TODO: wire this to your OpenClaw approval UX/channel.
  return false;
}

export async function guardOpenClawTool(params: {
  prompt: string;
  toolName: string;
  toolInput?: unknown;
  execute: () => Promise<unknown>;
}): Promise<unknown> {
  const decision = await guard.gate(
    {
      prompt: params.prompt,
      tools: [params.toolName],
      toolExecutions: [{ tool: params.toolName, input: params.toolInput }]
    },
    async (review) => {
      const approved = await askUserApproval(review);
      return {
        approved,
        confirmedTools: approved ? [params.toolName] : []
      };
    }
  );

  if (!decision.allowed) {
    throw new Error(
      `ai-sec denied (status=${decision.effectiveStatus}, decision=${decision.gatewayDecision}, risk=${decision.riskScore})`
    );
  }

  return params.execute();
}
TS
fi

echo "Created ${out_file}"
echo "Next: wrap sensitive OpenClaw tool execution paths with guardOpenClawTool(...)"

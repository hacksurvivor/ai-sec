import { randomUUID } from "node:crypto";

export type AiSecDecisionClass = "allow" | "review" | "block";
export type AiSecEffectiveStatus = "allow" | "review" | "block" | "error";
export type AiSecReviewMode = "autonomous" | "human_approval";
export type AiSecTrustLevel = "internal" | "partner" | "external" | "unknown";

export interface AiSecContextChunk {
  content: string;
  sourceId?: string;
  source_id?: string;
  trust?: AiSecTrustLevel;
}

export interface AiSecGateInput {
  prompt: string;
  tools?: string[];
  confirmedTools?: string[];
  context?: AiSecContextChunk[];
  metadata?: Record<string, string>;
}

export interface AiSecGatewayResponse {
  decision: string;
  risk_score: number;
  signals: string[];
  blocked_tools: string[];
  challenge_required: boolean;
  event_id: string;
}

export interface AiSecReviewRequest {
  prompt: string;
  requestedTools: string[];
  suggestedBlockedTools: string[];
  riskScore: number;
  signals: string[];
  gatewayDecision: string;
  eventId: string;
}

export interface AiSecReviewResponse {
  approved: boolean;
  confirmedTools?: string[];
}

export type AiSecReviewHandler = (
  request: AiSecReviewRequest
) => Promise<AiSecReviewResponse> | AiSecReviewResponse;

export interface AiSecGuardResult {
  gatewayDecision: string;
  gatewayStatus: AiSecDecisionClass;
  effectiveStatus: AiSecEffectiveStatus;
  allowed: boolean;
  reviewBypassed: boolean;
  requiresHumanApproval: boolean;
  exitCode: 0 | 1 | 20 | 30;
  riskScore: number;
  signals: string[];
  blockedTools: string[];
  challengeRequired: boolean;
  eventId: string;
}

export interface OpenClawAiSecConfig {
  baseUrl?: string;
  token?: string;
  sessionId?: string;
  userId?: string;
  reviewMode?: AiSecReviewMode;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  toolAliases?: Record<string, string>;
  metadata?: Record<string, string>;
}

interface GatewayContextChunk {
  source_id: string;
  trust: AiSecTrustLevel;
  content: string;
}

interface GatewayRequestPayload {
  session_id: string;
  user_id: string;
  prompt: string;
  context: GatewayContextChunk[];
  requested_tools: string[];
  user_confirmed_tools: string[];
  metadata?: Record<string, string>;
}

export class AiSecTransportError extends Error {
  constructor(message: string, public readonly status?: number, public readonly payload?: unknown) {
    super(message);
    this.name = "AiSecTransportError";
  }
}

export class AiSecDeniedError extends Error {
  constructor(message: string, public readonly result: AiSecGuardResult) {
    super(message);
    this.name = "AiSecDeniedError";
  }
}

const DEFAULT_TOOL_ALIASES: Record<string, string> = {
  bash: "terminal.exec",
  shell: "terminal.exec",
  terminal: "terminal.exec",
  "terminal.exec": "terminal.exec",
  write: "write_file",
  edit: "write_file",
  file_write: "write_file",
  "fs.write": "write_file",
  "write_file": "write_file",
  task: "spawn_agent",
  spawn_agent: "spawn_agent",
  agent: "spawn_agent",
  web_fetch: "web.fetch",
  fetch: "web.fetch",
  "web.fetch": "web.fetch",
  web_search: "web.search",
  search: "web.search",
  "web.search": "web.search"
};

function normalizeBaseUrl(value: string): string {
  return value.trim().replace(/\/+$/, "");
}

function classifyDecision(decision: string): AiSecDecisionClass {
  if (["block", "fail", "quarantine"].includes(decision)) {
    return "block";
  }

  if (["challenge", "human_review"].includes(decision)) {
    return "review";
  }

  return "allow";
}

function dedupe(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.trim().length > 0))];
}

function normalizeTool(tool: string, aliases: Record<string, string>): string {
  const trimmed = tool.trim();
  if (!trimmed) {
    return "";
  }

  const exact = aliases[trimmed];
  if (exact) {
    return exact;
  }

  const lower = aliases[trimmed.toLowerCase()];
  return lower ?? trimmed;
}

function toGatewayContext(context: AiSecContextChunk[]): GatewayContextChunk[] {
  return context
    .filter((chunk) => chunk.content.trim().length > 0)
    .map((chunk, index) => ({
      source_id: chunk.source_id?.trim() || chunk.sourceId?.trim() || `openclaw_ctx_${index + 1}`,
      trust: chunk.trust ?? "unknown",
      content: chunk.content
    }));
}

function mergeMetadata(
  base: Record<string, string> | undefined,
  incoming: Record<string, string> | undefined
): Record<string, string> | undefined {
  if (!base && !incoming) {
    return undefined;
  }

  return {
    ...(base ?? {}),
    ...(incoming ?? {})
  };
}

export class OpenClawAiSecAdapter {
  private readonly baseUrl: string;
  private readonly token?: string;
  private readonly sessionId: string;
  private readonly userId: string;
  private readonly reviewMode: AiSecReviewMode;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly toolAliases: Record<string, string>;
  private readonly metadata?: Record<string, string>;

  constructor(config: OpenClawAiSecConfig = {}) {
    this.baseUrl = normalizeBaseUrl(config.baseUrl ?? "http://127.0.0.1:8080");
    this.token = config.token;
    this.sessionId = config.sessionId ?? `sess_openclaw_${randomUUID().slice(0, 8)}`;
    this.userId = config.userId ?? "openclaw_agent";
    this.reviewMode = config.reviewMode ?? "autonomous";
    this.timeoutMs = config.timeoutMs ?? 10_000;
    this.fetchImpl = config.fetchImpl ?? fetch;
    this.toolAliases = {
      ...DEFAULT_TOOL_ALIASES,
      ...(config.toolAliases ?? {})
    };
    this.metadata = config.metadata;
  }

  async gate(input: AiSecGateInput, reviewHandler?: AiSecReviewHandler): Promise<AiSecGuardResult> {
    const first = await this.gateOnce(input, input.confirmedTools ?? []);

    if (first.gatewayStatus === "allow" || first.gatewayStatus === "block") {
      return first;
    }

    if (this.reviewMode === "autonomous") {
      return {
        ...first,
        effectiveStatus: "allow",
        allowed: true,
        reviewBypassed: true,
        requiresHumanApproval: false,
        exitCode: 0
      };
    }

    if (!reviewHandler) {
      return first;
    }

    const approval = await reviewHandler({
      prompt: input.prompt,
      requestedTools: first.blockedTools.length > 0 ? first.blockedTools : this.normalizeTools(input.tools ?? []),
      suggestedBlockedTools: first.blockedTools,
      riskScore: first.riskScore,
      signals: first.signals,
      gatewayDecision: first.gatewayDecision,
      eventId: first.eventId
    });

    if (!approval.approved) {
      return first;
    }

    const requestedTools = this.normalizeTools(input.tools ?? []);
    const approvedTools = this.normalizeTools(approval.confirmedTools ?? []);
    const confirmedTools = dedupe([
      ...this.normalizeTools(input.confirmedTools ?? []),
      ...approvedTools,
      ...requestedTools
    ]);

    return this.gateOnce(input, confirmedTools);
  }

  async assertAllowed(input: AiSecGateInput, reviewHandler?: AiSecReviewHandler): Promise<AiSecGuardResult> {
    const result = await this.gate(input, reviewHandler);
    if (!result.allowed) {
      throw new AiSecDeniedError(
        `ai-sec denied execution (${result.effectiveStatus}, decision=${result.gatewayDecision}, risk=${result.riskScore})`,
        result
      );
    }

    return result;
  }

  private normalizeTools(tools: string[]): string[] {
    return dedupe(tools.map((tool) => normalizeTool(tool, this.toolAliases)).filter((tool) => tool.length > 0));
  }

  private async gateOnce(input: AiSecGateInput, confirmedTools: string[]): Promise<AiSecGuardResult> {
    const prompt = input.prompt.trim();
    if (!prompt) {
      throw new AiSecTransportError("Prompt is required");
    }

    const payload: GatewayRequestPayload = {
      session_id: this.sessionId,
      user_id: this.userId,
      prompt,
      context: toGatewayContext(input.context ?? []),
      requested_tools: this.normalizeTools(input.tools ?? []),
      user_confirmed_tools: this.normalizeTools(confirmedTools),
      metadata: mergeMetadata(this.metadata, input.metadata)
    };

    const response = await this.callGateway(payload);
    const gatewayStatus = classifyDecision(response.decision);
    const effectiveStatus: AiSecEffectiveStatus = gatewayStatus;

    return {
      gatewayDecision: response.decision,
      gatewayStatus,
      effectiveStatus,
      allowed: effectiveStatus === "allow",
      reviewBypassed: false,
      requiresHumanApproval: effectiveStatus === "review",
      exitCode: effectiveStatus === "allow" ? 0 : effectiveStatus === "review" ? 20 : 30,
      riskScore: response.risk_score,
      signals: response.signals,
      blockedTools: response.blocked_tools,
      challengeRequired: response.challenge_required,
      eventId: response.event_id
    };
  }

  private async callGateway(payload: GatewayRequestPayload): Promise<AiSecGatewayResponse> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchImpl(`${this.baseUrl}/v1/agent/gate`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(this.token ? { authorization: `Bearer ${this.token}` } : {})
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });

      const text = await response.text();
      const decoded: unknown = text.length > 0 ? JSON.parse(text) : {};

      if (!response.ok) {
        throw new AiSecTransportError(`Gateway request failed with status ${response.status}`, response.status, decoded);
      }

      const parsed = decoded as Partial<AiSecGatewayResponse>;
      if (
        typeof parsed.decision !== "string" ||
        typeof parsed.risk_score !== "number" ||
        !Array.isArray(parsed.signals) ||
        !Array.isArray(parsed.blocked_tools) ||
        typeof parsed.challenge_required !== "boolean" ||
        typeof parsed.event_id !== "string"
      ) {
        throw new AiSecTransportError("Gateway response is missing required fields", response.status, decoded);
      }

      return {
        decision: parsed.decision,
        risk_score: parsed.risk_score,
        signals: parsed.signals,
        blocked_tools: parsed.blocked_tools,
        challenge_required: parsed.challenge_required,
        event_id: parsed.event_id
      };
    } catch (error) {
      if (error instanceof AiSecTransportError) {
        throw error;
      }

      const message = error instanceof Error ? error.message : String(error);
      throw new AiSecTransportError(`Gateway transport error: ${message}`);
    } finally {
      clearTimeout(timeout);
    }
  }
}

export function createOpenClawAiSecAdapter(config: OpenClawAiSecConfig = {}): OpenClawAiSecAdapter {
  return new OpenClawAiSecAdapter(config);
}

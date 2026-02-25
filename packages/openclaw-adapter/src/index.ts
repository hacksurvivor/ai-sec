import { createHash, randomUUID } from "node:crypto";

export type AiSecDecisionClass = "allow" | "review" | "block";
export type AiSecEffectiveStatus = "allow" | "review" | "block" | "error";
export type AiSecReviewMode = "autonomous" | "human_approval";
export type AiSecTrustLevel = "internal" | "partner" | "external" | "unknown";
export type AiSecFirewallMode = "off" | "audit" | "enforce";
export type AiSecCanaryMode = "off" | "audit" | "enforce";
export type AiSecAutonomyBudgetMode = "off" | "audit" | "enforce";
export type AiSecContextShieldMode = "off" | "audit" | "enforce";

export interface AiSecContextChunk {
  content: string;
  sourceId?: string;
  source_id?: string;
  trust?: AiSecTrustLevel;
}

export interface AiSecToolExecution {
  tool: string;
  input?: unknown;
}

export interface AiSecGateInput {
  prompt: string;
  tools?: string[];
  confirmedTools?: string[];
  toolExecutions?: AiSecToolExecution[];
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
  firewallMode: AiSecFirewallMode;
  firewallBlocked: boolean;
  firewallFindings: AiSecFirewallFinding[];
  canaryMode: AiSecCanaryMode;
  canaryDetected: boolean;
  canaryFindings: AiSecCanaryFinding[];
  autonomyBudgetMode: AiSecAutonomyBudgetMode;
  autonomyBudgetExceeded: boolean;
  autonomyBudgetReasons: string[];
  autonomyBudgetSnapshot: AiSecAutonomyBudgetSnapshot;
  contextShieldMode: AiSecContextShieldMode;
  contextShieldQuarantinedChunks: number;
  contextShieldFindings: AiSecContextShieldFinding[];
  decisionReceipt?: AiSecDecisionReceipt;
}

export interface AiSecFirewallRule {
  id: string;
  tool?: string;
  pattern: string | RegExp;
  flags?: string;
  reason: string;
}

export interface AiSecExecutionFirewallConfig {
  mode?: AiSecFirewallMode;
  blockedTools?: string[];
  rules?: AiSecFirewallRule[];
  includeDefaultRules?: boolean;
}

export interface AiSecFirewallFinding {
  id: string;
  reason: string;
  tool?: string;
  match?: string;
}

export interface AiSecCanaryConfig {
  mode?: AiSecCanaryMode;
  sessionCanary?: boolean;
  tokens?: string[];
}

export interface AiSecCanaryFinding {
  token: string;
  source: "prompt" | "tool_input";
  tool?: string;
}

export interface AiSecAutonomyBudgetConfig {
  mode?: AiSecAutonomyBudgetMode;
  maxReviewBypass?: number;
  maxCumulativeRisk?: number;
  maxSingleBypassRisk?: number;
  windowMs?: number;
}

export interface AiSecAutonomyBudgetSnapshot {
  windowStartedAtMs: number;
  windowEndsAtMs: number;
  reviewBypassCount: number;
  cumulativeBypassRisk: number;
  maxReviewBypass: number;
  maxCumulativeRisk: number;
  maxSingleBypassRisk: number;
}

export interface AiSecContextShieldRule {
  id: string;
  pattern: string | RegExp;
  flags?: string;
  reason: string;
  trust?: AiSecTrustLevel[];
}

export interface AiSecContextShieldConfig {
  mode?: AiSecContextShieldMode;
  quarantineTrust?: AiSecTrustLevel[];
  rules?: AiSecContextShieldRule[];
  includeDefaultRules?: boolean;
}

export interface AiSecContextShieldFinding {
  id: string;
  sourceId: string;
  trust: AiSecTrustLevel;
  reason: string;
  match?: string;
}

export interface AiSecDecisionReceiptConfig {
  enabled?: boolean;
  chain?: boolean;
  includeInputHashes?: boolean;
}

export interface AiSecDecisionReceipt {
  receiptId: string;
  createdAtMs: number;
  sessionId: string;
  userId: string;
  eventId: string;
  gatewayDecision: string;
  effectiveStatus: AiSecEffectiveStatus;
  riskScore: number;
  blockedTools: string[];
  signals: string[];
  promptHash?: string;
  contextHash?: string;
  requestedToolsHash?: string;
  toolExecutionsHash?: string;
  previousReceiptHash?: string;
  receiptHash: string;
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
  executionFirewall?: AiSecExecutionFirewallConfig;
  canary?: AiSecCanaryConfig;
  autonomyBudget?: AiSecAutonomyBudgetConfig;
  contextShield?: AiSecContextShieldConfig;
  decisionReceipt?: AiSecDecisionReceiptConfig;
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

export class AiSecConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AiSecConfigError";
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

const DEFAULT_EXECUTION_FIREWALL_RULES: readonly AiSecFirewallRule[] = [
  {
    id: "terminal.pipe_shell_remote",
    tool: "terminal.exec",
    pattern: "(?:curl|wget)\\s+[^\\n|]+\\|\\s*(?:sh|bash|zsh)\\b",
    flags: "i",
    reason: "Remote script is piped directly into a shell"
  },
  {
    id: "terminal.rm_rf_root",
    tool: "terminal.exec",
    pattern: "(?:^|\\s)rm\\s+-rf\\s+/(?:\\s|$)",
    flags: "i",
    reason: "Destructive root deletion command"
  },
  {
    id: "terminal.fork_bomb",
    tool: "terminal.exec",
    pattern: ":\\(\\)\\s*\\{\\s*:\\|:&\\s*\\};\\s*:",
    flags: "i",
    reason: "Fork bomb pattern"
  },
  {
    id: "terminal.raw_disk_write",
    tool: "terminal.exec",
    pattern: "\\bdd\\s+if=.*\\s+of=/dev/(?:sd[a-z]|nvme\\d+n\\d+)",
    flags: "i",
    reason: "Raw disk write command"
  }
];

const DEFAULT_CONTEXT_SHIELD_RULES: readonly AiSecContextShieldRule[] = [
  {
    id: "indirect_override",
    pattern: "\\bignore\\s+(?:all\\s+)?(?:previous|prior)\\s+instructions\\b",
    flags: "i",
    reason: "Indirect override instruction pattern"
  },
  {
    id: "hidden_instruction",
    pattern: "\\b(do\\s+not\\s+tell\\s+the\\s+user|hidden\\s+instruction|secret\\s+system\\s+prompt)\\b",
    flags: "i",
    reason: "Hidden instruction marker"
  },
  {
    id: "credential_exfil",
    pattern: "\\b(exfiltrate|send\\s+to\\s+attacker|reveal\\s+(?:secrets?|credentials?|tokens?))\\b",
    flags: "i",
    reason: "Credential/data exfiltration language"
  }
];

interface NormalizedFirewallRule {
  id: string;
  tool?: string;
  pattern: RegExp;
  reason: string;
}

interface NormalizedContextShieldRule {
  id: string;
  pattern: RegExp;
  reason: string;
  trust?: Set<AiSecTrustLevel>;
}

interface NormalizedContextChunk {
  source_id: string;
  trust: AiSecTrustLevel;
  content: string;
}

interface AiSecAutonomyBudgetLimits {
  maxReviewBypass: number;
  maxCumulativeRisk: number;
  maxSingleBypassRisk: number;
  windowMs: number;
}

interface AiSecAutonomyBudgetState {
  windowStartedAtMs: number;
  reviewBypassCount: number;
  cumulativeBypassRisk: number;
}

const DEFAULT_AUTONOMY_BUDGET_LIMITS: AiSecAutonomyBudgetLimits = {
  maxReviewBypass: 5,
  maxCumulativeRisk: 220,
  maxSingleBypassRisk: 74,
  windowMs: 10 * 60 * 1000
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

function normalizeContextChunks(context: AiSecContextChunk[]): NormalizedContextChunk[] {
  return context
    .filter((chunk) => chunk.content.trim().length > 0)
    .map((chunk, index) => ({
      source_id: chunk.source_id?.trim() || chunk.sourceId?.trim() || `openclaw_ctx_${index + 1}`,
      trust: chunk.trust ?? "unknown",
      content: chunk.content
    }));
}

function toGatewayContext(context: NormalizedContextChunk[]): GatewayContextChunk[] {
  return context.map((chunk) => ({
    source_id: chunk.source_id,
    trust: chunk.trust,
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

function hashJson(value: unknown): string {
  const json = JSON.stringify(value);
  return createHash("sha256").update(json, "utf8").digest("hex");
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
  private readonly firewallMode: AiSecFirewallMode;
  private readonly firewallBlockedTools: Set<string>;
  private readonly firewallRules: NormalizedFirewallRule[];
  private readonly canaryMode: AiSecCanaryMode;
  private readonly canaryTokens: string[];
  private readonly autonomyBudgetMode: AiSecAutonomyBudgetMode;
  private readonly autonomyBudgetLimits: AiSecAutonomyBudgetLimits;
  private autonomyBudgetState: AiSecAutonomyBudgetState;
  private readonly contextShieldMode: AiSecContextShieldMode;
  private readonly contextShieldQuarantineTrust: Set<AiSecTrustLevel>;
  private readonly contextShieldRules: NormalizedContextShieldRule[];
  private readonly decisionReceiptEnabled: boolean;
  private readonly decisionReceiptChain: boolean;
  private readonly decisionReceiptIncludeInputHashes: boolean;
  private previousReceiptHash?: string;

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

    const firewall = config.executionFirewall;
    this.firewallMode = firewall?.mode ?? "enforce";
    if (!["off", "audit", "enforce"].includes(this.firewallMode)) {
      throw new AiSecConfigError(`Invalid execution firewall mode: ${String(firewall?.mode)}`);
    }

    this.firewallBlockedTools = new Set(this.normalizeTools(firewall?.blockedTools ?? []));
    const includeDefaultRules = firewall?.includeDefaultRules ?? true;
    this.firewallRules = this.normalizeFirewallRules([
      ...(includeDefaultRules ? DEFAULT_EXECUTION_FIREWALL_RULES : []),
      ...(firewall?.rules ?? [])
    ]);

    const canary = config.canary;
    this.canaryMode = canary?.mode ?? "enforce";
    if (!["off", "audit", "enforce"].includes(this.canaryMode)) {
      throw new AiSecConfigError(`Invalid canary mode: ${String(canary?.mode)}`);
    }

    const builtInCanary =
      canary?.sessionCanary === false ? [] : [`__AISEC_CANARY_${randomUUID().replace(/-/g, "").slice(0, 16)}__`];
    this.canaryTokens = dedupe([
      ...builtInCanary,
      ...(canary?.tokens ?? []).map((token) => token.trim()).filter((token) => token.length >= 8)
    ]);

    const autonomy = config.autonomyBudget;
    this.autonomyBudgetMode = autonomy?.mode ?? "enforce";
    if (!["off", "audit", "enforce"].includes(this.autonomyBudgetMode)) {
      throw new AiSecConfigError(`Invalid autonomy budget mode: ${String(autonomy?.mode)}`);
    }

    const maxReviewBypass = autonomy?.maxReviewBypass ?? DEFAULT_AUTONOMY_BUDGET_LIMITS.maxReviewBypass;
    if (!Number.isInteger(maxReviewBypass) || maxReviewBypass < 1) {
      throw new AiSecConfigError("autonomyBudget.maxReviewBypass must be an integer >= 1");
    }

    const maxCumulativeRisk = autonomy?.maxCumulativeRisk ?? DEFAULT_AUTONOMY_BUDGET_LIMITS.maxCumulativeRisk;
    if (typeof maxCumulativeRisk !== "number" || !Number.isFinite(maxCumulativeRisk) || maxCumulativeRisk < 1) {
      throw new AiSecConfigError("autonomyBudget.maxCumulativeRisk must be a number >= 1");
    }

    const maxSingleBypassRisk = autonomy?.maxSingleBypassRisk ?? DEFAULT_AUTONOMY_BUDGET_LIMITS.maxSingleBypassRisk;
    if (typeof maxSingleBypassRisk !== "number" || !Number.isFinite(maxSingleBypassRisk) || maxSingleBypassRisk < 1) {
      throw new AiSecConfigError("autonomyBudget.maxSingleBypassRisk must be a number >= 1");
    }

    const windowMs = autonomy?.windowMs ?? DEFAULT_AUTONOMY_BUDGET_LIMITS.windowMs;
    if (!Number.isInteger(windowMs) || windowMs < 1_000) {
      throw new AiSecConfigError("autonomyBudget.windowMs must be an integer >= 1000");
    }

    this.autonomyBudgetLimits = {
      maxReviewBypass,
      maxCumulativeRisk,
      maxSingleBypassRisk,
      windowMs
    };
    this.autonomyBudgetState = {
      windowStartedAtMs: Date.now(),
      reviewBypassCount: 0,
      cumulativeBypassRisk: 0
    };

    const contextShield = config.contextShield;
    this.contextShieldMode = contextShield?.mode ?? "enforce";
    if (!["off", "audit", "enforce"].includes(this.contextShieldMode)) {
      throw new AiSecConfigError(`Invalid context shield mode: ${String(contextShield?.mode)}`);
    }

    const quarantineTrust = contextShield?.quarantineTrust ?? ["external", "unknown"];
    this.contextShieldQuarantineTrust = new Set(
      quarantineTrust.filter((trust): trust is AiSecTrustLevel =>
        ["internal", "partner", "external", "unknown"].includes(trust)
      )
    );

    if (this.contextShieldQuarantineTrust.size === 0) {
      throw new AiSecConfigError("contextShield.quarantineTrust must include at least one valid trust level");
    }

    const includeDefaultContextRules = contextShield?.includeDefaultRules ?? true;
    this.contextShieldRules = this.normalizeContextShieldRules([
      ...(includeDefaultContextRules ? DEFAULT_CONTEXT_SHIELD_RULES : []),
      ...(contextShield?.rules ?? [])
    ]);

    const decisionReceipt = config.decisionReceipt;
    this.decisionReceiptEnabled = decisionReceipt?.enabled ?? true;
    this.decisionReceiptChain = decisionReceipt?.chain ?? true;
    this.decisionReceiptIncludeInputHashes = decisionReceipt?.includeInputHashes ?? true;
  }

  async gate(input: AiSecGateInput, reviewHandler?: AiSecReviewHandler): Promise<AiSecGuardResult> {
    this.refreshAutonomyBudgetWindow(Date.now());
    const first = await this.gateOnce(input, input.confirmedTools ?? []);

    if (first.effectiveStatus === "block" || first.gatewayStatus === "allow" || first.gatewayStatus === "block") {
      return this.withDecisionReceipt(first, input);
    }

    if (this.reviewMode === "autonomous") {
      const bypassed = this.applyAutonomyBudget({
        ...first,
        effectiveStatus: "allow",
        allowed: true,
        reviewBypassed: true,
        requiresHumanApproval: false,
        exitCode: 0
      });
      return this.withDecisionReceipt(bypassed, input);
    }

    if (!reviewHandler) {
      return this.withDecisionReceipt(first, input);
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
      return this.withDecisionReceipt(first, input);
    }

    const requestedTools = this.normalizeTools(input.tools ?? []);
    const approvedTools = this.normalizeTools(approval.confirmedTools ?? []);
    const confirmedTools = dedupe([
      ...this.normalizeTools(input.confirmedTools ?? []),
      ...approvedTools,
      ...requestedTools
    ]);

    const second = await this.gateOnce(input, confirmedTools);
    return this.withDecisionReceipt(second, input);
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

  getCanaryTokens(): string[] {
    return [...this.canaryTokens];
  }

  getPrimaryCanaryToken(): string | undefined {
    return this.canaryTokens[0];
  }

  getAutonomyBudgetSnapshot(): AiSecAutonomyBudgetSnapshot {
    const now = Date.now();
    this.refreshAutonomyBudgetWindow(now);
    return this.createAutonomyBudgetSnapshot(this.autonomyBudgetState);
  }

  private withDecisionReceipt(result: AiSecGuardResult, input: AiSecGateInput): AiSecGuardResult {
    if (!this.decisionReceiptEnabled) {
      return result;
    }

    const normalizedContext = normalizeContextChunks(input.context ?? []);
    const normalizedTools = this.normalizeTools(input.tools ?? []);
    const normalizedToolExecutions = this.normalizeToolExecutions(input.toolExecutions);
    const previousReceiptHash = this.decisionReceiptChain ? this.previousReceiptHash : undefined;

    const receiptBase: Omit<AiSecDecisionReceipt, "receiptHash"> = {
      receiptId: `rcpt_${randomUUID().slice(0, 8)}`,
      createdAtMs: Date.now(),
      sessionId: this.sessionId,
      userId: this.userId,
      eventId: result.eventId,
      gatewayDecision: result.gatewayDecision,
      effectiveStatus: result.effectiveStatus,
      riskScore: result.riskScore,
      blockedTools: [...result.blockedTools],
      signals: [...result.signals],
      ...(this.decisionReceiptIncludeInputHashes
        ? {
            promptHash: hashJson(input.prompt),
            contextHash: hashJson(
              normalizedContext.map((chunk) => ({
                source_id: chunk.source_id,
                trust: chunk.trust,
                contentHash: hashJson(chunk.content)
              }))
            ),
            requestedToolsHash: hashJson(normalizedTools),
            toolExecutionsHash: hashJson(
              normalizedToolExecutions.map((execution) => ({
                tool: execution.tool,
                inputHash: hashJson(execution.input)
              }))
            )
          }
        : {}),
      ...(previousReceiptHash ? { previousReceiptHash } : {})
    };

    const receiptHash = hashJson(receiptBase);
    const receipt: AiSecDecisionReceipt = {
      ...receiptBase,
      receiptHash
    };

    if (this.decisionReceiptChain) {
      this.previousReceiptHash = receiptHash;
    }

    return {
      ...result,
      decisionReceipt: receipt
    };
  }

  private refreshAutonomyBudgetWindow(nowMs: number): void {
    const expiresAtMs = this.autonomyBudgetState.windowStartedAtMs + this.autonomyBudgetLimits.windowMs;
    if (nowMs < expiresAtMs) {
      return;
    }

    this.autonomyBudgetState = {
      windowStartedAtMs: nowMs,
      reviewBypassCount: 0,
      cumulativeBypassRisk: 0
    };
  }

  private createAutonomyBudgetSnapshot(state: AiSecAutonomyBudgetState): AiSecAutonomyBudgetSnapshot {
    return {
      windowStartedAtMs: state.windowStartedAtMs,
      windowEndsAtMs: state.windowStartedAtMs + this.autonomyBudgetLimits.windowMs,
      reviewBypassCount: state.reviewBypassCount,
      cumulativeBypassRisk: state.cumulativeBypassRisk,
      maxReviewBypass: this.autonomyBudgetLimits.maxReviewBypass,
      maxCumulativeRisk: this.autonomyBudgetLimits.maxCumulativeRisk,
      maxSingleBypassRisk: this.autonomyBudgetLimits.maxSingleBypassRisk
    };
  }

  private applyAutonomyBudget(result: AiSecGuardResult): AiSecGuardResult {
    const now = Date.now();
    this.refreshAutonomyBudgetWindow(now);

    if (this.autonomyBudgetMode === "off") {
      return {
        ...result,
        autonomyBudgetMode: this.autonomyBudgetMode,
        autonomyBudgetExceeded: false,
        autonomyBudgetReasons: [],
        autonomyBudgetSnapshot: this.createAutonomyBudgetSnapshot(this.autonomyBudgetState)
      };
    }

    const projectedState: AiSecAutonomyBudgetState = {
      windowStartedAtMs: this.autonomyBudgetState.windowStartedAtMs,
      reviewBypassCount: this.autonomyBudgetState.reviewBypassCount + 1,
      cumulativeBypassRisk: this.autonomyBudgetState.cumulativeBypassRisk + result.riskScore
    };

    const reasonEntries: Array<{ id: string; reason: string }> = [];
    if (result.riskScore > this.autonomyBudgetLimits.maxSingleBypassRisk) {
      reasonEntries.push({
        id: "max_single_bypass_risk",
        reason: `Bypass risk ${result.riskScore} exceeds max single bypass risk ${this.autonomyBudgetLimits.maxSingleBypassRisk}`
      });
    }
    if (projectedState.reviewBypassCount > this.autonomyBudgetLimits.maxReviewBypass) {
      reasonEntries.push({
        id: "max_review_bypass",
        reason: `Review bypass count ${projectedState.reviewBypassCount} exceeds max ${this.autonomyBudgetLimits.maxReviewBypass}`
      });
    }
    if (projectedState.cumulativeBypassRisk > this.autonomyBudgetLimits.maxCumulativeRisk) {
      reasonEntries.push({
        id: "max_cumulative_risk",
        reason: `Cumulative bypass risk ${projectedState.cumulativeBypassRisk} exceeds max ${this.autonomyBudgetLimits.maxCumulativeRisk}`
      });
    }

    const exceeded = reasonEntries.length > 0;
    const reasons = reasonEntries.map((entry) => entry.reason);
    const budgetSignals = reasonEntries.map((entry) => `autonomy_budget:${entry.id}`);
    const snapshot = this.createAutonomyBudgetSnapshot(projectedState);

    if (exceeded && this.autonomyBudgetMode === "enforce") {
      return {
        ...result,
        effectiveStatus: "block",
        allowed: false,
        reviewBypassed: false,
        requiresHumanApproval: false,
        exitCode: 30,
        riskScore: Math.max(result.riskScore, 88),
        signals: dedupe([...result.signals, ...budgetSignals]),
        challengeRequired: false,
        autonomyBudgetMode: this.autonomyBudgetMode,
        autonomyBudgetExceeded: true,
        autonomyBudgetReasons: reasons,
        autonomyBudgetSnapshot: snapshot
      };
    }

    this.autonomyBudgetState = projectedState;
    return {
      ...result,
      signals: dedupe([...result.signals, ...budgetSignals]),
      autonomyBudgetMode: this.autonomyBudgetMode,
      autonomyBudgetExceeded: exceeded,
      autonomyBudgetReasons: reasons,
      autonomyBudgetSnapshot: snapshot
    };
  }

  private normalizeFirewallRules(rules: AiSecFirewallRule[]): NormalizedFirewallRule[] {
    return rules.map((rule, index) => {
      const id = rule.id?.trim();
      if (!id) {
        throw new AiSecConfigError(`Execution firewall rule at index ${index} is missing a valid id`);
      }

      const reason = rule.reason?.trim();
      if (!reason) {
        throw new AiSecConfigError(`Execution firewall rule "${id}" is missing a reason`);
      }

      const normalizedTool = typeof rule.tool === "string" ? normalizeTool(rule.tool, this.toolAliases) : undefined;

      const parsedFlags = typeof rule.flags === "string" ? rule.flags.replace(/g/g, "") : undefined;
      let pattern: RegExp;
      try {
        if (rule.pattern instanceof RegExp) {
          const flags = (parsedFlags ?? rule.pattern.flags).replace(/g/g, "");
          pattern = new RegExp(rule.pattern.source, flags);
        } else {
          pattern = new RegExp(rule.pattern, parsedFlags ?? "i");
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new AiSecConfigError(`Invalid execution firewall rule "${id}": ${message}`);
      }

      return {
        id,
        tool: normalizedTool && normalizedTool.length > 0 ? normalizedTool : undefined,
        pattern,
        reason
      };
    });
  }

  private normalizeContextShieldRules(rules: AiSecContextShieldRule[]): NormalizedContextShieldRule[] {
    return rules.map((rule, index) => {
      const id = rule.id?.trim();
      if (!id) {
        throw new AiSecConfigError(`Context shield rule at index ${index} is missing a valid id`);
      }

      const reason = rule.reason?.trim();
      if (!reason) {
        throw new AiSecConfigError(`Context shield rule "${id}" is missing a reason`);
      }

      const parsedFlags = typeof rule.flags === "string" ? rule.flags.replace(/g/g, "") : undefined;
      let pattern: RegExp;
      try {
        if (rule.pattern instanceof RegExp) {
          const flags = (parsedFlags ?? rule.pattern.flags).replace(/g/g, "");
          pattern = new RegExp(rule.pattern.source, flags);
        } else {
          pattern = new RegExp(rule.pattern, parsedFlags ?? "i");
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new AiSecConfigError(`Invalid context shield rule "${id}": ${message}`);
      }

      const trustSet =
        Array.isArray(rule.trust) && rule.trust.length > 0
          ? new Set(rule.trust.filter((trust): trust is AiSecTrustLevel => ["internal", "partner", "external", "unknown"].includes(trust)))
          : undefined;

      return {
        id,
        pattern,
        reason,
        trust: trustSet && trustSet.size > 0 ? trustSet : undefined
      };
    });
  }

  private evaluateContextShield(context: NormalizedContextChunk[]): {
    forwardedContext: NormalizedContextChunk[];
    findings: AiSecContextShieldFinding[];
    quarantinedChunkCount: number;
  } {
    if (this.contextShieldMode === "off" || context.length === 0 || this.contextShieldRules.length === 0) {
      return {
        forwardedContext: context,
        findings: [],
        quarantinedChunkCount: 0
      };
    }

    const findings: AiSecContextShieldFinding[] = [];
    const quarantinedSourceIds = new Set<string>();
    const findingIds = new Set<string>();

    for (const chunk of context) {
      if (!this.contextShieldQuarantineTrust.has(chunk.trust)) {
        continue;
      }

      for (const rule of this.contextShieldRules) {
        if (rule.trust && !rule.trust.has(chunk.trust)) {
          continue;
        }

        const match = chunk.content.match(rule.pattern);
        if (!match || match[0].length === 0) {
          continue;
        }

        const dedupeKey = `${rule.id}:${chunk.source_id}`;
        if (findingIds.has(dedupeKey)) {
          continue;
        }

        findingIds.add(dedupeKey);
        quarantinedSourceIds.add(chunk.source_id);
        findings.push({
          id: rule.id,
          sourceId: chunk.source_id,
          trust: chunk.trust,
          reason: rule.reason,
          match: match[0].slice(0, 120)
        });
      }
    }

    if (this.contextShieldMode === "audit") {
      return {
        forwardedContext: context,
        findings,
        quarantinedChunkCount: 0
      };
    }

    return {
      forwardedContext: context.filter((chunk) => !quarantinedSourceIds.has(chunk.source_id)),
      findings,
      quarantinedChunkCount: quarantinedSourceIds.size
    };
  }

  private normalizeToolExecutions(executions: AiSecToolExecution[] | undefined): { tool: string; input: string }[] {
    if (!executions || executions.length === 0) {
      return [];
    }

    return executions
      .map((execution) => {
        const tool = normalizeTool(execution.tool, this.toolAliases);
        if (!tool) {
          return undefined;
        }

        if (typeof execution.input === "string") {
          return { tool, input: execution.input };
        }

        if (execution.input === undefined || execution.input === null) {
          return { tool, input: "" };
        }

        try {
          return { tool, input: JSON.stringify(execution.input) };
        } catch {
          return { tool, input: String(execution.input) };
        }
      })
      .filter((item): item is { tool: string; input: string } => Boolean(item));
  }

  private evaluateFirewall(input: AiSecGateInput, requestedTools: string[]): AiSecFirewallFinding[] {
    if (this.firewallMode === "off") {
      return [];
    }

    const findings: AiSecFirewallFinding[] = [];
    const uniqueFindingIds = new Set<string>();

    for (const tool of requestedTools) {
      if (!this.firewallBlockedTools.has(tool)) {
        continue;
      }

      const findingId = `blocked_tool:${tool}`;
      if (uniqueFindingIds.has(findingId)) {
        continue;
      }

      uniqueFindingIds.add(findingId);
      findings.push({
        id: findingId,
        reason: `Tool "${tool}" is blocked by local execution firewall policy`,
        tool
      });
    }

    const normalizedExecutions = this.normalizeToolExecutions(input.toolExecutions);
    for (const execution of normalizedExecutions) {
      for (const rule of this.firewallRules) {
        if (rule.tool && rule.tool !== execution.tool) {
          continue;
        }

        const match = execution.input.match(rule.pattern);
        if (!match || match[0].length === 0) {
          continue;
        }

        const findingId = `${rule.id}:${execution.tool}`;
        if (uniqueFindingIds.has(findingId)) {
          continue;
        }

        uniqueFindingIds.add(findingId);
        findings.push({
          id: rule.id,
          reason: rule.reason,
          tool: execution.tool,
          match: match[0].slice(0, 120)
        });
      }
    }

    return findings;
  }

  private applyFirewall(result: AiSecGuardResult, findings: AiSecFirewallFinding[]): AiSecGuardResult {
    if (this.firewallMode === "off" || findings.length === 0) {
      return {
        ...result,
        firewallMode: this.firewallMode,
        firewallBlocked: false,
        firewallFindings: findings
      };
    }

    if (this.firewallMode === "audit") {
      return {
        ...result,
        firewallMode: this.firewallMode,
        firewallBlocked: false,
        firewallFindings: findings
      };
    }

    const firewallSignals = findings.map((finding) => `firewall:${finding.id}`);
    const firewallTools = findings
      .map((finding) => finding.tool)
      .filter((tool): tool is string => typeof tool === "string" && tool.trim().length > 0);

    return {
      ...result,
      effectiveStatus: "block",
      allowed: false,
      reviewBypassed: false,
      requiresHumanApproval: false,
      exitCode: 30,
      riskScore: Math.max(result.riskScore, 95),
      signals: dedupe([...result.signals, ...firewallSignals]),
      blockedTools: dedupe([...result.blockedTools, ...firewallTools]),
      challengeRequired: false,
      firewallMode: this.firewallMode,
      firewallBlocked: true,
      firewallFindings: findings
    };
  }

  private evaluateCanary(input: AiSecGateInput): AiSecCanaryFinding[] {
    if (this.canaryMode === "off" || this.canaryTokens.length === 0) {
      return [];
    }

    const findings: AiSecCanaryFinding[] = [];
    const seen = new Set<string>();

    for (const token of this.canaryTokens) {
      if (input.prompt.includes(token)) {
        const key = `prompt:${token}`;
        if (!seen.has(key)) {
          seen.add(key);
          findings.push({
            token,
            source: "prompt"
          });
        }
      }
    }

    const executions = this.normalizeToolExecutions(input.toolExecutions);
    for (const execution of executions) {
      for (const token of this.canaryTokens) {
        if (!execution.input.includes(token)) {
          continue;
        }

        const key = `tool_input:${execution.tool}:${token}`;
        if (seen.has(key)) {
          continue;
        }

        seen.add(key);
        findings.push({
          token,
          source: "tool_input",
          tool: execution.tool
        });
      }
    }

    return findings;
  }

  private applyCanary(result: AiSecGuardResult, findings: AiSecCanaryFinding[]): AiSecGuardResult {
    if (this.canaryMode === "off" || findings.length === 0) {
      return {
        ...result,
        canaryMode: this.canaryMode,
        canaryDetected: false,
        canaryFindings: findings
      };
    }

    if (this.canaryMode === "audit") {
      return {
        ...result,
        canaryMode: this.canaryMode,
        canaryDetected: true,
        canaryFindings: findings
      };
    }

    const canarySignals = findings.map((finding) => `canary_leak:${finding.source}`);
    const canaryTools = findings
      .map((finding) => finding.tool)
      .filter((tool): tool is string => typeof tool === "string" && tool.trim().length > 0);

    return {
      ...result,
      effectiveStatus: "block",
      allowed: false,
      reviewBypassed: false,
      requiresHumanApproval: false,
      exitCode: 30,
      riskScore: Math.max(result.riskScore, 98),
      signals: dedupe([...result.signals, ...canarySignals]),
      blockedTools: dedupe([...result.blockedTools, ...canaryTools]),
      challengeRequired: false,
      canaryMode: this.canaryMode,
      canaryDetected: true,
      canaryFindings: findings
    };
  }

  private async gateOnce(input: AiSecGateInput, confirmedTools: string[]): Promise<AiSecGuardResult> {
    const prompt = input.prompt.trim();
    if (!prompt) {
      throw new AiSecTransportError("Prompt is required");
    }

    const requestedTools = this.normalizeTools(input.tools ?? []);
    const normalizedContext = normalizeContextChunks(input.context ?? []);
    const contextShield = this.evaluateContextShield(normalizedContext);
    const contextShieldSignals =
      contextShield.findings.length === 0
        ? []
        : dedupe([
            ...contextShield.findings.map((finding) => `context_shield:${finding.id}`),
            ...(contextShield.quarantinedChunkCount > 0 ? ["context_shield:quarantine"] : [])
          ]);

    const payload: GatewayRequestPayload = {
      session_id: this.sessionId,
      user_id: this.userId,
      prompt,
      context: toGatewayContext(contextShield.forwardedContext),
      requested_tools: requestedTools,
      user_confirmed_tools: this.normalizeTools(confirmedTools),
      metadata: mergeMetadata(this.metadata, input.metadata)
    };

    const response = await this.callGateway(payload);
    const gatewayStatus = classifyDecision(response.decision);
    const effectiveStatus: AiSecEffectiveStatus = gatewayStatus;

    const baseResult: AiSecGuardResult = {
      gatewayDecision: response.decision,
      gatewayStatus,
      effectiveStatus,
      allowed: effectiveStatus === "allow",
      reviewBypassed: false,
      requiresHumanApproval: effectiveStatus === "review",
      exitCode: effectiveStatus === "allow" ? 0 : effectiveStatus === "review" ? 20 : 30,
      riskScore: response.risk_score,
      signals: dedupe([...response.signals, ...contextShieldSignals]),
      blockedTools: response.blocked_tools,
      challengeRequired: response.challenge_required,
      eventId: response.event_id,
      firewallMode: this.firewallMode,
      firewallBlocked: false,
      firewallFindings: [],
      canaryMode: this.canaryMode,
      canaryDetected: false,
      canaryFindings: [],
      autonomyBudgetMode: this.autonomyBudgetMode,
      autonomyBudgetExceeded: false,
      autonomyBudgetReasons: [],
      autonomyBudgetSnapshot: this.createAutonomyBudgetSnapshot(this.autonomyBudgetState),
      contextShieldMode: this.contextShieldMode,
      contextShieldQuarantinedChunks: contextShield.quarantinedChunkCount,
      contextShieldFindings: contextShield.findings
    };

    const firewallFindings = this.evaluateFirewall(input, requestedTools);
    const withFirewall = this.applyFirewall(baseResult, firewallFindings);
    const canaryFindings = this.evaluateCanary(input);
    return this.applyCanary(withFirewall, canaryFindings);
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

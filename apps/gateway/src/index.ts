import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { randomUUID } from "node:crypto";
import {
  evaluatePolicy,
  guardToolCall,
  sanitizeModelOutput,
  scanMany,
  type ScanSignal
} from "@ai-sec/security-core";
import { runRedTeamSuite } from "@ai-sec/redteam-runner";
import { config } from "./config.js";
import { logger } from "./logger.js";
import { EventStore } from "./eventStore.js";
import { generateModelResponse } from "./modelProvider.js";
import {
  agentGateRequestSchema,
  contextScanRequestSchema,
  listSecurityEventsQuerySchema,
  redTeamRunSchema,
  secureChatRequestSchema
} from "./schemas.js";
import { authenticateRequest, requireRole } from "./auth.js";

const app = express();
const eventStore = new EventStore(config.databaseUrl);
const authBypassEnabled =
  config.authMode === "disabled" ||
  (config.authMode === "auto" && config.serviceApiTokens.size === 0 && config.nodeEnv !== "production");

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "256kb" }));
app.use(
  rateLimit({
    windowMs: 60_000,
    limit: config.apiRateLimitPerMinute,
    standardHeaders: "draft-8",
    legacyHeaders: false
  })
);
app.use(
  (req, res, next) => {
    const requestId = randomUUID();
    const startedAt = Date.now();
    res.setHeader("x-request-id", requestId);
    res.on("finish", () => {
      logger.info(
        {
          requestId,
          method: req.method,
          path: req.path,
          statusCode: res.statusCode,
          latencyMs: Date.now() - startedAt
        },
        "http_request"
      );
    });
    next();
  }
);

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "gateway", timestamp: new Date().toISOString() });
});

app.use(
  "/v1",
  authenticateRequest(config.serviceApiTokens, {
    allowAnonymous: authBypassEnabled,
    anonymousRole: "admin"
  })
);

app.post("/v1/context/scan", async (req, res) => {
  const startedAt = Date.now();
  const eventId = randomUUID();

  const parsedBody = contextScanRequestSchema.safeParse(req.body);
  if (!parsedBody.success) {
    return res.status(400).json({
      error: "invalid_request",
      details: parsedBody.error.flatten()
    });
  }

  const body = parsedBody.data;
  const chunkResults = body.context.map((chunk) => {
    const scan = scanMany([chunk.content], "context");
    const decision = evaluatePolicy({
      input: scan,
      context: scan,
      output: scan
    });

    const action = decision.decision === "allow" ? "allow" : "quarantine";
    return {
      source_id: chunk.source_id,
      trust: chunk.trust,
      action,
      decision: decision.decision,
      risk_score: decision.riskScore,
      signals: scan.signals.map((signal) => signal.id)
    };
  });

  const quarantined = chunkResults.filter((result) => result.action === "quarantine");
  const allSignals = [...new Set(chunkResults.flatMap((result) => result.signals))];
  const maxRiskScore = chunkResults.reduce((max, result) => Math.max(max, result.risk_score), 0);
  const summaryAction = quarantined.length > 0 ? "quarantine" : "allow";
  const latencyMs = Date.now() - startedAt;

  await eventStore.write({
    eventId,
    eventType: "context_scan",
    sessionId: body.session_id,
    userId: body.user_id,
    riskScore: maxRiskScore,
    decision: summaryAction,
    signals: allSignals,
    blockedTools: [],
    latencyMs,
    payload: {
      total_chunks: chunkResults.length,
      quarantined_chunks: quarantined.length,
      quarantined_source_ids: quarantined.map((result) => result.source_id).slice(0, 200),
      metadata: body.metadata ?? {}
    }
  });

  return res.json({
    summary: {
      action: summaryAction,
      total_chunks: chunkResults.length,
      quarantined_chunks: quarantined.length,
      max_risk_score: maxRiskScore,
      signals: allSignals
    },
    results: chunkResults,
    event_id: eventId
  });
});

app.post("/v1/agent/gate", async (req, res) => {
  const startedAt = Date.now();
  const eventId = randomUUID();

  const parsedBody = agentGateRequestSchema.safeParse(req.body);
  if (!parsedBody.success) {
    return res.status(400).json({
      error: "invalid_request",
      details: parsedBody.error.flatten()
    });
  }

  const body = parsedBody.data;
  const inputScan = scanMany([body.prompt], "input");
  const contextScan = scanMany(body.context.map((chunk) => chunk.content), "context");

  let policy = evaluatePolicy({
    input: inputScan,
    context: contextScan,
    requestedTools: body.requested_tools
  });

  const blockedTools: string[] = [];
  for (const toolName of body.requested_tools) {
    const confirmed = body.user_confirmed_tools.includes(toolName);
    const toolGate = guardToolCall(toolName, confirmed);
    if (!toolGate.allowed) {
      blockedTools.push(toolName);
    }
  }

  if (blockedTools.length > 0 && policy.decision !== "block") {
    policy = {
      decision: "human_review",
      riskScore: Math.max(policy.riskScore, 60),
      reasons: ["One or more requested tools require explicit confirmation"]
    };
  }

  const allSignals = [...inputScan.signals, ...contextScan.signals];
  const latencyMs = Date.now() - startedAt;

  await eventStore.write({
    eventId,
    eventType: "agent_gate",
    sessionId: body.session_id,
    userId: body.user_id,
    riskScore: policy.riskScore,
    decision: policy.decision,
    signals: allSignals.map((signal) => signal.id),
    blockedTools,
    latencyMs,
    payload: {
      reasons: policy.reasons,
      metadata: body.metadata ?? {}
    }
  });

  return res.json({
    decision: policy.decision,
    risk_score: policy.riskScore,
    signals: allSignals.map((signal) => signal.id),
    blocked_tools: blockedTools,
    challenge_required: policy.decision === "challenge" || policy.decision === "human_review",
    event_id: eventId
  });
});

app.post("/v1/secure-chat", async (req, res) => {
  const startedAt = Date.now();
  const eventId = randomUUID();

  const parsedBody = secureChatRequestSchema.safeParse(req.body);
  if (!parsedBody.success) {
    return res.status(400).json({
      error: "invalid_request",
      details: parsedBody.error.flatten()
    });
  }

  const body = parsedBody.data;
  const inputTexts = body.messages.map((message) => message.content);
  const contextTexts = body.context.map((chunk) => chunk.content);

  const inputScan = scanMany(inputTexts, "input");
  const contextScan = scanMany(contextTexts, "context");

  let policy = evaluatePolicy({
    input: inputScan,
    context: contextScan,
    requestedTools: body.requested_tools
  });

  let assistantMessage: string | undefined;
  let removedArtifacts: string[] = [];
  let outputSignals: ScanSignal[] = [];

  if (policy.decision === "allow" || policy.decision === "sanitize") {
    const rawOutput = await generateModelResponse(body);
    const sanitizedOutput = sanitizeModelOutput(rawOutput);
    assistantMessage = sanitizedOutput.sanitized;
    removedArtifacts = sanitizedOutput.removedArtifacts;

    const outputScan = scanMany([assistantMessage], "output");
    outputSignals = outputScan.signals;

    const postPolicy = evaluatePolicy({
      input: inputScan,
      context: contextScan,
      output: outputScan,
      requestedTools: body.requested_tools
    });

    if (postPolicy.riskScore > policy.riskScore || postPolicy.decision === "block") {
      policy = postPolicy;
      if (policy.decision === "block") {
        assistantMessage = undefined;
      }
    }
  }

  const blockedTools: string[] = [];
  for (const toolName of body.requested_tools) {
    const confirmed = body.user_confirmed_tools.includes(toolName);
    const toolGate = guardToolCall(toolName, confirmed);
    if (!toolGate.allowed) {
      blockedTools.push(toolName);
    }
  }

  if (blockedTools.length > 0 && policy.decision !== "block") {
    policy = {
      decision: "human_review",
      riskScore: Math.max(policy.riskScore, 60),
      reasons: ["One or more requested tools require explicit confirmation"]
    };
  }

  const allSignals = [...inputScan.signals, ...contextScan.signals, ...outputSignals];
  const latencyMs = Date.now() - startedAt;

  await eventStore.write({
    eventId,
    eventType: "secure_chat",
    sessionId: body.session_id,
    userId: body.user_id,
    model: body.model,
    riskScore: policy.riskScore,
    decision: policy.decision,
    signals: allSignals.map((signal) => signal.id),
    blockedTools,
    latencyMs,
    payload: {
      removedArtifacts,
      reasons: policy.reasons,
      metadata: body.metadata ?? {}
    }
  });

  return res.json({
    model_provider: config.modelProvider,
    decision: policy.decision,
    risk_score: policy.riskScore,
    signals: allSignals.map((signal) => signal.id),
    assistant_message: assistantMessage,
    blocked_tools: blockedTools,
    challenge_required: policy.decision === "challenge" || policy.decision === "human_review",
    event_id: eventId
  });
});

app.post("/v1/redteam/run", async (req, res) => {
  const eventId = randomUUID();
  const startedAt = Date.now();

  const parsedBody = redTeamRunSchema.safeParse(req.body);
  if (!parsedBody.success) {
    return res.status(400).json({
      error: "invalid_request",
      details: parsedBody.error.flatten()
    });
  }

  const body = parsedBody.data;

  const run = runRedTeamSuite({
    suite: body.suite,
    targetModel: body.target_model,
    maxSuccessfulAttacks: body.fail_threshold.max_successful_attacks,
    minDetectionRate: body.fail_threshold.min_detection_rate
  });

  await eventStore.write({
    eventId,
    eventType: "redteam_run",
    model: body.target_model,
    riskScore: Math.round(run.detectionRate * 100),
    decision: run.status,
    signals: run.outcomes.flatMap((outcome) => outcome.signals),
    blockedTools: [],
    latencyMs: Date.now() - startedAt,
    payload: run as unknown as Record<string, unknown>
  });

  return res.status(run.status === "pass" ? 200 : 409).json({
    run_id: run.runId,
    status: run.status,
    detection_rate: run.detectionRate,
    successful_attacks: run.successfulAttacks,
    total_cases: run.totalCases,
    outcomes: run.outcomes
  });
});

app.get("/v1/security-events", requireRole("analyst"), async (req, res) => {
  const parsed = listSecurityEventsQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    return res.status(400).json({
      error: "invalid_request",
      details: parsed.error.flatten()
    });
  }

  const query = parsed.data;
  const events = await eventStore.list({
    limit: query.limit,
    eventType: query.event_type,
    decision: query.decision
  });

  return res.json({
    total: events.length,
    events: events.map((event) => ({
      id: event.id,
      event_type: event.eventType,
      created_at: event.createdAt,
      session_id: event.sessionId,
      user_id: event.userId,
      model: event.model,
      risk_score: event.riskScore,
      decision: event.decision,
      signals: event.signals,
      blocked_tools: event.blockedTools,
      latency_ms: event.latencyMs
    }))
  });
});

app.get("/v1/security-events/:id", requireRole("analyst"), async (req, res) => {
  const rawId = req.params.id;
  const id = Array.isArray(rawId) ? rawId[0] : rawId;
  if (!id || id.length > 200) {
    return res.status(400).json({ error: "invalid_request" });
  }

  const event = await eventStore.getById(id);
  if (!event) {
    return res.status(404).json({ error: "not_found" });
  }

  return res.json({
    event: {
      id: event.id,
      event_type: event.eventType,
      created_at: event.createdAt,
      session_id: event.sessionId,
      user_id: event.userId,
      model: event.model,
      risk_score: event.riskScore,
      decision: event.decision,
      signals: event.signals,
      blocked_tools: event.blockedTools,
      latency_ms: event.latencyMs,
      payload: event.payload
    }
  });
});

app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error({ error }, "Unhandled gateway error");
  res.status(500).json({ error: "internal_error" });
});

async function start(): Promise<void> {
  await eventStore.init();

  if (authBypassEnabled) {
    logger.warn({
      authMode: config.authMode,
      nodeEnv: config.nodeEnv
    }, "API auth bypass is enabled. /v1 endpoints accept anonymous access.");
  } else if (config.serviceApiTokens.size === 0) {
    logger.warn("SERVICE_API_TOKENS is empty; all /v1 requests will be denied");
  }

  const server = app.listen(config.port, () => {
    logger.info({ port: config.port }, "Gateway listening");
  });

  const shutdown = async () => {
    logger.info("Shutting down");
    server.close(async () => {
      await eventStore.close();
      process.exit(0);
    });
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

start().catch((error) => {
  logger.error({ error }, "Failed to start gateway");
  process.exit(1);
});

import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

interface EventRecord {
  id: string;
  event_type: string;
  created_at: string;
  decision: string;
  risk_score: number;
  latency_ms: number;
  signals: string[];
  payload: Record<string, unknown>;
}

function json(res: ServerResponse, code: number, payload: unknown): void {
  res.statusCode = code;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(payload));
}

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.from(chunk));
  }

  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw.trim()) {
    return {};
  }

  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return {};
  }
}

async function runCliScripted(params: {
  script: string;
  baseUrl: string;
  homeDir: string;
  token?: string;
}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const cliEntry = fileURLToPath(new URL("./index.js", import.meta.url));

  const child = spawn(process.execPath, [cliEntry], {
    env: {
      ...process.env,
      AI_SEC_CLI_SCRIPT: params.script,
      AI_SEC_CLI_NO_CLEAR: "1",
      AI_SEC_CLI_TELEMETRY: "off",
      GATEWAY_URL: params.baseUrl,
      HOME: params.homeDir,
      USERPROFILE: params.homeDir,
      SERVICE_API_TOKEN: params.token ?? ""
    },
    stdio: ["ignore", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";

  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");

  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
  });

  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
  });

  const [code] = (await once(child, "exit")) as [number | null];
  return { code, stdout, stderr };
}

describe("CLI scripted flows", () => {
  let server = createServer();
  let baseUrl = "";
  let homeDir = "";
  const events: EventRecord[] = [];
  let secureChatRequiresAuth = false;

  before(async () => {
    homeDir = await mkdtemp(path.join(tmpdir(), "ai-sec-cli-test-"));

    server = createServer(async (req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");

      if (req.method === "GET" && url.pathname === "/health") {
        json(res, 200, { status: "ok", service: "gateway", timestamp: new Date().toISOString() });
        return;
      }

      if (req.method === "POST" && url.pathname === "/v1/secure-chat") {
        const authHeader = req.headers.authorization;
        if (secureChatRequiresAuth && authHeader !== "Bearer token-analyst") {
          json(res, 401, { error: "unauthorized" });
          return;
        }

        const body = await readBody(req);
        const message = Array.isArray(body.messages)
          ? ((body.messages[0] as { content?: unknown })?.content as string | undefined) ?? ""
          : "";

        const blocked = /ignore\s+all\s+previous\s+instructions/i.test(message);
        const event: EventRecord = {
          id: `evt_${events.length + 1}`,
          event_type: "secure_chat",
          created_at: new Date().toISOString(),
          decision: blocked ? "block" : "allow",
          risk_score: blocked ? 85 : 0,
          latency_ms: 3,
          signals: blocked ? ["direct_override"] : [],
          payload: { prompt: message }
        };
        events.unshift(event);

        json(res, 200, {
          model_provider: "mock",
          decision: event.decision,
          risk_score: event.risk_score,
          signals: event.signals,
          assistant_message: blocked ? undefined : "Request received. Safe summary.",
          blocked_tools: [],
          challenge_required: false,
          event_id: event.id
        });
        return;
      }

      if (req.method === "POST" && url.pathname === "/v1/context/scan") {
        const event: EventRecord = {
          id: `evt_${events.length + 1}`,
          event_type: "context_scan",
          created_at: new Date().toISOString(),
          decision: "quarantine",
          risk_score: 100,
          latency_ms: 2,
          signals: ["direct_override", "indirect_bracket_instruction"],
          payload: { quarantined_chunks: 1 }
        };
        events.unshift(event);

        json(res, 200, {
          summary: {
            action: "quarantine",
            total_chunks: 2,
            quarantined_chunks: 1,
            max_risk_score: 100,
            signals: ["direct_override", "indirect_bracket_instruction"]
          },
          results: [],
          event_id: event.id
        });
        return;
      }

      if (req.method === "POST" && url.pathname === "/v1/redteam/run") {
        const event: EventRecord = {
          id: `evt_${events.length + 1}`,
          event_type: "redteam_run",
          created_at: new Date().toISOString(),
          decision: "pass",
          risk_score: 100,
          latency_ms: 3,
          signals: [],
          payload: { run_id: "run_mock" }
        };
        events.unshift(event);

        json(res, 200, {
          run_id: "run_mock",
          status: "pass",
          detection_rate: 1,
          successful_attacks: 0,
          total_cases: 8
        });
        return;
      }

      if (req.method === "GET" && url.pathname === "/v1/security-events") {
        json(res, 200, {
          total: events.length,
          events: events.map((event) => ({
            id: event.id,
            event_type: event.event_type,
            created_at: event.created_at,
            decision: event.decision,
            risk_score: event.risk_score,
            latency_ms: event.latency_ms,
            signals: event.signals
          }))
        });
        return;
      }

      if (req.method === "GET" && url.pathname.startsWith("/v1/security-events/")) {
        const id = url.pathname.split("/").at(-1) ?? "";
        const event = events.find((item) => item.id === id);
        if (!event) {
          json(res, 404, { error: "not_found" });
          return;
        }

        json(res, 200, {
          event: {
            id: event.id,
            event_type: event.event_type,
            created_at: event.created_at,
            decision: event.decision,
            risk_score: event.risk_score,
            signals: event.signals,
            payload: event.payload
          }
        });
        return;
      }

      json(res, 404, { error: "not_found" });
    });

    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Expected tcp address");
    }

    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  after(async () => {
    server.close();
    await once(server, "close");
    await rm(homeDir, { recursive: true, force: true });
  });

  it("runs a full scripted operator flow successfully", async () => {
    secureChatRequiresAuth = false;
    const result = await runCliScripted({
      script: "health,safe,injection,context:mixed,redteam,events,exit",
      baseUrl,
      homeDir
    });

    assert.equal(result.code, 0);
    assert.match(result.stdout, /Gateway Health/);
    assert.match(result.stdout, /Secure Chat - Safe Prompt/);
    assert.match(result.stdout, /Secure Chat - Injection Challenge/);
    assert.match(result.stdout, /Context Scan/);
    assert.match(result.stdout, /Red-Team Run/);
    assert.match(result.stdout, /Event Details/);
    assert.match(result.stdout, /Session closed\./);
    assert.ok(!/Fatal error/i.test(result.stderr));
  });

  it("recovers gracefully from 401 responses in scripted mode", async () => {
    secureChatRequiresAuth = true;

    const result = await runCliScripted({
      script: "safe,exit",
      baseUrl,
      homeDir
    });

    assert.equal(result.code, 0);
    assert.match(result.stdout, /HTTP 401/);
    assert.match(result.stdout, /Session closed\./);
  });
});

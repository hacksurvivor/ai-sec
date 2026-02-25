import { Pool } from "pg";
import { logger } from "./logger.js";

export interface SecurityEventRecord {
  eventId: string;
  eventType: "secure_chat" | "redteam_run" | "context_scan";
  sessionId?: string;
  userId?: string;
  model?: string;
  riskScore?: number;
  decision?: string;
  signals?: string[];
  blockedTools?: string[];
  latencyMs?: number;
  payload: Record<string, unknown>;
}

export interface SecurityEventView {
  id: string;
  eventType: string;
  createdAt: string;
  sessionId: string | null;
  userId: string | null;
  model: string | null;
  riskScore: number | null;
  decision: string | null;
  signals: string[];
  blockedTools: string[];
  latencyMs: number | null;
  payload: Record<string, unknown>;
}

interface ListOptions {
  limit: number;
  eventType?: "secure_chat" | "redteam_run" | "context_scan";
  decision?: string;
}

function asObject(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

function parseJsonObject(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }

  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return {};
    }
  }

  return {};
}

function parseJsonArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === "string");
  }

  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value) as unknown;
      if (Array.isArray(parsed)) {
        return parsed.filter((item): item is string => typeof item === "string");
      }
    } catch {
      return [];
    }
  }

  return [];
}

function toView(row: Record<string, unknown>): SecurityEventView {
  return {
    id: typeof row.id === "string" ? row.id : "",
    eventType: typeof row.event_type === "string" ? row.event_type : "",
    createdAt:
      typeof row.created_at === "string"
        ? row.created_at
        : row.created_at instanceof Date
          ? row.created_at.toISOString()
          : new Date().toISOString(),
    sessionId: typeof row.session_id === "string" ? row.session_id : null,
    userId: typeof row.user_id === "string" ? row.user_id : null,
    model: typeof row.model === "string" ? row.model : null,
    riskScore: typeof row.risk_score === "number" ? row.risk_score : null,
    decision: typeof row.decision === "string" ? row.decision : null,
    signals: parseJsonArray(row.signals),
    blockedTools: parseJsonArray(row.blocked_tools),
    latencyMs: typeof row.latency_ms === "number" ? row.latency_ms : null,
    payload: asObject(parseJsonObject(row.payload))
  };
}

export class EventStore {
  private readonly pool?: Pool;
  private readonly memoryEvents: SecurityEventView[] = [];

  public constructor(databaseUrl?: string) {
    if (databaseUrl) {
      this.pool = new Pool({ connectionString: databaseUrl });
    }
  }

  public async init(): Promise<void> {
    if (!this.pool) {
      logger.info("DATABASE_URL not set; using log-only event store");
      return;
    }

    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS security_events (
        id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        session_id TEXT,
        user_id TEXT,
        model TEXT,
        risk_score INT,
        decision TEXT,
        signals JSONB,
        blocked_tools JSONB,
        latency_ms INT,
        payload JSONB NOT NULL
      )
    `);
  }

  public async write(record: SecurityEventRecord): Promise<void> {
    const memoryRecord: SecurityEventView = {
      id: record.eventId,
      eventType: record.eventType,
      createdAt: new Date().toISOString(),
      sessionId: record.sessionId ?? null,
      userId: record.userId ?? null,
      model: record.model ?? null,
      riskScore: record.riskScore ?? null,
      decision: record.decision ?? null,
      signals: record.signals ?? [],
      blockedTools: record.blockedTools ?? [],
      latencyMs: record.latencyMs ?? null,
      payload: record.payload
    };
    this.memoryEvents.unshift(memoryRecord);
    if (this.memoryEvents.length > 500) {
      this.memoryEvents.length = 500;
    }

    if (!this.pool) {
      logger.info({
        eventId: record.eventId,
        eventType: record.eventType,
        decision: record.decision,
        riskScore: record.riskScore
      }, "security_event");
      return;
    }

    await this.pool.query(
      `
      INSERT INTO security_events (
        id,
        event_type,
        session_id,
        user_id,
        model,
        risk_score,
        decision,
        signals,
        blocked_tools,
        latency_ms,
        payload
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      `,
      [
        record.eventId,
        record.eventType,
        record.sessionId ?? null,
        record.userId ?? null,
        record.model ?? null,
        record.riskScore ?? null,
        record.decision ?? null,
        JSON.stringify(record.signals ?? []),
        JSON.stringify(record.blockedTools ?? []),
        record.latencyMs ?? null,
        JSON.stringify(record.payload)
      ]
    );
  }

  public async list(options: ListOptions): Promise<SecurityEventView[]> {
    if (!this.pool) {
      return this.memoryEvents
        .filter((event) => {
          if (options.eventType && event.eventType !== options.eventType) {
            return false;
          }
          if (options.decision && event.decision !== options.decision) {
            return false;
          }
          return true;
        })
        .slice(0, options.limit);
    }

    const conditions: string[] = [];
    const values: unknown[] = [];
    let index = 1;

    if (options.eventType) {
      conditions.push(`event_type = $${index}`);
      values.push(options.eventType);
      index += 1;
    }

    if (options.decision) {
      conditions.push(`decision = $${index}`);
      values.push(options.decision);
      index += 1;
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    values.push(options.limit);

    const query = `
      SELECT id, event_type, created_at, session_id, user_id, model, risk_score, decision, signals, blocked_tools, latency_ms, payload
      FROM security_events
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT $${index}
    `;

    const result = await this.pool.query(query, values);
    return result.rows.map((row) => toView(row));
  }

  public async getById(id: string): Promise<SecurityEventView | undefined> {
    if (!this.pool) {
      return this.memoryEvents.find((event) => event.id === id);
    }

    const query = `
      SELECT id, event_type, created_at, session_id, user_id, model, risk_score, decision, signals, blocked_tools, latency_ms, payload
      FROM security_events
      WHERE id = $1
      LIMIT 1
    `;
    const result = await this.pool.query(query, [id]);
    if (result.rows.length === 0) {
      return undefined;
    }
    return toView(result.rows[0]);
  }

  public async close(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
    }
  }
}

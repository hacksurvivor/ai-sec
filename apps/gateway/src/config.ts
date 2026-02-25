import dotenv from "dotenv";

dotenv.config();

export type PrincipalRole = "ingest" | "analyst" | "admin";
export type AuthMode = "auto" | "required" | "disabled";

function parseServiceApiTokens(raw: string | undefined): Map<string, PrincipalRole> {
  const result = new Map<string, PrincipalRole>();
  if (!raw) {
    return result;
  }

  const entries = raw
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);

  for (const entry of entries) {
    const [tokenPart, rolePart] = entry.split(":");
    const token = tokenPart?.trim() ?? "";
    const role = (rolePart?.trim() ?? "ingest") as PrincipalRole;
    if (!token) {
      continue;
    }
    if (role !== "ingest" && role !== "analyst" && role !== "admin") {
      continue;
    }
    result.set(token, role);
  }

  return result;
}

export interface AppConfig {
  port: number;
  nodeEnv: string;
  databaseUrl?: string;
  logLevel: string;
  apiRateLimitPerMinute: number;
  modelProvider: "mock" | "ollama";
  modelTimeoutMs: number;
  ollamaBaseUrl: string;
  ollamaModel: string;
  serviceApiTokens: Map<string, PrincipalRole>;
  authMode: AuthMode;
}

function resolveModelProvider(value: string | undefined): "mock" | "ollama" {
  const normalized = (value ?? "mock").toLowerCase();
  if (normalized === "mock" || normalized === "ollama") {
    return normalized;
  }
  return "mock";
}

function resolveAuthMode(value: string | undefined): AuthMode {
  const normalized = (value ?? "required").toLowerCase();
  if (normalized === "auto" || normalized === "required" || normalized === "disabled") {
    return normalized;
  }
  return "required";
}

export const config: AppConfig = {
  port: Number.parseInt(process.env.PORT ?? "8080", 10),
  nodeEnv: process.env.NODE_ENV ?? "development",
  databaseUrl: process.env.DATABASE_URL,
  logLevel: process.env.LOG_LEVEL ?? "info",
  apiRateLimitPerMinute: Number.parseInt(process.env.API_RATE_LIMIT_PER_MINUTE ?? "60", 10),
  modelProvider: resolveModelProvider(process.env.MODEL_PROVIDER),
  modelTimeoutMs: Number.parseInt(process.env.MODEL_TIMEOUT_MS ?? "15000", 10),
  ollamaBaseUrl: process.env.OLLAMA_BASE_URL ?? "http://localhost:11434",
  ollamaModel: process.env.OLLAMA_MODEL ?? "llama3.1:8b",
  serviceApiTokens: parseServiceApiTokens(process.env.SERVICE_API_TOKENS),
  authMode: resolveAuthMode(process.env.AUTH_MODE)
};

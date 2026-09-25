import dotenv from "dotenv";

dotenv.config();

export interface AppConfig {
  port: number;
  nodeEnv: string;
  logLevel: string;
  authRateLimitPerMinute: number;
  issuer: string;
  defaultAudience: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  accessTokenSecret: string;
  refreshTokenPepper: string;
  pairwiseSubjectSecret: string;
  piiLogSalt: string;
}

function parseInteger(value: string | undefined, fallback: number, min: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  if (Number.isNaN(parsed) || parsed < min) {
    return fallback;
  }
  return parsed;
}

function resolveSecret(value: string | undefined, fallbackName: string): string {
  if (value && value.trim().length >= 32) {
    return value.trim();
  }

  if ((process.env.NODE_ENV ?? "development") === "production") {
    throw new Error(`${fallbackName} must be set and at least 32 chars in production`);
  }

  return `dev-${fallbackName}-change-me-before-prod-0123456789`;
}

export const config: AppConfig = {
  port: parseInteger(process.env.AUTH_PORT ?? process.env.PORT, 8090, 1),
  nodeEnv: process.env.NODE_ENV ?? "development",
  logLevel: process.env.LOG_LEVEL ?? "info",
  authRateLimitPerMinute: parseInteger(process.env.AUTH_RATE_LIMIT_PER_MINUTE, 30, 1),
  issuer: process.env.AUTH_ISSUER ?? "ai-sec-auth-service",
  defaultAudience: process.env.AUTH_AUDIENCE_DEFAULT ?? "ai-sec-gateway",
  accessTokenTtlSeconds: parseInteger(process.env.ACCESS_TOKEN_TTL_SECONDS, 300, 60),
  refreshTokenTtlSeconds: parseInteger(process.env.REFRESH_TOKEN_TTL_SECONDS, 2_592_000, 3600),
  accessTokenSecret: resolveSecret(process.env.ACCESS_TOKEN_SECRET, "ACCESS_TOKEN_SECRET"),
  refreshTokenPepper: resolveSecret(process.env.REFRESH_TOKEN_PEPPER, "REFRESH_TOKEN_PEPPER"),
  pairwiseSubjectSecret: resolveSecret(process.env.PAIRWISE_SUBJECT_SECRET, "PAIRWISE_SUBJECT_SECRET"),
  piiLogSalt: resolveSecret(process.env.PII_LOG_SALT, "PII_LOG_SALT")
};

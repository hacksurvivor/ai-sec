import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { randomUUID } from "node:crypto";
import { config } from "./config.js";
import { logger } from "./logger.js";
import { AuthService, AuthServiceError, hashForLogs } from "./authService.js";
import { InMemoryAuthStore } from "./store.js";
import {
  introspectRequestSchema,
  loginRequestSchema,
  refreshRequestSchema,
  registerRequestSchema,
  revokeRequestSchema
} from "./schemas.js";

const app = express();
const store = new InMemoryAuthStore();
const authService = new AuthService(store, {
  issuer: config.issuer,
  defaultAudience: config.defaultAudience,
  accessTokenTtlSeconds: config.accessTokenTtlSeconds,
  refreshTokenTtlSeconds: config.refreshTokenTtlSeconds,
  accessTokenSecret: config.accessTokenSecret,
  refreshTokenPepper: config.refreshTokenPepper,
  pairwiseSubjectSecret: config.pairwiseSubjectSecret
});

const sensitiveLimiter = rateLimit({
  windowMs: 60_000,
  limit: config.authRateLimitPerMinute,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "rate_limited",
    message: "Too many auth attempts"
  }
});

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "64kb" }));
app.use((req, res, next) => {
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
      "auth_request"
    );
  });

  next();
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "auth-service", timestamp: new Date().toISOString() });
});

app.post("/v1/auth/register", sensitiveLimiter, async (req, res) => {
  const parsed = registerRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: "invalid_request",
      details: parsed.error.flatten()
    });
  }

  const body = parsed.data;
  const emailHash = hashForLogs(body.email, config.piiLogSalt);

  try {
    const tokenPair = await authService.register({
      email: body.email,
      password: body.password,
      clientId: body.client_id,
      audience: body.audience,
      scope: body.scope
    });

    logger.info({ emailHash, clientId: body.client_id }, "auth_register_success");
    return res.status(201).json(tokenPair);
  } catch (error) {
    if (error instanceof AuthServiceError) {
      logger.warn({ emailHash, code: error.code }, "auth_register_error");
      return res.status(error.status).json({ error: error.code, message: error.message });
    }

    logger.error({ emailHash, err: error }, "auth_register_unhandled");
    return res.status(500).json({ error: "internal_error" });
  }
});

app.post("/v1/auth/login", sensitiveLimiter, async (req, res) => {
  const parsed = loginRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: "invalid_request",
      details: parsed.error.flatten()
    });
  }

  const body = parsed.data;
  const emailHash = hashForLogs(body.email, config.piiLogSalt);

  try {
    const tokenPair = await authService.login({
      email: body.email,
      password: body.password,
      clientId: body.client_id,
      audience: body.audience,
      scope: body.scope
    });

    logger.info({ emailHash, clientId: body.client_id }, "auth_login_success");
    return res.json(tokenPair);
  } catch (error) {
    if (error instanceof AuthServiceError) {
      logger.warn({ emailHash, clientId: body.client_id, code: error.code }, "auth_login_error");
      return res.status(error.status).json({ error: error.code, message: error.message });
    }

    logger.error({ emailHash, clientId: body.client_id, err: error }, "auth_login_unhandled");
    return res.status(500).json({ error: "internal_error" });
  }
});

app.post("/v1/auth/refresh", sensitiveLimiter, async (req, res) => {
  const parsed = refreshRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: "invalid_request",
      details: parsed.error.flatten()
    });
  }

  const body = parsed.data;

  try {
    const tokenPair = await authService.refresh({
      refreshToken: body.refresh_token,
      clientId: body.client_id,
      audience: body.audience,
      scope: body.scope
    });

    return res.json(tokenPair);
  } catch (error) {
    if (error instanceof AuthServiceError) {
      return res.status(error.status).json({ error: error.code, message: error.message });
    }

    logger.error({ err: error }, "auth_refresh_unhandled");
    return res.status(500).json({ error: "internal_error" });
  }
});

app.post("/v1/auth/introspect", sensitiveLimiter, async (req, res) => {
  const parsed = introspectRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: "invalid_request",
      details: parsed.error.flatten()
    });
  }

  const result = await authService.introspect(parsed.data.token);
  return res.json(result);
});

app.post("/v1/auth/revoke", sensitiveLimiter, async (req, res) => {
  const parsed = revokeRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: "invalid_request",
      details: parsed.error.flatten()
    });
  }

  await authService.revoke({
    refreshToken: parsed.data.refresh_token,
    clientId: parsed.data.client_id
  });

  return res.status(200).json({ revoked: true });
});

app.use((_req, res) => {
  res.status(404).json({ error: "not_found" });
});

const server = app.listen(config.port, () => {
  logger.info({ port: config.port, issuer: config.issuer }, "auth_service_started");
});

const shutdown = () => {
  logger.info("auth_service_shutdown");
  server.close(() => {
    process.exit(0);
  });
};

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

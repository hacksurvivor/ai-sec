import argon2 from "argon2";
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { SignJWT, jwtVerify, type JWTPayload } from "jose";
import type { AuthStore, RefreshTokenRecord, UserRecord } from "./store.js";

export interface AuthServiceConfig {
  issuer: string;
  defaultAudience: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  accessTokenSecret: string;
  refreshTokenPepper: string;
  pairwiseSubjectSecret: string;
}

export interface TokenPair {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  subject: string;
}

export interface IntrospectionResult {
  active: boolean;
  sub?: string;
  aud?: string[];
  iss?: string;
  exp?: number;
  iat?: number;
  client_id?: string;
  scope?: string[];
}

export class AuthServiceError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, status: number, message: string) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function hashForLogs(value: string, salt: string): string {
  return createHash("sha256")
    .update(`${salt}:${value}`)
    .digest("hex")
    .slice(0, 24);
}

function hashRefreshToken(token: string, pepper: string): string {
  return createHash("sha256").update(`${pepper}:${token}`).digest("hex");
}

function safeHexEquals(leftHex: string, rightHex: string): boolean {
  const left = Buffer.from(leftHex, "hex");
  const right = Buffer.from(rightHex, "hex");
  if (left.length !== right.length) {
    return false;
  }
  return timingSafeEqual(left, right);
}

function createPairwiseSubject(userId: string, audience: string, secret: string): string {
  return createHmac("sha256", secret).update(`${userId}:${audience}`).digest("base64url");
}

interface ParsedRefreshToken {
  tokenId: string;
}

function parseRefreshToken(refreshToken: string): ParsedRefreshToken {
  const match = /^rt_([0-9a-fA-F-]{36})\.[A-Za-z0-9_-]{20,}$/.exec(refreshToken);
  if (!match) {
    throw new AuthServiceError("invalid_grant", 401, "Invalid refresh token");
  }
  return { tokenId: match[1].toLowerCase() };
}

interface IssueTokenInput {
  userId: string;
  clientId: string;
  audience: string;
  scope: string[];
}

interface BuildRefreshTokenResult {
  token: string;
  record: RefreshTokenRecord;
}

export class AuthService {
  private readonly accessTokenKey: Uint8Array;

  constructor(
    private readonly store: AuthStore,
    private readonly config: AuthServiceConfig
  ) {
    this.accessTokenKey = new TextEncoder().encode(config.accessTokenSecret);
  }

  async register(input: {
    email: string;
    password: string;
    clientId: string;
    audience?: string;
    scope?: string[];
  }): Promise<TokenPair> {
    const emailNormalized = normalizeEmail(input.email);
    const existing = await this.store.getUserByEmail(emailNormalized);
    if (existing) {
      throw new AuthServiceError("conflict", 409, "User already exists");
    }

    const passwordHash = await argon2.hash(input.password, {
      type: argon2.argon2id,
      memoryCost: 19_456,
      timeCost: 2,
      parallelism: 1
    });

    const user: UserRecord = {
      userId: randomUUID(),
      emailNormalized,
      passwordHash,
      createdAt: Date.now()
    };

    await this.store.insertUser(user);

    return this.issueTokenPair({
      userId: user.userId,
      clientId: input.clientId,
      audience: input.audience ?? this.config.defaultAudience,
      scope: input.scope ?? ["openid", "profile"]
    });
  }

  async login(input: {
    email: string;
    password: string;
    clientId: string;
    audience?: string;
    scope?: string[];
  }): Promise<TokenPair> {
    const emailNormalized = normalizeEmail(input.email);
    const user = await this.store.getUserByEmail(emailNormalized);

    if (!user) {
      await argon2.hash(input.password, {
        type: argon2.argon2id,
        memoryCost: 9_728,
        timeCost: 1,
        parallelism: 1
      });
      throw new AuthServiceError("invalid_grant", 401, "Invalid credentials");
    }

    const validPassword = await argon2.verify(user.passwordHash, input.password);
    if (!validPassword) {
      throw new AuthServiceError("invalid_grant", 401, "Invalid credentials");
    }

    return this.issueTokenPair({
      userId: user.userId,
      clientId: input.clientId,
      audience: input.audience ?? this.config.defaultAudience,
      scope: input.scope ?? ["openid", "profile"]
    });
  }

  async refresh(input: {
    refreshToken: string;
    clientId: string;
    audience?: string;
    scope?: string[];
  }): Promise<TokenPair> {
    const parsed = parseRefreshToken(input.refreshToken);
    const existing = await this.store.getRefreshToken(parsed.tokenId);
    const now = Date.now();

    if (!existing) {
      throw new AuthServiceError("invalid_grant", 401, "Invalid refresh token");
    }

    if (existing.clientId !== input.clientId) {
      throw new AuthServiceError("invalid_grant", 401, "Invalid refresh token");
    }

    const providedHash = hashRefreshToken(input.refreshToken, this.config.refreshTokenPepper);
    if (!safeHexEquals(existing.tokenHash, providedHash)) {
      throw new AuthServiceError("invalid_grant", 401, "Invalid refresh token");
    }

    if (existing.revokedAt || existing.expiresAt <= now) {
      throw new AuthServiceError("invalid_grant", 401, "Invalid refresh token");
    }

    if (existing.usedAt) {
      await this.store.revokeRefreshTokensForUserClient(existing.userId, existing.clientId, now, "reuse_detected");
      throw new AuthServiceError("token_reuse", 401, "Refresh token reuse detected");
    }

    const audience = input.audience ?? this.config.defaultAudience;
    const scope = input.scope ?? ["openid", "profile"];

    const newRefresh = this.buildRefreshToken(existing.userId, existing.clientId, now);
    await this.store.markRefreshTokenUsed(existing.tokenId, newRefresh.record.tokenId, now);
    await this.store.insertRefreshToken(newRefresh.record);

    const accessToken = await this.buildAccessToken({
      userId: existing.userId,
      clientId: existing.clientId,
      audience,
      scope
    });

    return {
      access_token: accessToken.token,
      token_type: "Bearer",
      expires_in: this.config.accessTokenTtlSeconds,
      refresh_token: newRefresh.token,
      subject: accessToken.subject
    };
  }

  async revoke(input: { refreshToken: string; clientId: string }): Promise<void> {
    let parsed: ParsedRefreshToken;
    try {
      parsed = parseRefreshToken(input.refreshToken);
    } catch {
      return;
    }

    const existing = await this.store.getRefreshToken(parsed.tokenId);
    if (!existing || existing.clientId !== input.clientId) {
      return;
    }

    const providedHash = hashRefreshToken(input.refreshToken, this.config.refreshTokenPepper);
    if (!safeHexEquals(existing.tokenHash, providedHash)) {
      return;
    }

    await this.store.revokeRefreshToken(existing.tokenId, Date.now(), "client_revocation");
  }

  async introspect(token: string): Promise<IntrospectionResult> {
    try {
      const verified = await jwtVerify(token, this.accessTokenKey, {
        issuer: this.config.issuer,
        algorithms: ["HS256"]
      });

      const payload = verified.payload;
      const scope = typeof payload.scope === "string" ? payload.scope.split(" ").filter(Boolean) : [];
      const aud = Array.isArray(payload.aud)
        ? payload.aud.filter((entry): entry is string => typeof entry === "string")
        : typeof payload.aud === "string"
          ? [payload.aud]
          : [];

      return {
        active: true,
        sub: typeof payload.sub === "string" ? payload.sub : undefined,
        aud,
        iss: typeof payload.iss === "string" ? payload.iss : undefined,
        exp: typeof payload.exp === "number" ? payload.exp : undefined,
        iat: typeof payload.iat === "number" ? payload.iat : undefined,
        client_id: typeof payload.client_id === "string" ? payload.client_id : undefined,
        scope
      };
    } catch {
      return { active: false };
    }
  }

  private async issueTokenPair(input: IssueTokenInput): Promise<TokenPair> {
    const now = Date.now();
    const refresh = this.buildRefreshToken(input.userId, input.clientId, now);
    await this.store.insertRefreshToken(refresh.record);

    const accessToken = await this.buildAccessToken(input);

    return {
      access_token: accessToken.token,
      token_type: "Bearer",
      expires_in: this.config.accessTokenTtlSeconds,
      refresh_token: refresh.token,
      subject: accessToken.subject
    };
  }

  private buildRefreshToken(userId: string, clientId: string, issuedAt: number): BuildRefreshTokenResult {
    const tokenId = randomUUID();
    const secret = randomBytes(32).toString("base64url");
    const token = `rt_${tokenId}.${secret}`;

    return {
      token,
      record: {
        tokenId,
        userId,
        clientId,
        tokenHash: hashRefreshToken(token, this.config.refreshTokenPepper),
        issuedAt,
        expiresAt: issuedAt + this.config.refreshTokenTtlSeconds * 1000
      }
    };
  }

  private async buildAccessToken(input: IssueTokenInput): Promise<{ token: string; subject: string }> {
    const subject = createPairwiseSubject(input.userId, input.audience, this.config.pairwiseSubjectSecret);
    const now = Math.floor(Date.now() / 1000);

    const payload: JWTPayload & { client_id: string; scope: string } = {
      sub: subject,
      aud: input.audience,
      iss: this.config.issuer,
      iat: now,
      exp: now + this.config.accessTokenTtlSeconds,
      jti: randomUUID(),
      client_id: input.clientId,
      scope: input.scope.join(" ")
    };

    const token = await new SignJWT(payload)
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .sign(this.accessTokenKey);

    return {
      token,
      subject
    };
  }
}

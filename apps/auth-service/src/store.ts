export interface UserRecord {
  userId: string;
  emailNormalized: string;
  passwordHash: string;
  createdAt: number;
}

export interface RefreshTokenRecord {
  tokenId: string;
  userId: string;
  clientId: string;
  tokenHash: string;
  issuedAt: number;
  expiresAt: number;
  usedAt?: number;
  revokedAt?: number;
  replacedByTokenId?: string;
  revokeReason?: string;
}

export interface AuthStore {
  getUserByEmail(emailNormalized: string): Promise<UserRecord | undefined>;
  getUserById(userId: string): Promise<UserRecord | undefined>;
  insertUser(user: UserRecord): Promise<void>;
  getRefreshToken(tokenId: string): Promise<RefreshTokenRecord | undefined>;
  insertRefreshToken(token: RefreshTokenRecord): Promise<void>;
  markRefreshTokenUsed(tokenId: string, replacedByTokenId: string, usedAt: number): Promise<void>;
  revokeRefreshToken(tokenId: string, revokedAt: number, reason: string): Promise<void>;
  revokeRefreshTokensForUserClient(userId: string, clientId: string, revokedAt: number, reason: string): Promise<void>;
}

export class InMemoryAuthStore implements AuthStore {
  private readonly usersByEmail = new Map<string, UserRecord>();
  private readonly usersById = new Map<string, UserRecord>();
  private readonly refreshTokens = new Map<string, RefreshTokenRecord>();

  async getUserByEmail(emailNormalized: string): Promise<UserRecord | undefined> {
    return this.usersByEmail.get(emailNormalized);
  }

  async getUserById(userId: string): Promise<UserRecord | undefined> {
    return this.usersById.get(userId);
  }

  async insertUser(user: UserRecord): Promise<void> {
    this.usersByEmail.set(user.emailNormalized, user);
    this.usersById.set(user.userId, user);
  }

  async getRefreshToken(tokenId: string): Promise<RefreshTokenRecord | undefined> {
    return this.refreshTokens.get(tokenId);
  }

  async insertRefreshToken(token: RefreshTokenRecord): Promise<void> {
    this.refreshTokens.set(token.tokenId, token);
  }

  async markRefreshTokenUsed(tokenId: string, replacedByTokenId: string, usedAt: number): Promise<void> {
    const existing = this.refreshTokens.get(tokenId);
    if (!existing) {
      return;
    }

    this.refreshTokens.set(tokenId, {
      ...existing,
      usedAt,
      replacedByTokenId
    });
  }

  async revokeRefreshToken(tokenId: string, revokedAt: number, reason: string): Promise<void> {
    const existing = this.refreshTokens.get(tokenId);
    if (!existing) {
      return;
    }

    this.refreshTokens.set(tokenId, {
      ...existing,
      revokedAt,
      revokeReason: reason
    });
  }

  async revokeRefreshTokensForUserClient(userId: string, clientId: string, revokedAt: number, reason: string): Promise<void> {
    for (const [tokenId, token] of this.refreshTokens.entries()) {
      if (token.userId !== userId || token.clientId !== clientId || token.revokedAt) {
        continue;
      }
      this.refreshTokens.set(tokenId, {
        ...token,
        revokedAt,
        revokeReason: reason
      });
    }
  }
}

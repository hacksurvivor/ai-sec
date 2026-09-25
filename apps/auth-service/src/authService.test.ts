import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { AuthService, AuthServiceError } from "./authService.js";
import { InMemoryAuthStore } from "./store.js";

function createService(): AuthService {
  return new AuthService(new InMemoryAuthStore(), {
    issuer: "https://auth.example.internal",
    defaultAudience: "gateway",
    accessTokenTtlSeconds: 300,
    refreshTokenTtlSeconds: 3600,
    accessTokenSecret: "test-access-token-secret-012345678901234567890123",
    refreshTokenPepper: "test-refresh-token-pepper-01234567890123456789012",
    pairwiseSubjectSecret: "test-pairwise-secret-0123456789012345678901234"
  });
}

describe("AuthService", () => {
  it("issues pairwise subject IDs per audience", async () => {
    const service = createService();

    const a = await service.register({
      email: "user@example.com",
      password: "SuperStrongPass!234",
      clientId: "web-app",
      audience: "gateway-a"
    });

    const b = await service.login({
      email: "user@example.com",
      password: "SuperStrongPass!234",
      clientId: "web-app",
      audience: "gateway-b"
    });

    assert.notEqual(a.subject, b.subject);

    const introspectedA = await service.introspect(a.access_token);
    const introspectedB = await service.introspect(b.access_token);

    assert.equal(introspectedA.active, true);
    assert.equal(introspectedB.active, true);
    assert.deepEqual(introspectedA.aud, ["gateway-a"]);
    assert.deepEqual(introspectedB.aud, ["gateway-b"]);
    assert.equal(introspectedA.sub, a.subject);
    assert.equal(introspectedB.sub, b.subject);
  });

  it("rotates refresh tokens and detects reuse", async () => {
    const service = createService();

    const first = await service.register({
      email: "rotate@example.com",
      password: "SuperStrongPass!234",
      clientId: "web-app"
    });

    const second = await service.refresh({
      refreshToken: first.refresh_token,
      clientId: "web-app"
    });

    assert.notEqual(first.refresh_token, second.refresh_token);

    await assert.rejects(
      service.refresh({
        refreshToken: first.refresh_token,
        clientId: "web-app"
      }),
      (error: unknown) => {
        assert.ok(error instanceof AuthServiceError);
        assert.equal(error.code, "token_reuse");
        return true;
      }
    );

    await assert.rejects(
      service.refresh({
        refreshToken: second.refresh_token,
        clientId: "web-app"
      }),
      (error: unknown) => {
        assert.ok(error instanceof AuthServiceError);
        assert.equal(error.code, "invalid_grant");
        return true;
      }
    );
  });

  it("rejects invalid credentials and duplicate registration", async () => {
    const service = createService();

    await service.register({
      email: "duplicate@example.com",
      password: "SuperStrongPass!234",
      clientId: "web-app"
    });

    await assert.rejects(
      service.login({
        email: "duplicate@example.com",
        password: "WrongPassword123",
        clientId: "web-app"
      }),
      (error: unknown) => {
        assert.ok(error instanceof AuthServiceError);
        assert.equal(error.code, "invalid_grant");
        return true;
      }
    );

    await assert.rejects(
      service.register({
        email: "duplicate@example.com",
        password: "SuperStrongPass!234",
        clientId: "web-app"
      }),
      (error: unknown) => {
        assert.ok(error instanceof AuthServiceError);
        assert.equal(error.code, "conflict");
        return true;
      }
    );
  });

  it("returns inactive for malformed tokens", async () => {
    const service = createService();
    const introspection = await service.introspect("not-a-real-token");
    assert.deepEqual(introspection, { active: false });
  });
});

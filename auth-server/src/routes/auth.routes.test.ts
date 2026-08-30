import express from "express";
import { createHash } from "node:crypto";
import jwt from "jsonwebtoken";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

process.env["DATABASE_URL"] = "postgresql://user:password@localhost:5432/auth_db";
process.env["JWT_REFRESH_SECRET"] = "test-refresh-secret-long";
process.env["JWT_ISSUER"] = "https://auth.temis.co.kr";
process.env["JWT_AUDIENCE"] = "temis";
process.env["FRONTEND_REDIRECT_URL"] = "http://localhost:3000/auth/callback";
process.env["GOOGLE_CLIENT_ID"] = "google";
process.env["GOOGLE_CLIENT_SECRET"] = "google-secret";
process.env["GOOGLE_REDIRECT_URI"] = "http://localhost:4000/auth/google/callback";
process.env["NAVER_CLIENT_ID"] = "naver";
process.env["NAVER_CLIENT_SECRET"] = "naver-secret";
process.env["NAVER_REDIRECT_URI"] = "http://localhost:4000/auth/naver/callback";
process.env["KAKAO_CLIENT_ID"] = "kakao";
process.env["KAKAO_CLIENT_SECRET"] = "kakao-secret";
process.env["KAKAO_REDIRECT_URI"] = "http://localhost:4000/auth/kakao/callback";
process.env["CORS_ALLOWED_ORIGINS"] = "http://localhost:3000";
process.env["AUTH_RATE_LIMIT_WINDOW_SECONDS"] = "60";
process.env["AUTH_RATE_LIMIT_MAX_REQUESTS"] = "2";
process.env["AUTH_CLIENTS_JSON"] = JSON.stringify([
  {
    clientId: "temis",
    audience: "temis",
    allowedRedirectUris: ["https://financenow.kr/auth/callback", "https://temis.me/auth/callback", "https://ti.temis.me/auth/callback"],
    allowedOrigins: ["https://financenow.kr"],
    defaultRole: { serviceKey: "temis", name: "user" }
  }
]);

const loginWithPassword = vi.fn();
const issueTokenPair = vi.fn();
const refreshAccessToken = vi.fn();
const rotateRefreshToken = vi.fn();
const recordAuthAuditEvent = vi.fn();
const recordLoginFailureAuditEvent = vi.fn();
const findAuditUserIdByEmail = vi.fn();
const findAuditUserIdByPasswordEmail = vi.fn();
const createAuthHandoff = vi.fn();
const tokenTransaction = vi.fn();
const rateLimitCounts = new Map<string, number>();
const temisRedirectUri = "https://financenow.kr/auth/callback";
const validCodeVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const validCodeChallenge = createHash("sha256").update(validCodeVerifier).digest("base64url");
const temisCallerState = "R_sz-vF_74ssoStateBase64urlExactly43Chars";

vi.mock("../services/password-auth.service.js", () => ({
  loginWithPassword
}));

vi.mock("@prisma/client", () => ({
  PrismaClient: vi.fn(function PrismaClient() {
    return {
      $transaction: tokenTransaction
    };
  })
}));

vi.mock("../services/password-auth.store.js", () => ({
  passwordAuthStore: {}
}));

vi.mock("../services/token.service.js", () => ({
  issueTokenPair,
  refreshAccessToken,
  rotateRefreshToken,
  revokeRefreshToken: vi.fn()
}));

vi.mock("../services/auth-handoff.store.js", () => ({
  authHandoffStore: {
    create: createAuthHandoff,
    consume: vi.fn()
  }
}));

vi.mock("../services/redis.client.js", () => ({
  redisTtlStoreClient: {
    incrementWithTtl: vi.fn(async (key: string) => {
      const next = (rateLimitCounts.get(key) ?? 0) + 1;
      rateLimitCounts.set(key, next);
      return next;
    })
  }
}));

vi.mock("../services/audit.service.js", () => ({
  auditContextFromRequest: vi.fn(() => ({})),
  auditEventTypes: {
    registerRequest: "register_request",
    loginSuccess: "login_success",
    loginFailure: "login_failure",
    lockout: "lockout",
    emailVerificationRequest: "email_verification_request",
    emailVerificationConfirm: "email_verification_confirm",
    passwordResetRequest: "password_reset_request",
    passwordResetConfirm: "password_reset_confirm",
    refresh: "refresh",
    logout: "logout",
    authHandoffExchangeSuccess: "auth_handoff_exchange_success",
    authHandoffExchangeFailure: "auth_handoff_exchange_failure",
    rateLimitExceeded: "rate_limit_exceeded"
  },
  recordAuthAuditEvent,
  recordLoginFailureAuditEvent
}));

vi.mock("../services/audit.store.js", () => ({
  auditLogStore: {
    create: vi.fn(),
    findUserIdByEmail: findAuditUserIdByEmail,
    findUserIdByPasswordEmail: findAuditUserIdByPasswordEmail
  }
}));

describe("auth password routes", () => {
  beforeEach(() => {
    vi.resetModules();
    loginWithPassword.mockReset();
    issueTokenPair.mockReset();
    refreshAccessToken.mockReset();
    rotateRefreshToken.mockReset();
    createAuthHandoff.mockReset();
    tokenTransaction.mockReset();
    recordAuthAuditEvent.mockReset();
    recordLoginFailureAuditEvent.mockReset();
    findAuditUserIdByEmail.mockReset();
    findAuditUserIdByPasswordEmail.mockReset();
    rateLimitCounts.clear();
  });

  it("Given a valid refresh token When POST /auth/refresh succeeds Then it records a success audit event with the rotated user id", async () => {
    const { authRouter } = await import("./auth.routes.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    rotateRefreshToken.mockResolvedValue({
      tokens: { accessToken: "new-access-token", refreshToken: "new-refresh-token" },
      userId: "auth-user-1"
    });

    const response = await request(app)
      .post("/auth/refresh")
      .send({ refreshToken: "raw-refresh-token" });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ accessToken: "new-access-token", refreshToken: "new-refresh-token" });
    expect(recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "refresh",
      outcome: "success",
      userId: "auth-user-1"
    });
  });

  it("Given valid company credentials When POST /auth/login is called Then it returns token pair", async () => {
    const { authRouter } = await import("./auth.routes.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    loginWithPassword.mockResolvedValue({ user: { id: "user-1" } });
    issueTokenPair.mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" });

    const response = await request(app)
      .post("/auth/login")
      .send({ email: "user@company.com", password: "correct-password-123" });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ accessToken: "access-token", refreshToken: "refresh-token" });
    expect(loginWithPassword).toHaveBeenCalledWith({}, {
      email: "user@company.com",
      password: "correct-password-123"
    });
    expect(issueTokenPair).toHaveBeenCalledWith("user-1");
  });

  it("Given valid company credentials with TEMIS handoff When POST /auth/login is called Then it returns a redirect URL with code and original state only", async () => {
    const { authRouter } = await import("./auth.routes.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    loginWithPassword.mockResolvedValue({ user: { id: "user-1" } });
    createAuthHandoff.mockResolvedValue("handoff-code-1");

    const response = await request(app)
      .post("/auth/login")
      .send({
        email: "user@company.com",
        password: "correct-password-123",
        clientId: "temis",
        redirectUri: temisRedirectUri,
        state: temisCallerState,
        codeChallenge: validCodeChallenge,
        codeChallengeMethod: "S256"
      });

    expect(response.status).toBe(200);
    const redirectUrl = new URL(response.body.redirectUrl);
    expect(redirectUrl.toString()).toBe(`${temisRedirectUri}?code=handoff-code-1&state=${temisCallerState}`);
    expect(redirectUrl.searchParams.get("accessToken")).toBeNull();
    expect(redirectUrl.searchParams.get("refreshToken")).toBeNull();
    expect(issueTokenPair).not.toHaveBeenCalled();
    expect(createAuthHandoff).toHaveBeenCalledWith({
      clientId: "temis",
      audience: "temis",
      redirectUri: temisRedirectUri,
      userId: "user-1",
      loginMethod: "password",
      codeChallenge: validCodeChallenge,
      codeChallengeMethod: "S256",
      state: temisCallerState
    });
  });

  it("Given valid company credentials with an unregistered redirect When POST /auth/login is called Then it rejects before creating a handoff", async () => {
    const { authRouter } = await import("./auth.routes.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    loginWithPassword.mockResolvedValue({ user: { id: "user-1" } });

    const response = await request(app)
      .post("/auth/login")
      .send({
        email: "user@company.com",
        password: "correct-password-123",
        clientId: "temis",
        redirectUri: "https://evil.example/callback",
        state: temisCallerState,
        codeChallenge: validCodeChallenge,
        codeChallengeMethod: "S256"
      });

    expect(response.status).toBe(400);
    expect(createAuthHandoff).not.toHaveBeenCalled();
  });

  it("Given repeated auth requests from one client When POST /auth/login exceeds the threshold Then it returns 429", async () => {
    vi.resetModules();
    const { authRouter } = await import("./auth.routes.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    loginWithPassword.mockResolvedValue({ user: { id: "user-1" } });
    issueTokenPair.mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" });

    const firstResponse = await request(app)
      .post("/auth/login")
      .send({ email: "user@company.com", password: "correct-password-123" });
    const secondResponse = await request(app)
      .post("/auth/login")
      .send({ email: "user@company.com", password: "correct-password-123" });
    const thirdResponse = await request(app)
      .post("/auth/login")
      .send({ email: "user@company.com", password: "correct-password-123" });

    expect(firstResponse.status).toBe(200);
    expect(secondResponse.status).toBe(200);
    expect(thirdResponse.status).toBe(429);
    expect(thirdResponse.body).toEqual({
      error: {
        code: "RATE_LIMITED",
        message: "Too many authentication requests"
      }
    });
  });

  it("Given an invalid refresh token When POST /auth/refresh fails Then it records a generic failure audit event", async () => {
    const { authRouter } = await import("./auth.routes.js");
    const { HttpError } = await import("../utils/httpError.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    app.use((error: unknown, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
      if (error instanceof HttpError) {
        response.status(error.statusCode).json({ error: { code: error.code, message: error.message } });
        return;
      }

      response.status(500).json({ error: { code: "INTERNAL_ERROR", message: "Internal server error" } });
    });
    rotateRefreshToken.mockRejectedValue(
      new HttpError(401, "INVALID_REFRESH_TOKEN", "Invalid refresh token")
    );

    const response = await request(app)
      .post("/auth/refresh")
      .send({ refreshToken: "raw-refresh-token" });

    expect(response.status).toBe(401);
    expect(response.body).toEqual({
      error: {
        code: "INVALID_REFRESH_TOKEN",
        message: "Invalid refresh token"
      }
    });
    expect(recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "refresh",
      outcome: "failure",
      userId: null,
      reasonCode: "REFRESH_FAILED"
    });
    expect(recordAuthAuditEvent).not.toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      refreshToken: "raw-refresh-token"
    }));
  });

  it.each([
    ["HS384", () => jwt.sign(
      { sub: "auth-user-1", type: "refresh", tokenId: "refresh-token-id" },
      "test-refresh-secret-long",
      { algorithm: "HS384", expiresIn: "30d" }
    )],
    ["HS512", () => jwt.sign(
      { sub: "auth-user-1", type: "refresh", tokenId: "refresh-token-id" },
      "test-refresh-secret-long",
      { algorithm: "HS512", expiresIn: "30d" }
    )],
    ["none", () => {
      const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
      const payload = Buffer.from(JSON.stringify({
        sub: "auth-user-1",
        type: "refresh",
        tokenId: "refresh-token-id"
      })).toString("base64url");
      return `${header}.${payload}.`;
    }],
    ["RS256", () => jwt.sign(
      { sub: "auth-user-1", type: "refresh", tokenId: "refresh-token-id" },
      process.env["JWT_ACCESS_PRIVATE_KEY"]?.replace(/\\n/g, "\n") ?? "",
      { algorithm: "RS256", expiresIn: "30d" }
    )],
    ["HS256 access type", () => jwt.sign(
      { sub: "auth-user-1", type: "access", tokenId: "refresh-token-id" },
      "test-refresh-secret-long",
      { algorithm: "HS256", expiresIn: "30d" }
    )],
    ["malformed", () => "not-a-jwt"]
  ])("Given an actual %s refresh token When POST /auth/refresh is called Then it returns the generic 401 envelope and audits once without a token DB transaction", async (_algorithm, createToken) => {
    const actualTokenService = await vi.importActual<typeof import("../services/token.service.js")>(
      "../services/token.service.js"
    );
    rotateRefreshToken.mockImplementation(actualTokenService.rotateRefreshToken);
    const { authRouter } = await import("./auth.routes.js");
    const { HttpError } = await import("../utils/httpError.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    app.use((error: unknown, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
      if (error instanceof HttpError) {
        response.status(error.statusCode).json({ error: { code: error.code, message: error.message } });
        return;
      }

      response.status(500).json({ error: { code: "INTERNAL_SERVER_ERROR", message: "Internal server error" } });
    });

    const response = await request(app)
      .post("/auth/refresh")
      .send({ refreshToken: createToken() });

    expect(response.status).toBe(401);
    expect(response.body).toEqual({
      error: {
        code: "INVALID_REFRESH_TOKEN",
        message: "Invalid refresh token"
      }
    });
    expect(recordAuthAuditEvent).toHaveBeenCalledTimes(1);
    expect(recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "refresh",
      outcome: "failure",
      userId: null,
      reasonCode: "REFRESH_FAILED"
    });
    expect(tokenTransaction).not.toHaveBeenCalled();
  });
});

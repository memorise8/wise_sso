// allow: SIZE_OK - end-to-end auth flow interactions stay together for P0; split deferred to post-P0 test-structure cleanup while full and focused tests prevent false confidence.
import request from "supertest";
import { generateKeyPairSync } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  registerWithPassword: vi.fn(),
  loginWithPassword: vi.fn(),
  issueTokenPair: vi.fn(),
  verifyAccessToken: vi.fn(),
  getCurrentUser: vi.fn(),
  requestEmailVerification: vi.fn(),
  confirmEmailVerification: vi.fn(),
  requestPasswordReset: vi.fn(),
  confirmPasswordReset: vi.fn(),
  refreshAccessToken: vi.fn(),
  rotateRefreshToken: vi.fn(),
  revokeRefreshToken: vi.fn(),
  recordAuthAuditEvent: vi.fn(),
  recordLoginFailureAuditEvent: vi.fn(),
  findUserIdByEmail: vi.fn(),
  findUserIdByPasswordEmail: vi.fn(),
  getCurrentUserWithStatus: vi.fn(),
  consumeAuthHandoff: vi.fn(),
  createAuthHandoff: vi.fn()
}));

vi.mock("../services/password-auth.service.js", () => ({
  registerWithPassword: mocks.registerWithPassword,
  loginWithPassword: mocks.loginWithPassword,
  isPasswordAuthFailure: vi.fn(() => false)
}));

vi.mock("../services/token.service.js", () => ({
  issueTokenPair: mocks.issueTokenPair,
  verifyAccessToken: mocks.verifyAccessToken,
  refreshAccessToken: mocks.refreshAccessToken,
  rotateRefreshToken: mocks.rotateRefreshToken,
  revokeRefreshToken: mocks.revokeRefreshToken
}));

vi.mock("../services/user.service.js", () => ({
  getCurrentUser: mocks.getCurrentUser,
  getCurrentUserWithStatus: mocks.getCurrentUserWithStatus,
  findOrCreateUserBySocialProfile: vi.fn()
}));

vi.mock("../services/email-verification.service.js", () => ({
  requestEmailVerification: mocks.requestEmailVerification,
  confirmEmailVerification: mocks.confirmEmailVerification
}));

vi.mock("../services/password-reset.service.js", () => ({
  requestPasswordReset: mocks.requestPasswordReset,
  confirmPasswordReset: mocks.confirmPasswordReset
}));

vi.mock("../services/audit.service.js", () => ({
  auditContextFromRequest: vi.fn(() => ({ ipAddress: "127.0.0.1", userAgent: "supertest" })),
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
  recordAuthAuditEvent: mocks.recordAuthAuditEvent,
  recordLoginFailureAuditEvent: mocks.recordLoginFailureAuditEvent
}));

vi.mock("../services/audit.store.js", () => ({
  auditLogStore: {
    create: vi.fn(),
    findUserIdByEmail: mocks.findUserIdByEmail,
    findUserIdByPasswordEmail: mocks.findUserIdByPasswordEmail
  }
}));

vi.mock("../services/password-auth.store.js", () => ({ passwordAuthStore: {} }));
vi.mock("../services/email-verification.store.js", () => ({ emailVerificationStore: {} }));
vi.mock("../services/password-reset.store.js", () => ({ passwordResetStore: {} }));
vi.mock("../services/mail.service.js", () => ({
  createMailService: () => ({
    sendEmailVerification: vi.fn(),
    sendPasswordReset: vi.fn()
  })
}));

vi.mock("../services/oauth-state.store.js", () => ({
  oauthStateStore: {
    create: async (): Promise<string> => "oauth-state-for-route-test-000000000000000000000000",
    consume: async (): Promise<boolean> => false
  }
}));

vi.mock("../services/auth-handoff.store.js", () => ({
  authHandoffStore: {
    create: mocks.createAuthHandoff,
    consume: mocks.consumeAuthHandoff
  }
}));

const setRequiredEnv = (maxRequests: string): void => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001
  });
  const publicJwk = publicKey.export({ format: "jwk" });
  if (publicJwk.kty !== "RSA" || typeof publicJwk.n !== "string" || typeof publicJwk.e !== "string") {
    throw new Error("Generated RSA key did not export a public JWK");
  }
  process.env["NODE_ENV"] = "test";
  process.env["DATABASE_URL"] = "postgresql://user:password@localhost:5432/auth_db";
  process.env["JWT_ACCESS_ALGORITHM"] = "RS256";
  process.env["JWT_ACCESS_PRIVATE_KEY"] = privateKey.export({ format: "pem", type: "pkcs8" }).toString().replace(/\n/g, "\\n");
  process.env["JWT_ACCESS_PUBLIC_JWK"] = JSON.stringify({
    kty: "RSA",
    n: publicJwk.n,
    e: publicJwk.e,
    alg: "RS256",
    use: "sig",
    kid: "temis-access-key-1"
  });
  process.env["JWT_ACCESS_KEY_ID"] = "temis-access-key-1";
  process.env["JWT_REFRESH_SECRET"] = "test-refresh-secret-long";
  process.env["JWT_ISSUER"] = "https://auth.temis.co.kr";
  process.env["JWT_AUDIENCE"] = "temis";
  process.env["REDIS_URL"] = "redis://localhost:6379";
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
  process.env["AUTH_RATE_LIMIT_MAX_REQUESTS"] = maxRequests;
  process.env["AUTH_CLIENTS_JSON"] = JSON.stringify([
    {
      clientId: "temis",
      audience: "temis",
      allowedRedirectUris: ["https://financenow.kr/auth/callback"],
      allowedOrigins: ["https://financenow.kr"],
      defaultRole: { serviceKey: "temis", name: "pending" }
    }
  ]);
};

const validPkceQuery = {
  client_id: "temis",
  redirect_uri: "https://financenow.kr/auth/callback",
  state: "qa-state",
  code_challenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
  code_challenge_method: "S256"
} as const;

const resetMocks = (): void => {
  for (const mock of Object.values(mocks)) {
    mock.mockReset();
  }
};

const loadApp = async (maxRequests = "20") => {
  vi.resetModules();
  setRequiredEnv(maxRequests);
  return import("../app.js");
};

describe("auth flow route QA", () => {
  beforeEach(() => {
    resetMocks();
  });

  it("Given a password user flow When register verify login and fetch me run through HTTP Then the app returns the current user", async () => {
    const { app } = await loadApp();
    const { HttpError } = await import("../utils/httpError.js");
    const user = { id: "user-1", email: "person@example.com", emailVerified: true, name: "Person", roles: ["user"] };
    const userResponse = { id: "user-1", email: "person@example.com", email_verified: true, name: "Person", roles: ["user"] };
    mocks.registerWithPassword.mockResolvedValue({ user });
    mocks.requestEmailVerification.mockResolvedValue({ status: "accepted" });
    mocks.confirmEmailVerification.mockResolvedValue({ status: "verified", userId: user.id });
    mocks.loginWithPassword
      .mockRejectedValueOnce(new HttpError(401, "INVALID_CREDENTIALS", "Invalid email or password"))
      .mockResolvedValueOnce({ user });
    mocks.issueTokenPair.mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" });
    mocks.verifyAccessToken.mockReturnValue("user-1");
    mocks.getCurrentUser.mockResolvedValue(user);
    mocks.getCurrentUserWithStatus.mockResolvedValue({ ...user, status: "ACTIVE" });

    const register = await request(app).post("/auth/register").send({
      email: "person@example.com",
      password: "correct-password-123",
      name: "Person"
    });
    const loginBeforeVerification = await request(app)
      .post("/auth/login")
      .send({ email: "person@example.com", password: "correct-password-123" });
    const verificationRequest = await request(app)
      .post("/auth/email-verification/request")
      .send({ email: "person@example.com" });
    const verificationConfirm = await request(app)
      .post("/auth/email-verification/confirm")
      .send({ token: "verification-token" });
    const login = await request(app)
      .post("/auth/login")
      .send({ email: "person@example.com", password: "correct-password-123" });
    const me = await request(app).get("/users/me").set("Authorization", "Bearer access-token");

    expect(register.status).toBe(202);
    expect(register.body).toEqual({ status: "accepted" });
    expect(loginBeforeVerification.status).toBe(401);
    expect(loginBeforeVerification.body).toEqual({
      error: {
        code: "INVALID_CREDENTIALS",
        message: "Invalid email or password"
      }
    });
    expect(verificationRequest.status).toBe(202);
    expect(verificationConfirm.status).toBe(200);
    expect(login.status).toBe(200);
    expect(login.body).toEqual({ accessToken: "access-token", refreshToken: "refresh-token" });
    expect(me.status).toBe(200);
    expect(me.body).toEqual(userResponse);
    expect(mocks.recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), expect.not.objectContaining({
      password: "correct-password-123"
    }));
  });

  it("Given a still-cryptographically-valid access token for a suspended user When GET /users/me runs through HTTP Then the DB-backed read is rejected", async () => {
    const { app } = await loadApp();
    mocks.verifyAccessToken.mockReturnValue("user-1");
    mocks.getCurrentUser.mockResolvedValue({
      id: "user-1",
      email: "person@example.com",
      name: "Person",
      roles: ["user"]
    });
    mocks.getCurrentUserWithStatus.mockResolvedValue({
      id: "user-1",
      email: "person@example.com",
      name: "Person",
      roles: ["user"],
      status: "SUSPENDED"
    });

    const response = await request(app).get("/users/me").set("Authorization", "Bearer access-token");

    expect(response.status).toBe(401);
    expect(response.body).toEqual({
      error: {
        code: "UNAUTHORIZED",
        message: "Authentication is required"
      }
    });
  });

  it("Given a handoff code for a deleted user When POST /auth/exchange runs through HTTP Then token return is rejected", async () => {
    const { app } = await loadApp();
    mocks.consumeAuthHandoff.mockResolvedValue({
      clientId: "temis",
      audience: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      userId: "user-1",
      provider: "google",
      loginMethod: "oauth",
      codeChallenge: "challenge",
      codeChallengeMethod: "S256",
      state: null,
      expiresAtEpochMs: Date.now() + 60_000
    });
    const { HttpError } = await import("../utils/httpError.js");
    mocks.issueTokenPair.mockRejectedValue(new HttpError(401, "UNAUTHORIZED", "Authentication is required"));

    const response = await request(app).post("/auth/exchange").send({
      code: "handoff-code",
      clientId: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      codeVerifier: "code-verifier"
    });

    expect(response.status).toBe(401);
    expect(response.body).toEqual({
      error: {
        code: "UNAUTHORIZED",
        message: "Authentication is required"
      }
    });
    expect(response.body).not.toHaveProperty("accessToken");
    expect(response.body).not.toHaveProperty("refreshToken");
    expect(mocks.issueTokenPair).toHaveBeenCalledWith("user-1", { audience: "temis" });
    expect(mocks.recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "auth_handoff_exchange_failure",
      outcome: "failure",
      userId: "user-1",
      ipAddress: "127.0.0.1",
      userAgent: "supertest",
      provider: "google",
      reasonCode: "UNAUTHORIZED",
      detailsJson: {
        route: "/auth/exchange",
        clientId: "temis"
      }
    });
    expect(JSON.stringify(mocks.recordAuthAuditEvent.mock.calls)).not.toContain("handoff-code");
    expect(JSON.stringify(mocks.recordAuthAuditEvent.mock.calls)).not.toContain("code-verifier");
  });

  it("Given invalid reset token and blocked browser origin When HTTP requests run Then failures stay generic and CORS stays blocked", async () => {
    const { app } = await loadApp();
    const { HttpError } = await import("../utils/httpError.js");
    mocks.confirmPasswordReset.mockRejectedValue(
      new HttpError(400, "INVALID_RESET_TOKEN", "Invalid or expired reset token")
    );

    const invalidReset = await request(app)
      .post("/auth/password-reset/confirm")
      .send({ token: "bad-token", password: "new-password-123" });
    const blockedCors = await request(app)
      .get("/auth/google")
      .query(validPkceQuery)
      .set("Origin", "https://evil.example");

    expect(invalidReset.status).toBe(400);
    expect(invalidReset.body).toEqual({
      error: {
        code: "INVALID_RESET_TOKEN",
        message: "Invalid or expired reset token"
      }
    });
    expect(blockedCors.status).toBe(302);
    expect(blockedCors.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("Given repeated login requests When the auth rate limit is exceeded Then later requests return 429", async () => {
    const { app } = await loadApp("2");
    const user = { id: "user-1", email: "person@example.com", name: "Person", roles: ["user"] };
    mocks.loginWithPassword.mockResolvedValue({ user });
    mocks.issueTokenPair.mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" });

    const first = await request(app).post("/auth/login").send({ email: user.email, password: "correct-password-123" });
    const second = await request(app).post("/auth/login").send({ email: user.email, password: "correct-password-123" });
    const third = await request(app).post("/auth/login").send({ email: user.email, password: "correct-password-123" });

    expect(first.status).toBe(200);
    expect(second.status).toBe(200);
    expect(third.status).toBe(429);
    expect(third.body).toEqual({
      error: {
        code: "RATE_LIMITED",
        message: "Too many authentication requests"
      }
    });
    expect(mocks.recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "rate_limit_exceeded",
      outcome: "failure",
      userId: null,
      ipAddress: "127.0.0.1",
      userAgent: "supertest",
      reasonCode: "RATE_LIMITED",
      detailsJson: {
        route: "/auth/login",
        method: "POST",
        maxRequests: 2,
        windowSeconds: 60,
        retryAfterSeconds: 60
      }
    });
    expect(JSON.stringify(mocks.recordAuthAuditEvent.mock.calls)).not.toContain("correct-password-123");
  });
});

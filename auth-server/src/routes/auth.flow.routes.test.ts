import request from "supertest";
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
  findUserIdByPasswordEmail: vi.fn()
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
    logout: "logout"
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

const setRequiredEnv = (maxRequests: string): void => {
  process.env["NODE_ENV"] = "test";
  process.env["DATABASE_URL"] = "postgresql://user:password@localhost:5432/auth_db";
  process.env["JWT_ACCESS_SECRET"] = "test-access-secret-long";
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
  process.env["AUTH_RATE_LIMIT_MAX_REQUESTS"] = maxRequests;
};

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
    const user = { id: "user-1", email: "person@example.com", name: "Person", roles: ["user"] };
    mocks.registerWithPassword.mockResolvedValue({ user });
    mocks.requestEmailVerification.mockResolvedValue({ status: "accepted" });
    mocks.confirmEmailVerification.mockResolvedValue({ status: "verified", userId: user.id });
    mocks.loginWithPassword
      .mockRejectedValueOnce(new HttpError(401, "INVALID_CREDENTIALS", "Invalid email or password"))
      .mockResolvedValueOnce({ user });
    mocks.issueTokenPair.mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" });
    mocks.verifyAccessToken.mockReturnValue("user-1");
    mocks.getCurrentUser.mockResolvedValue(user);

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
    expect(me.body).toEqual(user);
    expect(mocks.recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), expect.not.objectContaining({
      password: "correct-password-123"
    }));
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
    const blockedCors = await request(app).get("/auth/google").set("Origin", "https://evil.example");

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
  });
});

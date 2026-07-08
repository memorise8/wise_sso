import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

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
process.env["AUTH_RATE_LIMIT_MAX_REQUESTS"] = "2";

const loginWithPassword = vi.fn();
const issueTokenPair = vi.fn();
const refreshAccessToken = vi.fn();
const rotateRefreshToken = vi.fn();
const recordAuthAuditEvent = vi.fn();
const recordLoginFailureAuditEvent = vi.fn();
const findAuditUserIdByEmail = vi.fn();
const findAuditUserIdByPasswordEmail = vi.fn();

vi.mock("../services/password-auth.service.js", () => ({
  loginWithPassword
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
    logout: "logout"
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
    recordAuthAuditEvent.mockReset();
    recordLoginFailureAuditEvent.mockReset();
    findAuditUserIdByEmail.mockReset();
    findAuditUserIdByPasswordEmail.mockReset();
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
});

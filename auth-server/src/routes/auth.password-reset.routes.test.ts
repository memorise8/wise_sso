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
process.env["AUTH_RATE_LIMIT_MAX_REQUESTS"] = "20";

const requestPasswordReset = vi.fn();
const confirmPasswordReset = vi.fn();
const recordAuthAuditEvent = vi.fn();
const recordLoginFailureAuditEvent = vi.fn();
const findAuditUserIdByPasswordEmail = vi.fn();

vi.mock("../services/password-reset.service.js", () => ({
  requestPasswordReset,
  confirmPasswordReset
}));

vi.mock("../services/password-reset.store.js", () => ({
  passwordResetStore: {}
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
    findUserIdByEmail: vi.fn(),
    findUserIdByPasswordEmail: findAuditUserIdByPasswordEmail
  }
}));

vi.mock("../services/mail.service.js", () => ({
  createMailService: () => ({ sendPasswordReset: vi.fn() })
}));

describe("auth password reset routes", () => {
  beforeEach(() => {
    requestPasswordReset.mockReset();
    confirmPasswordReset.mockReset();
    recordAuthAuditEvent.mockReset();
    recordLoginFailureAuditEvent.mockReset();
    findAuditUserIdByPasswordEmail.mockReset();
  });

  it("Given a reset request email When POST /auth/password-reset/request is called Then it returns the generic accepted response", async () => {
    const { authRouter } = await import("./auth.routes.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    requestPasswordReset.mockResolvedValue({ status: "accepted" });

    const response = await request(app)
      .post("/auth/password-reset/request")
      .send({ email: "User@Company.com" });

    expect(response.status).toBe(202);
    expect(response.body).toEqual({ status: "accepted" });
    expect(requestPasswordReset).toHaveBeenCalledWith({}, expect.objectContaining({
      sendPasswordReset: expect.any(Function)
    }), {
      email: "User@Company.com",
      resetUrlBase: "http://localhost:3000/password-reset"
    });
  });

  it("Given a reset token and new password When POST /auth/password-reset/confirm is called Then it confirms the reset", async () => {
    const { authRouter } = await import("./auth.routes.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    confirmPasswordReset.mockResolvedValue({ userId: "user-1" });

    const response = await request(app)
      .post("/auth/password-reset/confirm")
      .send({ token: "reset-token", password: "new-password-123" });

    expect(response.status).toBe(204);
    expect(response.body).toEqual({});
    expect(confirmPasswordReset).toHaveBeenCalledWith({}, {
      token: "reset-token",
      password: "new-password-123"
    }, {
      minLength: 12,
      allowedEmailDomain: null
    });
    expect(recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "password_reset_confirm",
      outcome: "success",
      userId: "user-1"
    });
  });

  it("Given an invalid reset token When POST /auth/password-reset/confirm fails Then it records a generic failure audit event", async () => {
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
    confirmPasswordReset.mockRejectedValue(
      new HttpError(400, "INVALID_RESET_TOKEN", "Invalid or expired reset token")
    );

    const response = await request(app)
      .post("/auth/password-reset/confirm")
      .send({ token: "raw-reset-token", password: "new-password-123" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        code: "INVALID_RESET_TOKEN",
        message: "Invalid or expired reset token"
      }
    });
    expect(recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "password_reset_confirm",
      outcome: "failure",
      userId: null,
      reasonCode: "INVALID_RESET_TOKEN"
    });
    expect(recordAuthAuditEvent).not.toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      password: "new-password-123"
    }));
    expect(recordAuthAuditEvent).not.toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      token: "raw-reset-token"
    }));
  });
});

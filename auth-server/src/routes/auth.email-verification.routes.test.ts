import express from "express";
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

const requestEmailVerification = vi.fn();
const confirmEmailVerification = vi.fn();
const recordAuthAuditEvent = vi.fn();
const recordLoginFailureAuditEvent = vi.fn();
const findAuditUserIdByEmail = vi.fn();
const findAuditUserIdByPasswordEmail = vi.fn();
const createAuthHandoff = vi.fn();
const rateLimitCounts = new Map<string, number>();

vi.mock("../services/email-verification.service.js", () => ({
  requestEmailVerification,
  confirmEmailVerification
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

vi.mock("../services/auth-handoff.store.js", () => ({
  authHandoffStore: {
    create: createAuthHandoff
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

describe("auth email verification routes", () => {
  beforeEach(() => {
    vi.resetModules();
    requestEmailVerification.mockReset();
    confirmEmailVerification.mockReset();
    recordAuthAuditEvent.mockReset();
    recordLoginFailureAuditEvent.mockReset();
    findAuditUserIdByEmail.mockReset();
    findAuditUserIdByPasswordEmail.mockReset();
    createAuthHandoff.mockReset();
    rateLimitCounts.clear();
  });

  it("Given any valid email When POST /auth/email-verification/request is called Then it returns a generic accepted response", async () => {
    const { authRouter } = await import("./auth.routes.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    requestEmailVerification.mockResolvedValue({ status: "accepted" });

    const response = await request(app)
      .post("/auth/email-verification/request")
      .send({ email: "person@gmail.com" });

    expect(response.status).toBe(202);
    expect(response.body).toEqual({ status: "accepted" });
    expect(requestEmailVerification).toHaveBeenCalledWith(expect.objectContaining({
      input: { email: "person@gmail.com" }
    }));
  });

  it("Given TEMIS PKCE metadata When verification email is requested Then the handoff binding is stored with the token request", async () => {
    const { authRouter } = await import("./auth.routes.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    requestEmailVerification.mockResolvedValue({ status: "accepted" });

    const response = await request(app)
      .post("/auth/email-verification/request")
      .send({
        email: "person@gmail.com",
        clientId: "temis",
        redirectUri: "https://financenow.kr/auth/callback",
        state: "caller-state",
        codeChallenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        codeChallengeMethod: "S256"
      });

    expect(response.status).toBe(202);
    expect(requestEmailVerification).toHaveBeenCalledWith(expect.objectContaining({
      input: {
        email: "person@gmail.com",
        handoff: {
          clientId: "temis",
          audience: "temis",
          redirectUri: "https://financenow.kr/auth/callback",
          state: "caller-state",
          codeChallenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
          codeChallengeMethod: "S256"
        }
      }
    }));
  });

  it("Given a malformed verification request When POST /auth/email-verification/request is called Then it returns invalid request", async () => {
    const { authRouter } = await import("./auth.routes.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    app.use((error: unknown, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
      response.status(400).json({ error: { code: "INVALID_REQUEST", message: "Invalid request" } });
    });

    const response = await request(app)
      .post("/auth/email-verification/request")
      .send({ email: "not-an-email" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        code: "INVALID_REQUEST",
        message: "Invalid request"
      }
    });
    expect(requestEmailVerification).not.toHaveBeenCalled();
  });

  it("Given a token When POST /auth/email-verification/confirm is called Then it returns verified", async () => {
    const { authRouter } = await import("./auth.routes.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    confirmEmailVerification.mockResolvedValue({ status: "verified", userId: "user-1" });

    const response = await request(app)
      .post("/auth/email-verification/confirm")
      .send({ token: "raw-verification-token" });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: "verified" });
    expect(confirmEmailVerification).toHaveBeenCalledWith(expect.objectContaining({
      input: { token: "raw-verification-token" }
    }));
    expect(recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "email_verification_confirm",
      outcome: "success",
      userId: "user-1"
    });
  });

  it("Given a verified TEMIS signup handoff When POST /auth/email-verification/confirm succeeds Then it returns only callback code and state", async () => {
    const { authRouter } = await import("./auth.routes.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    createAuthHandoff.mockResolvedValue("handoff-code");
    confirmEmailVerification.mockResolvedValue({
      status: "verified",
      userId: "user-1",
      handoff: {
        clientId: "temis",
        audience: "temis",
        redirectUri: "https://financenow.kr/auth/callback",
        state: "caller-state",
        codeChallenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        codeChallengeMethod: "S256"
      }
    });

    const response = await request(app)
      .post("/auth/email-verification/confirm")
      .send({ token: "raw-verification-token" });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      status: "verified",
      redirectUrl: "https://financenow.kr/auth/callback?code=handoff-code&state=caller-state"
    });
    expect(createAuthHandoff).toHaveBeenCalledWith({
      clientId: "temis",
      audience: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      userId: "user-1",
      loginMethod: "password",
      codeChallenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
      codeChallengeMethod: "S256",
      state: "caller-state"
    });
    const redirectUrl = new URL(response.body.redirectUrl);
    expect([...redirectUrl.searchParams.keys()].sort()).toEqual(["code", "state"]);
    expect(redirectUrl.searchParams.get("accessToken")).toBeNull();
    expect(redirectUrl.searchParams.get("refreshToken")).toBeNull();
  });

  it("Given handoff creation fails after verification When POST /auth/email-verification/confirm fails Then it does not record an invalid token failure", async () => {
    const { authRouter } = await import("./auth.routes.js");
    const app = express();
    app.use(express.json());
    app.use("/auth", authRouter);
    app.use((error: unknown, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
      response.status(500).json({
        error: {
          code: error instanceof Error ? error.name : "INTERNAL_ERROR",
          message: "Internal server error"
        }
      });
    });
    createAuthHandoff.mockRejectedValue(new Error("Redis unavailable"));
    confirmEmailVerification.mockResolvedValue({
      status: "verified",
      userId: "user-1",
      handoff: {
        clientId: "temis",
        audience: "temis",
        redirectUri: "https://financenow.kr/auth/callback",
        state: "caller-state",
        codeChallenge: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        codeChallengeMethod: "S256"
      }
    });

    const response = await request(app)
      .post("/auth/email-verification/confirm")
      .send({ token: "raw-verification-token" });

    expect(response.status).toBe(500);
    expect(recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "email_verification_confirm",
      outcome: "success",
      userId: "user-1"
    });
    expect(recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "email_verification_confirm",
      outcome: "failure",
      userId: "user-1",
      reasonCode: "AUTH_HANDOFF_CREATE_FAILED"
    });
    expect(recordAuthAuditEvent).not.toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      reasonCode: "INVALID_VERIFICATION_TOKEN"
    }));
  });

  it("Given an invalid verification token When POST /auth/email-verification/confirm fails Then it records a generic failure audit event", async () => {
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
    confirmEmailVerification.mockRejectedValue(
      new HttpError(400, "INVALID_VERIFICATION_TOKEN", "Invalid or expired verification token")
    );

    const response = await request(app)
      .post("/auth/email-verification/confirm")
      .send({ token: "raw-verification-token" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        code: "INVALID_VERIFICATION_TOKEN",
        message: "Invalid or expired verification token"
      }
    });
    expect(recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "email_verification_confirm",
      outcome: "failure",
      userId: null,
      reasonCode: "INVALID_VERIFICATION_TOKEN"
    });
    expect(recordAuthAuditEvent).not.toHaveBeenCalledWith(expect.anything(), expect.objectContaining({
      token: "raw-verification-token"
    }));
  });
});

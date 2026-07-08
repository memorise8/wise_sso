import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

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

const issueTokenPair = vi.fn();
const findOrCreateUserBySocialProfile = vi.fn();
const kyPost = vi.fn();
const kyGet = vi.fn();
const recordAuthAuditEvent = vi.fn();
const recordLoginFailureAuditEvent = vi.fn();
const findAuditUserIdByEmail = vi.fn();
const findAuditUserIdByPasswordEmail = vi.fn();

vi.mock("../services/token.service.js", () => ({
  issueTokenPair,
  refreshAccessToken: vi.fn(),
  rotateRefreshToken: vi.fn(),
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

vi.mock("../services/user.service.js", () => ({
  findOrCreateUserBySocialProfile
}));

vi.mock("ky", () => ({
  default: {
    post: kyPost,
    get: kyGet
  }
}));

const createOAuthTestApp = async (): Promise<express.Express> => {
  const { authRouter } = await import("./auth.routes.js");
  const { isHttpError } = await import("../utils/httpError.js");
  const app = express();
  app.use(express.json());
  app.use("/auth", authRouter);
  app.use((error: unknown, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
    if (isHttpError(error)) {
      response.status(error.statusCode).json({
        error: {
          code: error.code,
          message: error.message
        }
      });
      return;
    }

    if (error instanceof z.ZodError) {
      response.status(400).json({
        error: {
          code: "INVALID_REQUEST",
          message: "Invalid request"
        }
      });
      return;
    }

    response.status(500).json({
      error: {
        code: "INTERNAL_SERVER_ERROR",
        message: "Internal server error"
      }
    });
  });
  return app;
};

describe("auth OAuth routes", () => {
  beforeEach(() => {
    vi.resetModules();
    issueTokenPair.mockReset();
    findOrCreateUserBySocialProfile.mockReset();
    kyPost.mockReset();
    kyGet.mockReset();
    recordAuthAuditEvent.mockReset();
    recordLoginFailureAuditEvent.mockReset();
    findAuditUserIdByEmail.mockReset();
    findAuditUserIdByPasswordEmail.mockReset();
  });

  it("Given a Google OAuth login request When GET /auth/google is called Then the redirect location contains server-generated state", async () => {
    const app = await createOAuthTestApp();

    const response = await request(app).get("/auth/google");
    const redirectUrl = z.string().url().parse(response.headers["location"]);
    const state = new URL(redirectUrl).searchParams.get("state");

    expect(response.status).toBe(302);
    expect(state).toEqual(expect.any(String));
    expect(state?.length).toBeGreaterThanOrEqual(32);
  });

  it("Given a callback without OAuth state When GET /auth/google/callback is called Then it rejects the request before token exchange", async () => {
    const app = await createOAuthTestApp();

    const response = await request(app).get("/auth/google/callback").query({ code: "authorization-code" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        code: "INVALID_OAUTH_STATE",
        message: "Invalid OAuth state"
      }
    });
    expect(kyPost).not.toHaveBeenCalled();
  });

  it("Given a callback with the wrong OAuth state When GET /auth/google/callback is called Then it rejects the request before token exchange", async () => {
    const app = await createOAuthTestApp();
    await request(app).get("/auth/google");

    const response = await request(app)
      .get("/auth/google/callback")
      .query({ code: "authorization-code", state: "stale_state" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        code: "INVALID_OAUTH_STATE",
        message: "Invalid OAuth state"
      }
    });
    expect(kyPost).not.toHaveBeenCalled();
  });

  it("Given a callback with valid OAuth state When GET /auth/google/callback is called Then it redirects with a handoff code only", async () => {
    const app = await createOAuthTestApp();
    kyPost.mockReturnValue({
      json: vi.fn().mockResolvedValue({ access_token: "provider-access-token" })
    });
    kyGet.mockReturnValue({
      json: vi.fn().mockResolvedValue({
        sub: "google-user-1",
        email: "user@example.com",
        name: "Google User"
      })
    });
    findOrCreateUserBySocialProfile.mockResolvedValue({ id: "user-1" });
    issueTokenPair.mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" });
    const loginResponse = await request(app).get("/auth/google");
    const location = z.string().url().parse(loginResponse.headers["location"]);
    const state = z.string().min(1).parse(new URL(location).searchParams.get("state"));

    const response = await request(app)
      .get("/auth/google/callback")
      .query({ code: "authorization-code", state });

    expect(response.status).toBe(302);
    expect(kyPost).toHaveBeenCalledOnce();
    const redirectUrl = new URL(z.string().url().parse(response.headers["location"]));
    expect(redirectUrl.origin).toBe("http://localhost:3000");
    expect(redirectUrl.pathname).toBe("/auth/callback");
    expect(redirectUrl.searchParams.get("code")).toEqual(expect.any(String));
    expect(redirectUrl.searchParams.get("accessToken")).toBeNull();
    expect(redirectUrl.searchParams.get("refreshToken")).toBeNull();
    expect(redirectUrl.hash).not.toContain("accessToken");
    expect(redirectUrl.hash).not.toContain("refreshToken");
  });

  it("Given a callback handoff code When POST /auth/exchange is called twice Then tokens are returned once", async () => {
    const app = await createOAuthTestApp();
    kyPost.mockReturnValue({
      json: vi.fn().mockResolvedValue({ access_token: "provider-access-token" })
    });
    kyGet.mockReturnValue({
      json: vi.fn().mockResolvedValue({
        sub: "google-user-1",
        email: "user@example.com",
        name: "Google User"
      })
    });
    findOrCreateUserBySocialProfile.mockResolvedValue({ id: "user-1" });
    issueTokenPair.mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" });
    const loginResponse = await request(app).get("/auth/google");
    const location = z.string().url().parse(loginResponse.headers["location"]);
    const state = z.string().min(1).parse(new URL(location).searchParams.get("state"));
    const callbackResponse = await request(app)
      .get("/auth/google/callback")
      .query({ code: "authorization-code", state });
    const callbackLocation = new URL(z.string().url().parse(callbackResponse.headers["location"]));
    const handoffCode = z.string().min(1).parse(callbackLocation.searchParams.get("code"));

    const firstExchange = await request(app).post("/auth/exchange").send({ code: handoffCode });
    const secondExchange = await request(app).post("/auth/exchange").send({ code: handoffCode });

    expect(firstExchange.status).toBe(200);
    expect(firstExchange.body).toEqual({ accessToken: "access-token", refreshToken: "refresh-token" });
    expect(secondExchange.status).toBe(400);
    expect(secondExchange.body).toEqual({
      error: {
        code: "INVALID_AUTH_HANDOFF_CODE",
        message: "Invalid authorization code"
      }
    });
  });
});

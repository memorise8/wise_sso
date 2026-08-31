// allow: SIZE_OK - This P0 auth-hardening wave intentionally keeps the OAuth route suite together to preserve shared mocked provider/handoff setup while concurrent todos stabilize the public OAuth contract; focused behavior coverage and the full suite protect against false confidence until a dedicated post-P0 test-structure split.
import { createHash } from "node:crypto";
import express from "express";
import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

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
  },
  {
    clientId: "ledger",
    audience: "ledger-api",
    allowedRedirectUris: ["https://ledger.example/auth/callback"],
    allowedOrigins: ["https://ledger.example"],
    defaultRole: { serviceKey: "ledger", name: "pending" }
  }
]);

const issueTokenPair = vi.fn();
const verifyAccessToken = vi.fn();
const findOrCreateUserBySocialProfile = vi.fn();
const getCurrentUserWithStatus = vi.fn();
const kyPost = vi.fn();
const kyGet = vi.fn();
const recordAuthAuditEvent = vi.fn();
const recordLoginFailureAuditEvent = vi.fn();
const findAuditUserIdByEmail = vi.fn();
const findAuditUserIdByPasswordEmail = vi.fn();
type OAuthStateMetadata = {
  readonly provider: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly callerState: string | null;
  readonly codeChallenge: string | null;
  readonly codeChallengeMethod: "S256" | null;
};
type AuthHandoffMetadata = {
  readonly clientId: string;
  readonly audience: string;
  readonly redirectUri: string;
  readonly userId: string;
  readonly provider: string;
  readonly loginMethod: "oauth";
  readonly codeChallenge: string;
  readonly codeChallengeMethod: "S256";
  readonly state: string | null;
};
type AuthExchangeInput = {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly code: string;
  readonly codeVerifier: string;
};

const oauthStates = new Map<string, OAuthStateMetadata>();
const authHandoffs = new Map<string, AuthHandoffMetadata>();
let oauthStateSequence = 0;
let authHandoffSequence = 0;
const temisRedirectUri = "https://financenow.kr/auth/callback";
const temisMeRedirectUri = "https://temis.me/auth/callback";
const tiTemisMeRedirectUri = "https://ti.temis.me/auth/callback";
const validCodeVerifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const validCodeChallenge = createHash("sha256").update(validCodeVerifier).digest("base64url");
const temisCallerState = "R_sz-vF_74ssoStateBase64urlExactly43Chars";
const rateLimitCounts = new Map<string, number>();

vi.mock("../services/token.service.js", () => ({
  issueTokenPair,
  verifyAccessToken,
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

vi.mock("../services/redis.client.js", () => ({
  redisTtlStoreClient: {
    incrementWithTtl: vi.fn(async (key: string) => {
      const next = (rateLimitCounts.get(key) ?? 0) + 1;
      rateLimitCounts.set(key, next);
      return next;
    })
  }
}));

vi.mock("../services/user.service.js", () => ({
  findOrCreateUserBySocialProfile,
  getCurrentUserWithStatus
}));

vi.mock("../services/oauth-state.store.js", () => ({
  oauthStateStore: {
    create: async (provider: string, metadata?: Omit<OAuthStateMetadata, "provider">): Promise<string> => {
      oauthStateSequence += 1;
      const state = `oauth-state-${oauthStateSequence.toString().padStart(32, "0")}`;
      oauthStates.set(state, {
        provider,
        clientId: metadata?.clientId ?? "temis",
        redirectUri: metadata?.redirectUri ?? temisRedirectUri,
        callerState: metadata?.callerState ?? null,
        codeChallenge: metadata?.codeChallenge ?? null,
        codeChallengeMethod: metadata?.codeChallengeMethod ?? null
      });
      return state;
    },
    consume: async (provider: string, state: string): Promise<Omit<OAuthStateMetadata, "provider"> | null> => {
      const storedState = oauthStates.get(state);
      oauthStates.delete(state);
      if (storedState?.provider !== provider) {
        return null;
      }
      return {
        clientId: storedState.clientId,
        redirectUri: storedState.redirectUri,
        callerState: storedState.callerState,
        codeChallenge: storedState.codeChallenge,
        codeChallengeMethod: storedState.codeChallengeMethod
      };
    }
  }
}));

vi.mock("../services/auth-handoff.store.js", () => ({
  authHandoffStore: {
    create: async (metadata: AuthHandoffMetadata): Promise<string> => {
      authHandoffSequence += 1;
      const code = `auth-handoff-${authHandoffSequence}`;
      authHandoffs.set(code, metadata);
      return code;
    },
    consume: async (input: AuthExchangeInput): Promise<AuthHandoffMetadata | null> => {
      const metadata = authHandoffs.get(input.code) ?? null;
      if (
        !metadata ||
        metadata.clientId !== input.clientId ||
        metadata.redirectUri !== input.redirectUri ||
        metadata.codeChallenge !== createHash("sha256").update(input.codeVerifier).digest("base64url")
      ) {
        return null;
      }
      authHandoffs.delete(input.code);
      return metadata;
    }
  }
}));

vi.mock("ky", () => ({
  default: {
    post: kyPost,
    get: kyGet
  }
}));

const createOAuthTestApp = async (options: { readonly maxRequests?: string } = {}): Promise<express.Express> => {
  process.env["AUTH_RATE_LIMIT_MAX_REQUESTS"] = options.maxRequests ?? "20";
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
    oauthStates.clear();
    authHandoffs.clear();
    rateLimitCounts.clear();
    oauthStateSequence = 0;
    authHandoffSequence = 0;
    issueTokenPair.mockReset();
    verifyAccessToken.mockReset();
    findOrCreateUserBySocialProfile.mockReset();
    getCurrentUserWithStatus.mockReset();
    kyPost.mockReset();
    kyGet.mockReset();
    recordAuthAuditEvent.mockReset();
    recordLoginFailureAuditEvent.mockReset();
    findAuditUserIdByEmail.mockReset();
    findAuditUserIdByPasswordEmail.mockReset();
  });

  it("Given a TEMIS Google OAuth login request without PKCE When GET /auth/google is called Then it rejects before provider redirect", async () => {
    const app = await createOAuthTestApp();

    const response = await request(app).get("/auth/google");

    expect(response.status).toBe(400);
    expect(response.headers["location"]).toBeUndefined();
    expect(response.body).toEqual({
      error: {
        code: "INVALID_REQUEST",
        message: "Invalid request"
      }
    });
  });

  it("Given a TEMIS Google OAuth login request When GET /auth/google is called Then it validates the client redirect and preserves provider CSRF state", async () => {
    const app = await createOAuthTestApp();

    const response = await request(app).get("/auth/google").query({
      client_id: "temis",
      redirect_uri: temisRedirectUri,
      state: "qa-state",
      code_challenge: validCodeChallenge,
      code_challenge_method: "S256"
    });

    expect(response.status).toBe(302);
    const redirectUrl = new URL(z.string().url().parse(response.headers["location"]));
    expect(redirectUrl.origin).toBe("https://accounts.google.com");
    expect(redirectUrl.searchParams.get("redirect_uri")).toBe("http://localhost:4000/auth/google/callback");
    expect(redirectUrl.searchParams.get("state")).not.toBe("qa-state");
    expect(redirectUrl.searchParams.get("accessToken")).toBeNull();
    expect(redirectUrl.searchParams.get("refreshToken")).toBeNull();
  });

  it("Given a TEMIS Google OAuth login request without challenge method When GET /auth/google is called Then it infers S256 and stores provider CSRF metadata", async () => {
    const app = await createOAuthTestApp();

    const response = await request(app).get("/auth/google").query({
      client_id: "temis",
      redirect_uri: temisRedirectUri,
      state: "qa-state",
      code_challenge: validCodeChallenge
    });
    const redirectUrl = new URL(z.string().url().parse(response.headers["location"]));
    const providerState = z.string().min(1).parse(redirectUrl.searchParams.get("state"));
    const metadata = oauthStates.get(providerState);

    expect(response.status).toBe(302);
    expect(metadata?.codeChallenge).toBe(validCodeChallenge);
    expect(metadata?.codeChallengeMethod).toBe("S256");
    expect(metadata?.callerState).toBe("qa-state");
  });

  it("Given an unregistered TEMIS redirect URI When GET /auth/google is called Then it rejects before provider redirect", async () => {
    const app = await createOAuthTestApp();

    const response = await request(app).get("/auth/google").query({
      client_id: "temis",
      redirect_uri: "https://evil.example/callback",
      state: "qa-state",
      code_challenge: validCodeChallenge,
      code_challenge_method: "S256"
    });

    expect(response.status).toBe(400);
    expect(response.headers["location"]).toBeUndefined();
    expect(response.body).toEqual({
      error: {
        code: "INVALID_REDIRECT_URI",
        message: "Invalid redirect URI"
      }
    });
  });

  it("Given the TEMIS rebrand callback URI When GET /auth/google is called Then it accepts the redirect URI", async () => {
    const app = await createOAuthTestApp();

    const response = await request(app).get("/auth/google").query({
      client_id: "temis",
      redirect_uri: temisMeRedirectUri,
      state: temisCallerState,
      code_challenge: validCodeChallenge,
      code_challenge_method: "S256"
    });

    expect(response.status).toBe(302);
    const redirectUrl = new URL(z.string().url().parse(response.headers["location"]));
    const providerState = z.string().min(1).parse(redirectUrl.searchParams.get("state"));
    expect(oauthStates.get(providerState)?.redirectUri).toBe(temisMeRedirectUri);
  });

  it("Given the TEMIS isolated certification callback URI When GET /auth/google is called Then it accepts the redirect URI", async () => {
    const app = await createOAuthTestApp();

    const response = await request(app).get("/auth/google").query({
      client_id: "temis",
      redirect_uri: tiTemisMeRedirectUri,
      state: temisCallerState,
      code_challenge: validCodeChallenge,
      code_challenge_method: "S256"
    });

    expect(response.status).toBe(302);
    const redirectUrl = new URL(z.string().url().parse(response.headers["location"]));
    const providerState = z.string().min(1).parse(redirectUrl.searchParams.get("state"));
    expect(oauthStates.get(providerState)?.redirectUri).toBe(tiTemisMeRedirectUri);
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

  it("Given a callback with valid OAuth state When GET /auth/google/callback is called Then it redirects to TEMIS with a handoff code and caller state only", async () => {
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
    findOrCreateUserBySocialProfile.mockResolvedValue({ id: "user-1", status: "ACTIVE" });
    issueTokenPair.mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" });
    verifyAccessToken.mockReturnValue("user-1");
    getCurrentUserWithStatus.mockResolvedValue({
      id: "user-1",
      email: "user@example.com",
      name: "Google User",
      roles: [],
      status: "ACTIVE"
    });
    const loginResponse = await request(app).get("/auth/google").query({
      client_id: "temis",
      redirect_uri: temisRedirectUri,
      state: temisCallerState,
      code_challenge: validCodeChallenge,
      code_challenge_method: "S256"
    });
    const location = z.string().url().parse(loginResponse.headers["location"]);
    const state = z.string().min(1).parse(new URL(location).searchParams.get("state"));

    const response = await request(app)
      .get("/auth/google/callback")
      .query({ code: "authorization-code", state });

    expect(response.status).toBe(302);
    expect(kyPost).toHaveBeenCalledOnce();
    const redirectUrl = new URL(z.string().url().parse(response.headers["location"]));
    expect(redirectUrl.origin).toBe("https://financenow.kr");
    expect(redirectUrl.pathname).toBe("/auth/callback");
    expect(redirectUrl.searchParams.get("code")).toEqual(expect.any(String));
    expect(redirectUrl.searchParams.get("state")).toBe(temisCallerState);
    expect(redirectUrl.searchParams.get("accessToken")).toBeNull();
    expect(redirectUrl.searchParams.get("refreshToken")).toBeNull();
    expect(redirectUrl.hash).not.toContain("accessToken");
    expect(redirectUrl.hash).not.toContain("refreshToken");
    const handoffCode = z.string().min(1).parse(redirectUrl.searchParams.get("code"));
    expect(authHandoffs.get(handoffCode)?.state).toBe(temisCallerState);
  });

  it("Given an active browser re-enters Google OAuth with a new TEMIS state When callback completes Then the new caller state is echoed", async () => {
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
    findOrCreateUserBySocialProfile.mockResolvedValue({ id: "user-1", status: "ACTIVE" });
    const firstCallerState = "first_43char_state_from_temis_BFF_exactly_001";
    const secondCallerState = "second_43char_state_from_temis_BFF_exactly_02";
    const startOAuth = async (callerState: string): Promise<string> => {
      const response = await request(app).get("/auth/google").query({
        client_id: "temis",
        redirect_uri: temisRedirectUri,
        state: callerState,
        code_challenge: validCodeChallenge,
        code_challenge_method: "S256"
      });
      const location = z.string().url().parse(response.headers["location"]);
      return z.string().min(1).parse(new URL(location).searchParams.get("state"));
    };

    const firstProviderState = await startOAuth(firstCallerState);
    const secondProviderState = await startOAuth(secondCallerState);
    const firstCallback = await request(app)
      .get("/auth/google/callback")
      .query({ code: "authorization-code-1", state: firstProviderState });
    const secondCallback = await request(app)
      .get("/auth/google/callback")
      .query({ code: "authorization-code-2", state: secondProviderState });

    const firstRedirectUrl = new URL(z.string().url().parse(firstCallback.headers["location"]));
    const secondRedirectUrl = new URL(z.string().url().parse(secondCallback.headers["location"]));
    expect(firstCallback.status).toBe(302);
    expect(secondCallback.status).toBe(302);
    expect(firstProviderState).not.toBe(secondProviderState);
    expect(firstRedirectUrl.searchParams.get("state")).toBe(firstCallerState);
    expect(secondRedirectUrl.searchParams.get("state")).toBe(secondCallerState);
    expect(firstRedirectUrl.searchParams.get("state")).not.toBe(firstProviderState);
    expect(secondRedirectUrl.searchParams.get("state")).not.toBe(secondProviderState);
  });

  it("Given repeated OAuth start requests When GET /auth/google exceeds the auth limit Then it returns a generic rate limit error and audits the limit", async () => {
    const app = await createOAuthTestApp({ maxRequests: "2" });
    const query = {
      client_id: "temis",
      redirect_uri: temisRedirectUri,
      state: "qa-state",
      code_challenge: validCodeChallenge,
      code_challenge_method: "S256"
    };

    const firstResponse = await request(app).get("/auth/google").query(query);
    const secondResponse = await request(app).get("/auth/google").query(query);
    const limitedResponse = await request(app).get("/auth/google").query(query);

    expect(firstResponse.status).toBe(302);
    expect(secondResponse.status).toBe(302);
    expect(limitedResponse.status).toBe(429);
    expect(limitedResponse.body).toEqual({
      error: {
        code: "RATE_LIMITED",
        message: "Too many authentication requests"
      }
    });
    expect(oauthStates.size).toBe(2);
    expect(recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "rate_limit_exceeded",
      outcome: "failure",
      userId: null,
      reasonCode: "RATE_LIMITED",
      detailsJson: expect.objectContaining({
        route: "/auth/google",
        method: "GET",
        maxRequests: 2
      })
    });
  });

  it("Given repeated OAuth callback requests When GET /auth/google/callback exceeds the auth limit Then provider calls stop before token exchange", async () => {
    const app = await createOAuthTestApp({ maxRequests: "2" });
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
    findOrCreateUserBySocialProfile.mockResolvedValue({ id: "user-1", status: "ACTIVE" });
    for (const state of ["oauth-callback-state-1", "oauth-callback-state-2", "oauth-callback-state-3"]) {
      oauthStates.set(state, {
        provider: "google",
        clientId: "temis",
        redirectUri: temisRedirectUri,
        callerState: null,
        codeChallenge: validCodeChallenge,
        codeChallengeMethod: "S256"
      });
    }

    const firstResponse = await request(app)
      .get("/auth/google/callback")
      .query({ code: "authorization-code-1", state: "oauth-callback-state-1" });
    const secondResponse = await request(app)
      .get("/auth/google/callback")
      .query({ code: "authorization-code-2", state: "oauth-callback-state-2" });
    const limitedResponse = await request(app)
      .get("/auth/google/callback")
      .query({ code: "authorization-code-3", state: "oauth-callback-state-3" });

    expect(firstResponse.status).toBe(302);
    expect(secondResponse.status).toBe(302);
    expect(limitedResponse.status).toBe(429);
    expect(limitedResponse.body).toEqual({
      error: {
        code: "RATE_LIMITED",
        message: "Too many authentication requests"
      }
    });
    expect(kyPost).toHaveBeenCalledTimes(2);
    expect(kyGet).toHaveBeenCalledTimes(2);
    expect(oauthStates.has("oauth-callback-state-3")).toBe(true);
    expect(recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "rate_limit_exceeded",
      outcome: "failure",
      userId: null,
      reasonCode: "RATE_LIMITED",
      detailsJson: expect.objectContaining({
        route: "/auth/google/callback",
        method: "GET",
        maxRequests: 2
      })
    });
  });

  it("Given OAuth resolves to a suspended user When GET /auth/google/callback completes Then no handoff code is created", async () => {
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
    findOrCreateUserBySocialProfile.mockResolvedValue({ id: "user-1", status: "SUSPENDED" });
    const loginResponse = await request(app).get("/auth/google").query({
      client_id: "temis",
      redirect_uri: temisRedirectUri,
      state: "qa-state",
      code_challenge: validCodeChallenge,
      code_challenge_method: "S256"
    });
    const location = z.string().url().parse(loginResponse.headers["location"]);
    const state = z.string().min(1).parse(new URL(location).searchParams.get("state"));

    const response = await request(app)
      .get("/auth/google/callback")
      .query({ code: "authorization-code", state });

    expect(response.status).toBe(401);
    expect(response.body).toEqual({
      error: {
        code: "UNAUTHORIZED",
        message: "Authentication is required"
      }
    });
    expect(authHandoffs.size).toBe(0);
    expect(issueTokenPair).not.toHaveBeenCalled();
  });

  it("Given a callback handoff code When POST /auth/exchange is called twice with matching bindings Then tokens are returned once", async () => {
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
    findOrCreateUserBySocialProfile.mockResolvedValue({ id: "user-1", status: "ACTIVE" });
    issueTokenPair.mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" });
    const loginResponse = await request(app).get("/auth/google").query({
      client_id: "temis",
      redirect_uri: temisRedirectUri,
      state: "qa-state",
      code_challenge: validCodeChallenge,
      code_challenge_method: "S256"
    });
    const location = z.string().url().parse(loginResponse.headers["location"]);
    const state = z.string().min(1).parse(new URL(location).searchParams.get("state"));
    const callbackResponse = await request(app)
      .get("/auth/google/callback")
      .query({ code: "authorization-code", state });
    const callbackLocation = new URL(z.string().url().parse(callbackResponse.headers["location"]));
    const handoffCode = z.string().min(1).parse(callbackLocation.searchParams.get("code"));

    const exchangeBody = {
      code: handoffCode,
      clientId: "temis",
      redirectUri: temisRedirectUri,
      codeVerifier: validCodeVerifier
    };
    const firstExchange = await request(app).post("/auth/exchange").send(exchangeBody);
    const secondExchange = await request(app).post("/auth/exchange").send(exchangeBody);

    expect(firstExchange.status).toBe(200);
    expect(firstExchange.body).toEqual({ accessToken: "access-token", refreshToken: "refresh-token" });
    expect(secondExchange.status).toBe(400);
    expect(secondExchange.body).toEqual({
      error: {
        code: "INVALID_AUTH_HANDOFF_CODE",
        message: "Invalid authorization code"
      }
    });
    expect(issueTokenPair).toHaveBeenCalledOnce();
    expect(issueTokenPair).toHaveBeenCalledWith("user-1", { audience: "temis" });
    expect(recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "auth_handoff_exchange_success",
      outcome: "success",
      userId: "user-1",
      provider: "google",
      detailsJson: {
        route: "/auth/exchange",
        clientId: "temis"
      }
    });
    expect(recordAuthAuditEvent).toHaveBeenCalledWith(expect.anything(), {
      eventType: "auth_handoff_exchange_failure",
      outcome: "failure",
      userId: null,
      reasonCode: "INVALID_AUTH_HANDOFF_CODE",
      detailsJson: {
        route: "/auth/exchange",
        clientId: "temis"
      }
    });
    expect(JSON.stringify(recordAuthAuditEvent.mock.calls)).not.toContain(handoffCode);
    expect(JSON.stringify(recordAuthAuditEvent.mock.calls)).not.toContain(validCodeVerifier);
  });

  it("Given a non-TEMIS callback handoff code When POST /auth/exchange succeeds Then token issuance uses the relying client audience", async () => {
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
    findOrCreateUserBySocialProfile.mockResolvedValue({ id: "user-1", status: "ACTIVE" });
    issueTokenPair.mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" });
    const loginResponse = await request(app).get("/auth/google").query({
      client_id: "ledger",
      redirect_uri: "https://ledger.example/auth/callback",
      state: "qa-state",
      code_challenge: validCodeChallenge,
      code_challenge_method: "S256"
    });
    const location = z.string().url().parse(loginResponse.headers["location"]);
    const state = z.string().min(1).parse(new URL(location).searchParams.get("state"));
    const callbackResponse = await request(app)
      .get("/auth/google/callback")
      .query({ code: "authorization-code", state });
    const callbackLocation = new URL(z.string().url().parse(callbackResponse.headers["location"]));
    const handoffCode = z.string().min(1).parse(callbackLocation.searchParams.get("code"));

    const response = await request(app).post("/auth/exchange").send({
      code: handoffCode,
      clientId: "ledger",
      redirectUri: "https://ledger.example/auth/callback",
      codeVerifier: validCodeVerifier
    });

    expect(response.status).toBe(200);
    expect(callbackLocation.origin).toBe("https://ledger.example");
    expect(issueTokenPair).toHaveBeenCalledWith("user-1", { audience: "ledger-api" });
  });

  it("Given a callback handoff code When POST /auth/exchange uses camelCase bindings Then tokens are returned", async () => {
    const app = await createOAuthTestApp();
    authHandoffs.set("auth-handoff-camel", {
      clientId: "temis",
      audience: "temis",
      redirectUri: temisRedirectUri,
      userId: "user-1",
      provider: "google",
      loginMethod: "oauth",
      codeChallenge: validCodeChallenge,
      codeChallengeMethod: "S256",
      state: "qa-state"
    });
    issueTokenPair.mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" });

    const response = await request(app).post("/auth/exchange").send({
      code: "auth-handoff-camel",
      clientId: "temis",
      redirectUri: temisRedirectUri,
      codeVerifier: validCodeVerifier
    });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ accessToken: "access-token", refreshToken: "refresh-token" });
    expect(issueTokenPair).toHaveBeenCalledWith("user-1", { audience: "temis" });
  });

  it("Given a callback handoff code When POST /auth/exchange uses snake_case bindings Then it rejects with a generic handoff failure", async () => {
    const app = await createOAuthTestApp();
    authHandoffs.set("auth-handoff-snake", {
      clientId: "temis",
      audience: "temis",
      redirectUri: temisRedirectUri,
      userId: "user-1",
      provider: "google",
      loginMethod: "oauth",
      codeChallenge: validCodeChallenge,
      codeChallengeMethod: "S256",
      state: "qa-state"
    });

    const response = await request(app).post("/auth/exchange").send({
      code: "auth-handoff-snake",
      client_id: "temis",
      redirect_uri: temisRedirectUri,
      code_verifier: validCodeVerifier
    });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        code: "INVALID_AUTH_HANDOFF_CODE",
        message: "Invalid authorization code"
      }
    });
    expect(authHandoffs.has("auth-handoff-snake")).toBe(true);
    expect(issueTokenPair).not.toHaveBeenCalled();
  });

  it("Given a callback handoff code When POST /auth/exchange includes an unknown field Then it rejects with a generic handoff failure", async () => {
    const app = await createOAuthTestApp();
    authHandoffs.set("auth-handoff-extra-field", {
      clientId: "temis",
      audience: "temis",
      redirectUri: temisRedirectUri,
      userId: "user-1",
      provider: "google",
      loginMethod: "oauth",
      codeChallenge: validCodeChallenge,
      codeChallengeMethod: "S256",
      state: "qa-state"
    });

    const response = await request(app).post("/auth/exchange").send({
      code: "auth-handoff-extra-field",
      clientId: "temis",
      redirectUri: temisRedirectUri,
      codeVerifier: validCodeVerifier,
      client_id: "temis"
    });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        code: "INVALID_AUTH_HANDOFF_CODE",
        message: "Invalid authorization code"
      }
    });
    expect(authHandoffs.has("auth-handoff-extra-field")).toBe(true);
    expect(issueTokenPair).not.toHaveBeenCalled();
  });

  it("Given a callback handoff code When POST /auth/exchange omits client redirect and verifier bindings Then it rejects the exchange", async () => {
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
    findOrCreateUserBySocialProfile.mockResolvedValue({ id: "user-1", status: "ACTIVE" });
    issueTokenPair.mockResolvedValue({ accessToken: "access-token", refreshToken: "refresh-token" });
    const loginResponse = await request(app).get("/auth/google").query({
      client_id: "temis",
      redirect_uri: temisRedirectUri,
      state: "qa-state",
      code_challenge: validCodeChallenge,
      code_challenge_method: "S256"
    });
    const location = z.string().url().parse(loginResponse.headers["location"]);
    const state = z.string().min(1).parse(new URL(location).searchParams.get("state"));
    const callbackResponse = await request(app)
      .get("/auth/google/callback")
      .query({ code: "authorization-code", state });
    const callbackLocation = new URL(z.string().url().parse(callbackResponse.headers["location"]));
    const handoffCode = z.string().min(1).parse(callbackLocation.searchParams.get("code"));

    const response = await request(app).post("/auth/exchange").send({ code: handoffCode });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        code: "INVALID_AUTH_HANDOFF_CODE",
        message: "Invalid authorization code"
      }
    });
    expect(authHandoffs.has(handoffCode)).toBe(true);
    expect(issueTokenPair).not.toHaveBeenCalled();
  });
});

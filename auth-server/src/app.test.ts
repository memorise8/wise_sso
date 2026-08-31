import request from "supertest";
import type { Express } from "express";
import { generateKeyPairSync } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./services/oauth-state.store.js", () => ({
  oauthStateStore: {
    create: async (): Promise<string> => "oauth-state-for-cors-test-000000000000000000000000",
    consume: async (): Promise<boolean> => false
  }
}));

vi.mock("./services/redis.client.js", () => ({
  redisTtlStoreClient: {
    incrementWithTtl: vi.fn(async () => 1)
  }
}));

const temisRedirectUri = "https://financenow.kr/auth/callback";
const validCodeChallenge = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const accessKeyId = "temis-access-key-1";

const createAccessKeyEnv = (): void => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001
  });
  const publicJwk = publicKey.export({ format: "jwk" });
  if (publicJwk.kty !== "RSA" || typeof publicJwk.n !== "string" || typeof publicJwk.e !== "string") {
    throw new Error("Generated RSA key did not export a public JWK");
  }
  process.env["JWT_ACCESS_ALGORITHM"] = "RS256";
  process.env["JWT_ACCESS_PRIVATE_KEY"] = privateKey.export({ format: "pem", type: "pkcs8" }).toString().replace(/\n/g, "\\n");
  process.env["JWT_ACCESS_PUBLIC_JWK"] = JSON.stringify({
    kty: "RSA",
    n: publicJwk.n,
    e: publicJwk.e,
    alg: "RS256",
    use: "sig",
    kid: accessKeyId
  });
  process.env["JWT_ACCESS_KEY_ID"] = accessKeyId;
};

const setRequiredEnv = (): void => {
  createAccessKeyEnv();
  process.env["DATABASE_URL"] = "postgresql://user:password@localhost:5432/auth_db";
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
  process.env["CORS_ALLOWED_ORIGINS"] = "http://localhost:3000,https://app.temis.co.kr";
  process.env["AUTH_RATE_LIMIT_WINDOW_SECONDS"] = "60";
  process.env["AUTH_RATE_LIMIT_MAX_REQUESTS"] = "20";
  process.env["AUTH_CLIENTS_JSON"] = JSON.stringify([
    {
      clientId: "temis",
      audience: "temis",
      allowedRedirectUris: [temisRedirectUri, "https://temis.me/auth/callback", "https://ti.temis.me/auth/callback"],
      allowedOrigins: ["https://financenow.kr"],
      defaultRole: { serviceKey: "temis", name: "user" }
    }
  ]);
};

const validPkceQuery = {
  client_id: "temis",
  redirect_uri: temisRedirectUri,
  state: "qa-state",
  code_challenge: validCodeChallenge,
  code_challenge_method: "S256"
} as const;

const importAppWithReadiness = async (readinessCheck: () => Promise<boolean>): Promise<Express> => {
  const { createApp } = await import("./app.js");
  return createApp({ readinessCheck });
};

describe("app CORS allowlist", () => {
  beforeEach(() => {
    vi.resetModules();
    setRequiredEnv();
  });

  it("Given a configured browser origin When GET /auth/google is called Then CORS allows the origin", async () => {
    const { app } = await import("./app.js");

    const response = await request(app)
      .get("/auth/google")
      .query(validPkceQuery)
      .set("Origin", "http://localhost:3000");

    expect(response.status).toBe(302);
    expect(response.headers["access-control-allow-origin"]).toBe("http://localhost:3000");
  });

  it("Given an unconfigured browser origin When GET /auth/google is called Then CORS does not allow the origin", async () => {
    const { app } = await import("./app.js");

    const response = await request(app)
      .get("/auth/google")
      .query(validPkceQuery)
      .set("Origin", "https://evil.example");

    expect(response.status).toBe(302);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("Given the SSO portal When GET /login is called Then it serves the login page", async () => {
    const { app } = await import("./app.js");

    const response = await request(app).get("/login");

    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toContain("text/html");
    expect(response.text).toContain("Wise SSO");
    expect(response.text).toContain("Google 계정으로 계속");
  });

  it("Given the SSO portal When GET /signup is called Then it serves the signup page shell", async () => {
    const { app } = await import("./app.js");

    const response = await request(app).get("/signup");

    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toContain("text/html");
    expect(response.text).toContain("회원가입");
    expect(response.text).toContain("data-form=\"signup\"");
  });

  it("Given the admin dashboard route When GET /admin/dashboard is called Then it serves the static management shell", async () => {
    const { app } = await import("./app.js");

    const response = await request(app).get("/admin/dashboard");

    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toContain("text/html");
    expect(response.text).toContain("사용자 관리");
    expect(response.text).toContain("data-token-form");
  });

  it("Given the public management alias When GET /manage/dashboard is called Then it serves the static management shell", async () => {
    const { app } = await import("./app.js");

    const response = await request(app).get("/manage/dashboard");

    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toContain("text/html");
    expect(response.text).toContain("사용자 관리");
    expect(response.text).toContain("content=\"/manage-api\"");
  });
});

describe("app health and readiness probes", () => {
  beforeEach(() => {
    vi.resetModules();
    setRequiredEnv();
  });

  it("Given an anonymous liveness request When GET /healthz is called Then it returns only process status", async () => {
    const testApp = await importAppWithReadiness(async () => true);

    const response = await request(testApp).get("/healthz");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: "ok" });
  });

  it("Given the database readiness check succeeds When GET /readyz is called Then it returns ready status", async () => {
    const testApp = await importAppWithReadiness(async () => true);

    const response = await request(testApp).get("/readyz");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: "ok" });
  });

  it("Given the database readiness check fails When GET /readyz is called Then it returns a generic unavailable response", async () => {
    const testApp = await importAppWithReadiness(async () => false);

    const response = await request(testApp).get("/readyz");

    expect(response.status).toBe(503);
    expect(response.body).toEqual({ status: "unavailable" });
  });
});

describe("well-known token metadata", () => {
  beforeEach(() => {
    vi.resetModules();
    setRequiredEnv();
  });

  it("Given public JWKS metadata When GET /.well-known/jwks.json is called Then it returns only public RSA signing keys", async () => {
    const testApp = await importAppWithReadiness(async () => true);

    const response = await request(testApp).get("/.well-known/jwks.json");
    const serializedBody = JSON.stringify(response.body);

    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toContain("public");
    expect(response.body).toEqual({
      keys: [
        expect.objectContaining({
          kty: "RSA",
          use: "sig",
          alg: "RS256",
          kid: accessKeyId
        })
      ]
    });
    expect(serializedBody).not.toContain("privateKey");
    expect(serializedBody).not.toContain("-----BEGIN PRIVATE KEY-----");
    expect(response.body.keys[0]).not.toHaveProperty("d");
    expect(response.body.keys[0]).not.toHaveProperty("p");
    expect(response.body.keys[0]).not.toHaveProperty("q");
  });

  it("Given public discovery metadata When GET /.well-known/openid-configuration is called Then it returns issuer jwks uri and access-token claims only", async () => {
    const testApp = await importAppWithReadiness(async () => true);

    const response = await request(testApp).get("/.well-known/openid-configuration");

    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toContain("public");
    expect(response.body).toMatchObject({
      issuer: "https://auth.temis.co.kr",
      jwks_uri: "https://auth.temis.co.kr/.well-known/jwks.json",
      subject_types_supported: ["public"],
      response_types_supported: ["code"],
      claims_supported: expect.arrayContaining(["sub", "iss", "aud", "exp", "iat", "roles", "email", "email_verified", "name", "type"])
    });
    expect(response.body).not.toHaveProperty("id_token_signing_alg_values_supported");
  });
});

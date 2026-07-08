import request from "supertest";
import { beforeEach, describe, expect, it, vi } from "vitest";

const setRequiredEnv = (): void => {
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
  process.env["CORS_ALLOWED_ORIGINS"] = "http://localhost:3000,https://app.temis.co.kr";
  process.env["AUTH_RATE_LIMIT_WINDOW_SECONDS"] = "60";
  process.env["AUTH_RATE_LIMIT_MAX_REQUESTS"] = "20";
};

describe("app CORS allowlist", () => {
  beforeEach(() => {
    vi.resetModules();
    setRequiredEnv();
  });

  it("Given a configured browser origin When GET /auth/google is called Then CORS allows the origin", async () => {
    const { app } = await import("./app.js");

    const response = await request(app).get("/auth/google").set("Origin", "http://localhost:3000");

    expect(response.status).toBe(302);
    expect(response.headers["access-control-allow-origin"]).toBe("http://localhost:3000");
  });

  it("Given an unconfigured browser origin When GET /auth/google is called Then CORS does not allow the origin", async () => {
    const { app } = await import("./app.js");

    const response = await request(app).get("/auth/google").set("Origin", "https://evil.example");

    expect(response.status).toBe(302);
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  });
});

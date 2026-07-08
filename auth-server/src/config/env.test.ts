import { beforeEach, describe, expect, it, vi } from "vitest";

const baseEnv = {
  DATABASE_URL: "postgresql://user:password@localhost:5432/auth_db",
  JWT_ACCESS_SECRET: "test-access-secret-long",
  JWT_REFRESH_SECRET: "test-refresh-secret-long",
  JWT_ISSUER: "https://auth.temis.co.kr",
  JWT_AUDIENCE: "temis",
  FRONTEND_REDIRECT_URL: "https://app.temis.co.kr/auth/callback",
  GOOGLE_CLIENT_ID: "google",
  GOOGLE_CLIENT_SECRET: "google-secret",
  GOOGLE_REDIRECT_URI: "http://localhost:4000/auth/google/callback",
  NAVER_CLIENT_ID: "naver",
  NAVER_CLIENT_SECRET: "naver-secret",
  NAVER_REDIRECT_URI: "http://localhost:4000/auth/naver/callback",
  KAKAO_CLIENT_ID: "kakao",
  KAKAO_CLIENT_SECRET: "kakao-secret",
  KAKAO_REDIRECT_URI: "http://localhost:4000/auth/kakao/callback",
  MAIL_PROVIDER: "dev"
} satisfies Record<string, string>;

const productionSmtpEnv = {
  ...baseEnv,
  NODE_ENV: "production",
  MAIL_PROVIDER: "smtp",
  SMTP_HOST: "smtp.example.com",
  SMTP_USERNAME: "mailer",
  SMTP_PASSWORD: "mailer-password"
} satisfies Record<string, string>;

describe("parseEnv CORS allowlist", () => {
  beforeEach(() => {
    vi.resetModules();
    Object.assign(process.env, baseEnv);
  });

  it("Given production env without local origins When env is parsed Then localhost is not added implicitly", async () => {
    const { parseEnv } = await import("./env.js");

    const parsed = parseEnv({
      ...productionSmtpEnv,
      CORS_ALLOWED_ORIGINS: "https://admin.temis.co.kr"
    });

    expect(parsed.CORS_ALLOWED_ORIGINS).toEqual([
      "https://admin.temis.co.kr",
      "https://app.temis.co.kr"
    ]);
  });

  it("Given production env with explicit localhost origin When env is parsed Then localhost remains allowed", async () => {
    const { parseEnv } = await import("./env.js");

    const parsed = parseEnv({
      ...productionSmtpEnv,
      CORS_ALLOWED_ORIGINS: "https://admin.temis.co.kr,http://localhost:3000"
    });

    expect(parsed.CORS_ALLOWED_ORIGINS).toContain("http://localhost:3000");
  });

  it("Given test env without local origins When env is parsed Then local development origins are added", async () => {
    const { parseEnv } = await import("./env.js");

    const parsed = parseEnv({
      ...baseEnv,
      NODE_ENV: "test",
      CORS_ALLOWED_ORIGINS: "https://admin.temis.co.kr"
    });

    expect(parsed.CORS_ALLOWED_ORIGINS).toEqual([
      "https://admin.temis.co.kr",
      "https://app.temis.co.kr",
      "http://localhost:3000",
      "http://127.0.0.1:3000"
    ]);
  });

  it("Given production env with dev mail provider When env is parsed Then it rejects the dev provider", async () => {
    const { parseEnv } = await import("./env.js");

    expect(() => parseEnv({
      ...baseEnv,
      NODE_ENV: "production",
      MAIL_PROVIDER: "dev"
    })).toThrow();
  });

  it("Given production smtp env without smtp credentials When env is parsed Then it rejects missing smtp settings", async () => {
    const { parseEnv } = await import("./env.js");

    expect(() => parseEnv({
      ...baseEnv,
      NODE_ENV: "production",
      MAIL_PROVIDER: "smtp"
    })).toThrow();
  });

  it("Given production env with example jwt secrets When env is parsed Then it rejects placeholder secrets", async () => {
    const { parseEnv } = await import("./env.js");

    expect(() => parseEnv({
      ...productionSmtpEnv,
      JWT_ACCESS_SECRET: "replace-access-secret",
      JWT_REFRESH_SECRET: "replace-refresh-secret"
    })).toThrow();
  });

  it("Given a short jwt secret When env is parsed Then it still rejects the secret length", async () => {
    const { parseEnv } = await import("./env.js");

    expect(() => parseEnv({
      ...productionSmtpEnv,
      JWT_ACCESS_SECRET: "short"
    })).toThrow();
  });
});

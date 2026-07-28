// allow: SIZE_OK - mail provider contract matrix is kept together to prevent delivery-mode regressions.
import { beforeEach, describe, expect, it, vi } from "vitest";

const nodemailerCreateTransport = vi.fn();

vi.mock("nodemailer", () => ({
  default: {
    createTransport: nodemailerCreateTransport
  }
}));

const authClientsJson = JSON.stringify([{
  clientId: "temis",
  audience: "temis",
  allowedRedirectUris: ["https://financenow.kr/auth/callback", "https://temis.me/auth/callback", "https://ti.temis.me/auth/callback"],
  allowedOrigins: ["https://financenow.kr"],
  defaultRole: { serviceKey: "temis", name: "user" }
}]);

const readRequiredTestEnv = (key: string): string => {
  const value = process.env[key];
  if (!value) {
    throw new Error(`${key} must be provided by the common Vitest setup`);
  }
  return value;
};

const baseEnv = {
  DATABASE_URL: "postgresql://user:password@localhost:5432/auth_db",
  JWT_ACCESS_ALGORITHM: readRequiredTestEnv("JWT_ACCESS_ALGORITHM"),
  JWT_ACCESS_PRIVATE_KEY: readRequiredTestEnv("JWT_ACCESS_PRIVATE_KEY"),
  JWT_ACCESS_PUBLIC_JWK: readRequiredTestEnv("JWT_ACCESS_PUBLIC_JWK"),
  JWT_ACCESS_KEY_ID: readRequiredTestEnv("JWT_ACCESS_KEY_ID"),
  JWT_REFRESH_SECRET: "test-refresh-secret-long",
  JWT_ISSUER: "https://auth.temis.co.kr",
  JWT_AUDIENCE: "temis",
  REDIS_URL: "redis://localhost:6379",
  FRONTEND_REDIRECT_URL: "http://localhost:3000/auth/callback",
  GOOGLE_CLIENT_ID: "google",
  GOOGLE_CLIENT_SECRET: "google-secret",
  GOOGLE_REDIRECT_URI: "http://localhost:4000/auth/google/callback",
  NAVER_CLIENT_ID: "naver",
  NAVER_CLIENT_SECRET: "naver-secret",
  NAVER_REDIRECT_URI: "http://localhost:4000/auth/naver/callback",
  KAKAO_CLIENT_ID: "kakao",
  KAKAO_CLIENT_SECRET: "kakao-secret",
  KAKAO_REDIRECT_URI: "http://localhost:4000/auth/kakao/callback",
  AUTH_CLIENTS_JSON: authClientsJson
} satisfies Record<string, string>;

describe("mail service", () => {
  beforeEach(() => {
    vi.resetModules();
    nodemailerCreateTransport.mockReset();
    delete process.env["MAIL_REPLY_TO"];
    delete process.env["RESEND_API_KEY"];
    delete process.env["RESEND_ADMIN_KEY"];
    delete process.env["SMTP_HOST"];
    delete process.env["SMTP_USERNAME"];
    delete process.env["SMTP_PASSWORD"];
    Object.assign(process.env, baseEnv);
  });

  it("Given auth links When verification and reset messages are sent Then fake mailer captures recipient and link shape", async () => {
    const { createFakeMailService } = await import("./mail.service.js");
    const mailer = createFakeMailService();

    await mailer.sendEmailVerification({
      to: "user@example.com",
      verificationUrl: "https://auth.example.com/verify?token=verification-token"
    });
    await mailer.sendPasswordReset({
      to: "user@example.com",
      resetUrl: "https://auth.example.com/reset?token=reset-token"
    });

    expect(mailer.messages).toEqual([
      {
        kind: "email-verification",
        to: "user@example.com",
        link: "https://auth.example.com/verify?token=verification-token"
      },
      {
        kind: "password-reset",
        to: "user@example.com",
        link: "https://auth.example.com/reset?token=reset-token"
      }
    ]);
  });

  it("Given a password reset link When dev mailer logs the message Then the raw token is redacted", async () => {
    const { createDevMailService } = await import("./mail.service.js");
    const logger = {
      info: vi.fn()
    };
    const mailer = createDevMailService(logger);

    await mailer.sendPasswordReset({
      to: "user@example.com",
      resetUrl: "https://auth.example.com/reset?token=raw-reset-token"
    });

    expect(logger.info).toHaveBeenCalledWith("dev mail captured", {
      kind: "password-reset",
      to: "user@example.com",
      link: "https://auth.example.com/reset?token=%5BREDACTED%5D"
    });
  });

  it("Given dev mail provider When mail service is created Then it logs a redacted verification token", async () => {
    process.env["MAIL_PROVIDER"] = "dev";
    const { createMailService } = await import("./mail.service.js");
    const logger = {
      info: vi.fn()
    };
    const mailer = createMailService({ logger });

    await mailer.sendEmailVerification({
      to: "user@example.com",
      verificationUrl: "https://auth.example.com/verify?token=raw-verification-token"
    });

    expect(logger.info).toHaveBeenCalledWith("dev mail captured", {
      kind: "email-verification",
      to: "user@example.com",
      link: "https://auth.example.com/verify?token=%5BREDACTED%5D"
    });
    expect(nodemailerCreateTransport).not.toHaveBeenCalled();
  });

  it("Given smtp mail provider When mail service is created Then SMTP transport is selected", async () => {
    Object.assign(process.env, {
      MAIL_PROVIDER: "smtp",
      MAIL_FROM: "Auth <auth@example.com>",
      MAIL_REPLY_TO: "",
      SMTP_HOST: "smtp.example.com",
      SMTP_PORT: "2525",
      SMTP_USERNAME: "smtp-user",
      SMTP_PASSWORD: "smtp-password"
    });
    const sendMail = vi.fn().mockResolvedValue({});
    nodemailerCreateTransport.mockReturnValue({ sendMail });
    const { createMailService } = await import("./mail.service.js");
    const mailer = createMailService();

    await mailer.sendPasswordReset({
      to: "user@example.com",
      resetUrl: "https://auth.example.com/reset?token=reset-token"
    });

    expect(nodemailerCreateTransport).toHaveBeenCalledWith({
      host: "smtp.example.com",
      port: 2525,
      secure: false,
      auth: {
        user: "smtp-user",
        pass: "smtp-password"
      }
    });
    expect(sendMail).toHaveBeenCalledWith({
      from: "Auth <auth@example.com>",
      to: "user@example.com",
      subject: "Reset your password",
      text: "Use this link to reset your password: https://auth.example.com/reset?token=reset-token",
      html: expect.stringContaining("https://auth.example.com/reset?token=reset-token")
    });
  });

  it("Given resend mail provider When mail service is created Then Resend SMTP transport is selected", async () => {
    Object.assign(process.env, {
      MAIL_PROVIDER: "resend",
      MAIL_FROM: "TEMIS <no-reply@temis.me>",
      MAIL_REPLY_TO: "contact@temis.me",
      RESEND_API_KEY: "re_test_api_key"
    });
    const sendMail = vi.fn().mockResolvedValue({});
    nodemailerCreateTransport.mockReturnValue({ sendMail });
    const { createMailService } = await import("./mail.service.js");
    const mailer = createMailService();

    await mailer.sendEmailVerification({
      to: "user@example.com",
      verificationUrl: "https://auth.example.com/verify?token=verification-token"
    });

    expect(nodemailerCreateTransport).toHaveBeenCalledWith({
      host: "smtp.resend.com",
      port: 465,
      secure: true,
      auth: {
        user: "resend",
        pass: "re_test_api_key"
      }
    });
    expect(sendMail).toHaveBeenCalledWith({
      from: "TEMIS <no-reply@temis.me>",
      replyTo: "contact@temis.me",
      to: "user@example.com",
      subject: "Verify your email",
      text: "Use this link to verify your email: https://auth.example.com/verify?token=verification-token",
      html: expect.stringContaining("https://auth.example.com/verify?token=verification-token")
    });
  });

  it("Given resend mail provider with admin key name When mail service is created Then Resend SMTP auth uses the fallback key", async () => {
    Object.assign(process.env, {
      MAIL_PROVIDER: "resend",
      MAIL_FROM: "TEMIS <no-reply@temis.me>",
      RESEND_API_KEY: "",
      RESEND_ADMIN_KEY: "re_test_admin_key"
    });
    const sendMail = vi.fn().mockResolvedValue({});
    nodemailerCreateTransport.mockReturnValue({ sendMail });
    const { createMailService } = await import("./mail.service.js");
    const mailer = createMailService();

    await mailer.sendPasswordReset({
      to: "user@example.com",
      resetUrl: "https://auth.example.com/reset?token=reset-token"
    });

    expect(nodemailerCreateTransport).toHaveBeenCalledWith({
      host: "smtp.resend.com",
      port: 465,
      secure: true,
      auth: {
        user: "resend",
        pass: "re_test_admin_key"
      }
    });
    expect(sendMail).toHaveBeenCalledWith(expect.objectContaining({
      from: "TEMIS <no-reply@temis.me>",
      to: "user@example.com",
      subject: "Reset your password"
    }));
  });

  it("Given smtp relay without credentials When mail service is created Then SMTP auth is omitted", async () => {
    Object.assign(process.env, {
      MAIL_PROVIDER: "smtp",
      MAIL_FROM: "Auth <auth@example.com>",
      MAIL_REPLY_TO: "",
      SMTP_HOST: "smtp-relay.gmail.com",
      SMTP_PORT: "587",
      SMTP_USERNAME: "",
      SMTP_PASSWORD: ""
    });
    const sendMail = vi.fn().mockResolvedValue({});
    nodemailerCreateTransport.mockReturnValue({ sendMail });
    const { createMailService } = await import("./mail.service.js");
    const mailer = createMailService();

    await mailer.sendEmailVerification({
      to: "user@example.com",
      verificationUrl: "https://auth.example.com/verify?token=verification-token"
    });

    expect(nodemailerCreateTransport).toHaveBeenCalledWith({
      host: "smtp-relay.gmail.com",
      port: 587,
      secure: false
    });
    expect(sendMail).toHaveBeenCalledWith({
      from: "Auth <auth@example.com>",
      to: "user@example.com",
      subject: "Verify your email",
      text: "Use this link to verify your email: https://auth.example.com/verify?token=verification-token",
      html: expect.stringContaining("https://auth.example.com/verify?token=verification-token")
    });
  });

  it("Given mail dev mode When env is parsed Then SMTP secrets are not required", async () => {
    const { parseEnv } = await import("../config/env.js");
    const parsed = parseEnv({
      ...baseEnv,
      NODE_ENV: "test",
      MAIL_PROVIDER: "dev",
      MAIL_FROM: "Auth <auth@example.com>"
    });

    expect(parsed.MAIL_PROVIDER).toBe("dev");
    expect(parsed.MAIL_FROM).toBe("Auth <auth@example.com>");
  });

  it("Given production SMTP mode without SMTP settings When env is parsed Then config fails before any external delivery", async () => {
    const { parseEnv } = await import("../config/env.js");
    expect(() => parseEnv({
      ...baseEnv,
      NODE_ENV: "production",
      MAIL_PROVIDER: "smtp",
      MAIL_FROM: "Auth <auth@example.com>"
    })).toThrow(/SMTP_HOST/);
  });

  it("Given production SMTP relay mode without SMTP auth When env is parsed Then config accepts IP based relay", async () => {
    const { parseEnv } = await import("../config/env.js");
    const parsed = parseEnv({
      ...baseEnv,
      NODE_ENV: "production",
      MAIL_PROVIDER: "smtp",
      MAIL_FROM: "Auth <auth@example.com>",
      SMTP_HOST: "smtp-relay.gmail.com",
      SMTP_USERNAME: "",
      SMTP_PASSWORD: ""
    });

    expect(parsed.SMTP_HOST).toBe("smtp-relay.gmail.com");
    expect(parsed.SMTP_USERNAME).toBeUndefined();
    expect(parsed.SMTP_PASSWORD).toBeUndefined();
  });

  it("Given production resend mode without API key When env is parsed Then config fails before delivery", async () => {
    const { parseEnv } = await import("../config/env.js");
    expect(() => parseEnv({
      ...baseEnv,
      NODE_ENV: "production",
      MAIL_PROVIDER: "resend",
      MAIL_FROM: "TEMIS <no-reply@temis.me>"
    })).toThrow(/RESEND_API_KEY or RESEND_ADMIN_KEY/);
  });

  it("Given production resend mode with API key When env is parsed Then config accepts Resend delivery settings", async () => {
    const { parseEnv } = await import("../config/env.js");
    const parsed = parseEnv({
      ...baseEnv,
      NODE_ENV: "production",
      MAIL_PROVIDER: "resend",
      MAIL_FROM: "TEMIS <no-reply@temis.me>",
      MAIL_REPLY_TO: "contact@temis.me",
      RESEND_API_KEY: "re_test_api_key"
    });

    expect(parsed.MAIL_PROVIDER).toBe("resend");
    expect(parsed.MAIL_FROM).toBe("TEMIS <no-reply@temis.me>");
    expect(parsed.MAIL_REPLY_TO).toBe("contact@temis.me");
    expect(parsed.RESEND_API_KEY).toBe("re_test_api_key");
  });

  it("Given production resend mode with admin key name When env is parsed Then config accepts the fallback key", async () => {
    const { parseEnv } = await import("../config/env.js");
    const parsed = parseEnv({
      ...baseEnv,
      NODE_ENV: "production",
      MAIL_PROVIDER: "resend",
      MAIL_FROM: "TEMIS <no-reply@temis.me>",
      RESEND_ADMIN_KEY: "re_test_admin_key"
    });

    expect(parsed.MAIL_PROVIDER).toBe("resend");
    expect(parsed.RESEND_API_KEY).toBeUndefined();
    expect(parsed.RESEND_ADMIN_KEY).toBe("re_test_admin_key");
  });
});

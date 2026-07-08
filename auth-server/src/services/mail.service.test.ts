import { beforeEach, describe, expect, it, vi } from "vitest";

const nodemailerCreateTransport = vi.fn();

vi.mock("nodemailer", () => ({
  default: {
    createTransport: nodemailerCreateTransport
  }
}));

const baseEnv = {
  DATABASE_URL: "postgresql://user:password@localhost:5432/auth_db",
  JWT_ACCESS_SECRET: "test-access-secret-long",
  JWT_REFRESH_SECRET: "test-refresh-secret-long",
  JWT_ISSUER: "https://auth.temis.co.kr",
  JWT_AUDIENCE: "temis",
  FRONTEND_REDIRECT_URL: "http://localhost:3000/auth/callback",
  GOOGLE_CLIENT_ID: "google",
  GOOGLE_CLIENT_SECRET: "google-secret",
  GOOGLE_REDIRECT_URI: "http://localhost:4000/auth/google/callback",
  NAVER_CLIENT_ID: "naver",
  NAVER_CLIENT_SECRET: "naver-secret",
  NAVER_REDIRECT_URI: "http://localhost:4000/auth/naver/callback",
  KAKAO_CLIENT_ID: "kakao",
  KAKAO_CLIENT_SECRET: "kakao-secret",
  KAKAO_REDIRECT_URI: "http://localhost:4000/auth/kakao/callback"
} satisfies Record<string, string>;

describe("mail service", () => {
  beforeEach(() => {
    vi.resetModules();
    nodemailerCreateTransport.mockReset();
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
      text: "Use this link to reset your password: https://auth.example.com/reset?token=reset-token"
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
});

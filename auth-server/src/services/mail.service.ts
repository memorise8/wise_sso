import nodemailer from "nodemailer";
import { env } from "../config/env.js";

export type MailLinkMessage = {
  readonly kind: "email-verification" | "password-reset";
  readonly to: string;
  readonly link: string;
};

export type SendEmailVerificationInput = {
  readonly to: string;
  readonly verificationUrl: string;
};

export type SendPasswordResetInput = {
  readonly to: string;
  readonly resetUrl: string;
};

export interface MailService {
  readonly sendEmailVerification: (input: SendEmailVerificationInput) => Promise<void>;
  readonly sendPasswordReset: (input: SendPasswordResetInput) => Promise<void>;
}

export type FakeMailService = MailService & {
  readonly messages: readonly MailLinkMessage[];
};

export type DevMailLogger = {
  readonly info: (message: string, metadata: MailLinkMessage) => void;
};

type CreateMailServiceOptions = {
  readonly logger?: DevMailLogger;
};

type SmtpMailConfig = {
  readonly from: string;
  readonly replyTo?: string;
  readonly host: string;
  readonly port: number;
  readonly username?: string;
  readonly password?: string;
};

const toVerificationMessage = (input: SendEmailVerificationInput): MailLinkMessage => ({
  kind: "email-verification",
  to: input.to,
  link: input.verificationUrl
});

const toResetMessage = (input: SendPasswordResetInput): MailLinkMessage => ({
  kind: "password-reset",
  to: input.to,
  link: input.resetUrl
});

const redactLinkToken = (message: MailLinkMessage): MailLinkMessage => {
  const link = new URL(message.link);
  if (link.searchParams.has("token")) {
    link.searchParams.set("token", "[REDACTED]");
  }

  return {
    ...message,
    link: link.toString()
  };
};

export const createFakeMailService = (): FakeMailService => {
  const messages: MailLinkMessage[] = [];

  return {
    messages,
    sendEmailVerification: async (input) => {
      messages.push(toVerificationMessage(input));
    },
    sendPasswordReset: async (input) => {
      messages.push(toResetMessage(input));
    }
  };
};

export const createDevMailService = (logger: DevMailLogger = console): MailService => ({
  sendEmailVerification: async (input) => {
    logger.info("dev mail captured", redactLinkToken(toVerificationMessage(input)));
  },
  sendPasswordReset: async (input) => {
    logger.info("dev mail captured", redactLinkToken(toResetMessage(input)));
  }
});

const smtpMailConfig = (): SmtpMailConfig => {
  const { MAIL_FROM, MAIL_REPLY_TO, SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD } = env;
  if (!SMTP_HOST) {
    throw new Error("SMTP_HOST is required when MAIL_PROVIDER=smtp");
  }

  return {
    from: MAIL_FROM,
    ...(MAIL_REPLY_TO ? { replyTo: MAIL_REPLY_TO } : {}),
    host: SMTP_HOST,
    port: SMTP_PORT,
    ...(SMTP_USERNAME && SMTP_PASSWORD ? {
      username: SMTP_USERNAME,
      password: SMTP_PASSWORD
    } : {})
  };
};

const resendMailConfig = (): SmtpMailConfig => {
  const apiKey = env.RESEND_API_KEY ?? env.RESEND_ADMIN_KEY;
  if (!apiKey) {
    throw new Error("RESEND_API_KEY or RESEND_ADMIN_KEY is required when MAIL_PROVIDER=resend");
  }

  return {
    from: env.MAIL_FROM,
    ...(env.MAIL_REPLY_TO ? { replyTo: env.MAIL_REPLY_TO } : {}),
    host: "smtp.resend.com",
    port: 465,
    username: "resend",
    password: apiKey
  };
};

const emailVerificationHtml = (verificationUrl: string): string => `
<p>아래 버튼을 눌러 이메일 인증을 완료해 주세요.</p>
<p><a href="${verificationUrl}">이메일 인증하기</a></p>
<p>버튼이 동작하지 않으면 아래 링크를 브라우저에 붙여넣어 주세요.</p>
<p>${verificationUrl}</p>`;

const passwordResetHtml = (resetUrl: string): string => `
<p>아래 버튼을 눌러 새 비밀번호를 설정해 주세요.</p>
<p><a href="${resetUrl}">비밀번호 재설정하기</a></p>
<p>버튼이 동작하지 않으면 아래 링크를 브라우저에 붙여넣어 주세요.</p>
<p>${resetUrl}</p>`;

const createSmtpMailService = (config: SmtpMailConfig): MailService => {
  const auth = config.username && config.password ? {
    user: config.username,
    pass: config.password
  } : undefined;
  const transport = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.port === 465,
    ...(auth ? { auth } : {})
  });

  return {
    sendEmailVerification: async (input) => {
      await transport.sendMail({
        from: config.from,
        ...(config.replyTo ? { replyTo: config.replyTo } : {}),
        to: input.to,
        subject: "Verify your email",
        text: `Use this link to verify your email: ${input.verificationUrl}`,
        html: emailVerificationHtml(input.verificationUrl)
      });
    },
    sendPasswordReset: async (input) => {
      await transport.sendMail({
        from: config.from,
        ...(config.replyTo ? { replyTo: config.replyTo } : {}),
        to: input.to,
        subject: "Reset your password",
        text: `Use this link to reset your password: ${input.resetUrl}`,
        html: passwordResetHtml(input.resetUrl)
      });
    }
  };
};

export const createMailService = (options: CreateMailServiceOptions = {}): MailService => {
  switch (env.MAIL_PROVIDER) {
    case "dev":
      return createDevMailService(options.logger);
    case "smtp":
      return createSmtpMailService(smtpMailConfig());
    case "resend":
      return createSmtpMailService(resendMailConfig());
  }
};

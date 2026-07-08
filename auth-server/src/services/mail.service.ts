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
  const { MAIL_FROM, SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD } = env;
  if (!SMTP_HOST) {
    throw new Error("SMTP_HOST is required when MAIL_PROVIDER=smtp");
  }

  return {
    from: MAIL_FROM,
    host: SMTP_HOST,
    port: SMTP_PORT,
    ...(SMTP_USERNAME && SMTP_PASSWORD ? {
      username: SMTP_USERNAME,
      password: SMTP_PASSWORD
    } : {})
  };
};

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
        to: input.to,
        subject: "Verify your email",
        text: `Use this link to verify your email: ${input.verificationUrl}`
      });
    },
    sendPasswordReset: async (input) => {
      await transport.sendMail({
        from: config.from,
        to: input.to,
        subject: "Reset your password",
        text: `Use this link to reset your password: ${input.resetUrl}`
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
  }
};

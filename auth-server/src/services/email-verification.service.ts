import { createHash, randomBytes } from "node:crypto";
import type { MailService } from "./mail.service.js";
import { HttpError } from "../utils/httpError.js";

export type EmailVerificationUser = {
  readonly id: string;
  readonly email: string | null;
  readonly status: string;
};

export type EmailVerificationTokenRecord = {
  readonly id: string;
  readonly userId: string;
  readonly expiresAt: Date;
  readonly usedAt: Date | null;
};

export type EmailVerificationStore = {
  readonly findUserByEmail: (email: string) => Promise<EmailVerificationUser | null>;
  readonly createVerificationToken: (input: {
    readonly userId: string;
    readonly tokenHash: string;
    readonly expiresAt: Date;
  }) => Promise<void>;
  readonly findVerificationTokenByHash: (tokenHash: string) => Promise<EmailVerificationTokenRecord | null>;
  readonly markTokenUsedAndActivateUser: (input: {
    readonly tokenId: string;
    readonly userId: string;
    readonly usedAt: Date;
  }) => Promise<boolean>;
};

export type EmailVerificationAccepted = {
  readonly status: "accepted";
};

export type EmailVerificationConfirmed = {
  readonly status: "verified";
  readonly userId: string;
};

export type RequestEmailVerificationInput = {
  readonly email: string;
};

export type ConfirmEmailVerificationInput = {
  readonly token: string;
};

export type RequestEmailVerificationContext = {
  readonly store: EmailVerificationStore;
  readonly mailer: MailService;
  readonly input: RequestEmailVerificationInput;
  readonly verificationUrlBase: string;
  readonly now?: () => Date;
};

export type ConfirmEmailVerificationContext = {
  readonly store: EmailVerificationStore;
  readonly input: ConfirmEmailVerificationInput;
  readonly now?: () => Date;
};

const tokenTtlMs = 24 * 60 * 60 * 1000;

const normalizeEmail = (email: string): string => email.trim().toLowerCase();

const createRawToken = (): string => randomBytes(32).toString("base64url");

const hashToken = (token: string): string => createHash("sha256").update(token).digest("hex");

const createVerificationUrl = (baseUrl: string, token: string): string => {
  const url = new URL(baseUrl);
  url.searchParams.set("token", token);
  return url.toString();
};

const invalidVerificationToken = (): HttpError =>
  new HttpError(400, "INVALID_VERIFICATION_TOKEN", "Invalid or expired verification token");

export const requestEmailVerification = async (
  context: RequestEmailVerificationContext
): Promise<EmailVerificationAccepted> => {
  const email = normalizeEmail(context.input.email);
  const user = await context.store.findUserByEmail(email);
  if (!user?.email) {
    return { status: "accepted" };
  }

  const now = context.now ? context.now() : new Date();
  const rawToken = createRawToken();
  await context.store.createVerificationToken({
    userId: user.id,
    tokenHash: hashToken(rawToken),
    expiresAt: new Date(now.getTime() + tokenTtlMs)
  });
  await context.mailer.sendEmailVerification({
    to: user.email,
    verificationUrl: createVerificationUrl(context.verificationUrlBase, rawToken)
  });

  return { status: "accepted" };
};

export const confirmEmailVerification = async (
  context: ConfirmEmailVerificationContext
): Promise<EmailVerificationConfirmed> => {
  const now = context.now ? context.now() : new Date();
  const token = await context.store.findVerificationTokenByHash(hashToken(context.input.token));
  if (!token || token.usedAt || token.expiresAt <= now) {
    throw invalidVerificationToken();
  }

  const consumed = await context.store.markTokenUsedAndActivateUser({
    tokenId: token.id,
    userId: token.userId,
    usedAt: now
  });
  if (!consumed) {
    throw invalidVerificationToken();
  }

  return { status: "verified", userId: token.userId };
};

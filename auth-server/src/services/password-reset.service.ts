import { createHash, randomBytes } from "node:crypto";
import argon2 from "argon2";
import type { MailService } from "./mail.service.js";
import { HttpError } from "../utils/httpError.js";

export type PasswordResetUser = {
  readonly id: string;
  readonly email: string;
};

export type CreateResetTokenInput = {
  readonly userId: string;
  readonly tokenHash: string;
  readonly expiresAt: Date;
};

export type ResetPasswordWithTokenInput = {
  readonly tokenHash: string;
  readonly passwordHash: string;
  readonly now: Date;
};

export type ResetPasswordWithTokenResult = {
  readonly userId: string;
};

export type PasswordResetStore = {
  readonly findUserByEmail: (email: string) => Promise<PasswordResetUser | null>;
  readonly createResetToken: (input: CreateResetTokenInput) => Promise<void>;
  readonly resetPasswordWithToken: (input: ResetPasswordWithTokenInput) => Promise<ResetPasswordWithTokenResult | null>;
};

export type RequestPasswordResetInput = {
  readonly email: string;
  readonly resetUrlBase: string;
  readonly now?: Date;
};

export type ConfirmPasswordResetInput = {
  readonly token: string;
  readonly password: string;
  readonly now?: Date;
};

export type PasswordResetPolicy = {
  readonly minLength: number;
  readonly allowedEmailDomain: string | null;
};

type AcceptedResult = {
  readonly status: "accepted";
};

export type PasswordResetConfirmed = {
  readonly userId: string;
};

const resetTokenTtlMs = 60 * 60 * 1000;

const normalizeEmail = (email: string): string => email.trim().toLowerCase();

const hashToken = (token: string): string => createHash("sha256").update(token).digest("hex");

const hashPassword = async (password: string): Promise<string> =>
  argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19_456,
    timeCost: 2,
    parallelism: 1
  });

const assertPasswordPolicy = (password: string, policy: PasswordResetPolicy): void => {
  if (password.length < policy.minLength) {
    throw new HttpError(400, "WEAK_PASSWORD", `Password must be at least ${policy.minLength} characters`);
  }
};

const buildResetUrl = (resetUrlBase: string, token: string): string => {
  const resetUrl = new URL(resetUrlBase);
  resetUrl.searchParams.set("token", token);
  return resetUrl.toString();
};

export const requestPasswordReset = async (
  store: PasswordResetStore,
  mailer: MailService,
  input: RequestPasswordResetInput
): Promise<AcceptedResult> => {
  const email = normalizeEmail(input.email);
  const user = await store.findUserByEmail(email);
  if (!user) {
    return { status: "accepted" };
  }

  const now = input.now ?? new Date();
  const token = randomBytes(32).toString("base64url");
  await store.createResetToken({
    userId: user.id,
    tokenHash: hashToken(token),
    expiresAt: new Date(now.getTime() + resetTokenTtlMs)
  });
  await mailer.sendPasswordReset({
    to: user.email,
    resetUrl: buildResetUrl(input.resetUrlBase, token)
  });

  return { status: "accepted" };
};

export const confirmPasswordReset = async (
  store: PasswordResetStore,
  input: ConfirmPasswordResetInput,
  policy: PasswordResetPolicy = { minLength: 12, allowedEmailDomain: null }
): Promise<PasswordResetConfirmed> => {
  assertPasswordPolicy(input.password, policy);
  const reset = await store.resetPasswordWithToken({
    tokenHash: hashToken(input.token),
    passwordHash: await hashPassword(input.password),
    now: input.now ?? new Date()
  });
  if (!reset) {
    throw new HttpError(400, "INVALID_RESET_TOKEN", "Invalid or expired reset token");
  }

  return { userId: reset.userId };
};

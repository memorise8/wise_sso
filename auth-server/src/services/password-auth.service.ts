import argon2 from "argon2";
import type { CurrentUser } from "./user.service.js";
import { HttpError } from "../utils/httpError.js";

export type PasswordAuthInput = {
  readonly email: string;
  readonly password: string;
};

export type RegisterPasswordInput = PasswordAuthInput & {
  readonly name: string | null;
};

export type PasswordPolicy = {
  readonly minLength: number;
  readonly allowedEmailDomain: string | null;
};

export type PasswordCredentialRecord = {
  readonly userId: string;
  readonly email: string;
  readonly passwordHash: string;
  readonly failedLoginCount: number;
  readonly lockedUntil: Date | null;
  readonly userStatus: string;
};

export type PasswordAuthStore = {
  readonly findUserByEmail: (email: string) => Promise<CurrentUser | null>;
  readonly createUserWithPassword: (input: {
    readonly email: string;
    readonly name: string | null;
    readonly passwordHash: string;
    readonly status: string;
  }) => Promise<CurrentUser>;
  readonly findCredentialByEmail: (email: string) => Promise<PasswordCredentialRecord | null>;
  readonly markLoginSuccess: (userId: string) => Promise<void>;
  readonly markLoginFailure: (userId: string) => Promise<void>;
  readonly getCurrentUser: (userId: string) => Promise<CurrentUser | null>;
};

type PasswordAuthResult = {
  readonly user: CurrentUser;
};

type PasswordAuthFailureAudit = {
  readonly userId: string | null;
  readonly reasonCode: "ACCOUNT_LOCKED" | "INVALID_CREDENTIALS" | "USER_INACTIVE";
};

class PasswordAuthFailure extends HttpError {
  public readonly audit: PasswordAuthFailureAudit;

  public constructor(audit: PasswordAuthFailureAudit) {
    super(401, "INVALID_CREDENTIALS", "Invalid email or password");
    this.audit = audit;
  }
}

const normalizeEmail = (email: string): string => email.trim().toLowerCase();

const hashPassword = async (password: string): Promise<string> =>
  argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19_456,
    timeCost: 2,
    parallelism: 1
  });

const defaultPasswordPolicy: PasswordPolicy = {
  minLength: 12,
  allowedEmailDomain: null
};

const passwordRegistrationInitialStatus = "pending_verification";

const dummyPasswordHash = "$argon2id$v=19$m=19456,t=2,p=1$SdlW23hIuyR5YOcdnZi8wg$U6czHfbJGnRhZehGLUmnc9E06qyzWWjlouMxjSv3gTM";

const assertPasswordPolicy = (email: string, password: string, policy: PasswordPolicy): void => {
  if (password.length < policy.minLength) {
    throw new HttpError(400, "WEAK_PASSWORD", `Password must be at least ${policy.minLength} characters`);
  }

  if (policy.allowedEmailDomain && !email.endsWith(`@${policy.allowedEmailDomain}`)) {
    throw new HttpError(403, "EMAIL_DOMAIN_NOT_ALLOWED", "Email domain is not allowed");
  }
};

const isCredentialLocked = (credential: PasswordCredentialRecord): boolean =>
  credential.lockedUntil !== null && credential.lockedUntil > new Date();

export const isPasswordAuthFailure = (error: unknown): error is PasswordAuthFailure =>
  error instanceof PasswordAuthFailure;

export const registerWithPassword = async (
  store: PasswordAuthStore,
  input: RegisterPasswordInput,
  policy: PasswordPolicy = defaultPasswordPolicy
): Promise<PasswordAuthResult> => {
  const email = normalizeEmail(input.email);
  assertPasswordPolicy(email, input.password, policy);
  const passwordHash = await hashPassword(input.password);

  const existingUser = await store.findUserByEmail(email);
  if (existingUser) {
    return { user: existingUser };
  }

  const user = await store.createUserWithPassword({
    email,
    name: input.name,
    passwordHash,
    status: passwordRegistrationInitialStatus
  });

  return { user };
};

export const loginWithPassword = async (
  store: PasswordAuthStore,
  input: PasswordAuthInput
): Promise<PasswordAuthResult> => {
  const email = normalizeEmail(input.email);
  const credential = await store.findCredentialByEmail(email);
  const verified = await argon2.verify(credential?.passwordHash ?? dummyPasswordHash, input.password);
  const credentialLocked = credential ? isCredentialLocked(credential) : false;
  const canLogin = credential && credential.userStatus === "active" && !credentialLocked && verified;
  if (!canLogin) {
    if (credential && credential.userStatus === "active" && !credentialLocked) {
      await store.markLoginFailure(credential.userId);
    }
    throw new PasswordAuthFailure({
      userId: credential?.userId ?? null,
      reasonCode: credentialLocked ? "ACCOUNT_LOCKED" : credential?.userStatus === "active" ? "INVALID_CREDENTIALS" : "USER_INACTIVE"
    });
  }

  await store.markLoginSuccess(credential.userId);
  const user = await store.getCurrentUser(credential.userId);
  if (!user) {
    throw new HttpError(401, "INVALID_CREDENTIALS", "Invalid email or password");
  }

  return { user };
};

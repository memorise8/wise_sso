import type { Request } from "express";

export const auditEventTypes = {
  registerRequest: "register_request",
  loginSuccess: "login_success",
  loginFailure: "login_failure",
  lockout: "lockout",
  emailVerificationRequest: "email_verification_request",
  emailVerificationConfirm: "email_verification_confirm",
  passwordResetRequest: "password_reset_request",
  passwordResetConfirm: "password_reset_confirm",
  refresh: "refresh",
  logout: "logout"
} as const;

export type AuthAuditEventType = typeof auditEventTypes[keyof typeof auditEventTypes];

export type AuthAuditOutcome = "request" | "success" | "failure";

export type AuthAuditEvent = {
  readonly eventType: AuthAuditEventType;
  readonly outcome: AuthAuditOutcome;
  readonly userId: string | null;
  readonly provider?: string;
  readonly serviceKey?: string;
  readonly ipAddress?: string;
  readonly userAgent?: string;
  readonly reasonCode?: string;
};

export type AuditLogStore = {
  readonly create: (event: AuthAuditEvent) => Promise<void>;
  readonly findUserIdByEmail: (email: string) => Promise<string | null>;
  readonly findUserIdByPasswordEmail: (email: string) => Promise<string | null>;
};

type AuditRequestContext = Pick<AuthAuditEvent, "ipAddress" | "userAgent">;

type LoginFailureAuditInput = AuditRequestContext & {
  readonly email: string;
  readonly reasonCode: string;
  readonly userId?: string | null;
};

const normalizeEmail = (email: string): string => email.trim().toLowerCase();

export const auditContextFromRequest = (request: Request): AuditRequestContext => {
  const forwardedFor = request.header("x-forwarded-for")?.split(",")[0]?.trim();
  const ipAddress = forwardedFor || request.ip;
  const userAgent = request.header("user-agent") ?? undefined;

  return {
    ...(ipAddress ? { ipAddress } : {}),
    ...(userAgent ? { userAgent } : {})
  };
};

export const recordAuthAuditEvent = async (store: AuditLogStore, event: AuthAuditEvent): Promise<void> => {
  await store.create(event);
};

export const recordLoginFailureAuditEvent = async (
  store: AuditLogStore,
  input: LoginFailureAuditInput
): Promise<void> => {
  const userId = input.userId ?? await store.findUserIdByPasswordEmail(normalizeEmail(input.email));
  await recordAuthAuditEvent(store, {
    eventType: input.reasonCode === "ACCOUNT_LOCKED" ? auditEventTypes.lockout : auditEventTypes.loginFailure,
    outcome: "failure",
    userId,
    ...(input.ipAddress ? { ipAddress: input.ipAddress } : {}),
    ...(input.userAgent ? { userAgent: input.userAgent } : {}),
    reasonCode: input.reasonCode
  });
};

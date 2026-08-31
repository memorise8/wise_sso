import type { Request } from "express";
import { HttpError } from "../utils/httpError.js";

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
  logout: "logout",
  adminUserStatusChanged: "admin_user_status_changed",
  adminUserRoleAssigned: "admin_user_role_assigned",
  adminUserRoleRemoved: "admin_user_role_removed",
  adminUserSessionsRevoked: "admin_user_sessions_revoked",
  adminAuthorizationFailure: "admin_authorization_failure",
  authHandoffExchangeSuccess: "auth_handoff_exchange_success",
  authHandoffExchangeFailure: "auth_handoff_exchange_failure",
  rateLimitExceeded: "rate_limit_exceeded"
} as const;

export type AuthAuditEventType = typeof auditEventTypes[keyof typeof auditEventTypes];

export type AuthAuditOutcome = "request" | "success" | "failure";

export type AdminAuditDetailsValue = string | number | boolean | null;

export type AdminAuditDetails = Readonly<Record<string, AdminAuditDetailsValue>>;

export type AuthAuditEvent = {
  readonly eventType: AuthAuditEventType;
  readonly outcome: AuthAuditOutcome;
  readonly userId: string | null;
  readonly actorUserId?: string | null;
  readonly targetUserId?: string | null;
  readonly provider?: string;
  readonly serviceKey?: string;
  readonly ipAddress?: string;
  readonly userAgent?: string;
  readonly reasonCode?: string;
  readonly detailsJson?: AdminAuditDetails;
};

export type AuditLogStore = {
  readonly create: (event: AuthAuditEvent) => Promise<void>;
  readonly findUserIdByEmail: (email: string) => Promise<string | null>;
  readonly findUserIdByPasswordEmail: (email: string) => Promise<string | null>;
};

export type AuditLogListInput = {
  readonly page: number;
  readonly pageSize: number;
  readonly createdAtFrom?: Date;
  readonly createdAtTo?: Date;
  readonly eventType?: string;
  readonly outcome?: AuthAuditOutcome;
  readonly userId?: string;
  readonly actorUserId?: string;
  readonly targetUserId?: string;
  readonly reasonCode?: string;
};

export type StoredAuditLogRecord = {
  readonly id: string;
  readonly eventType: string;
  readonly outcome: string;
  readonly userId: string | null;
  readonly actorUserId: string | null;
  readonly targetUserId: string | null;
  readonly reasonCode: string | null;
  readonly detailsJson: unknown;
  readonly createdAt: Date;
};

export type AuditLogQueryStore = {
  readonly queryAuditLogs: (input: AuditLogListInput) => Promise<{
    readonly items: readonly StoredAuditLogRecord[];
    readonly total: number;
  }>;
};

export type AdminAuditLogListItem = {
  readonly id: string;
  readonly eventType: string;
  readonly outcome: string;
  readonly userId: string | null;
  readonly actorUserId: string | null;
  readonly targetUserId: string | null;
  readonly reasonCode: string | null;
  readonly detailsJson?: AdminAuditDetails;
  readonly createdAt: string;
};

export type AdminAuditLogListResult = {
  readonly items: readonly AdminAuditLogListItem[];
  readonly total: number;
  readonly page: number;
  readonly pageSize: number;
};

type AuditRequestContext = Pick<AuthAuditEvent, "ipAddress" | "userAgent">;

type LoginFailureAuditInput = AuditRequestContext & {
  readonly email: string;
  readonly reasonCode: string;
  readonly userId?: string | null;
};

export type AdminAuditEventInput = {
  readonly eventType: Extract<
    AuthAuditEventType,
    | "admin_user_status_changed"
    | "admin_user_role_assigned"
    | "admin_user_role_removed"
    | "admin_user_sessions_revoked"
  >;
  readonly actorUserId: string | null;
  readonly targetUserId: string | null;
  readonly reasonCode: string;
  readonly details?: AdminAuditDetails;
};

const sensitiveDetailKeyPattern = /(token|password|secret|code|email)/i;

const sensitiveDetailValuePattern = /(token|password|secret|Bearer\s+|oauth-code|handoff-code)/i;

const emailLikeDetailValuePattern = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i;

const maxDetailsJsonBytes = 2048;

const redactedAuditValue = "[REDACTED]";

const normalizeEmail = (email: string): string => email.trim().toLowerCase();

const redactAuditDetailsRecord = (details: Readonly<Record<string, unknown>>): AdminAuditDetails => {
  const sanitizedDetails: Record<string, AdminAuditDetailsValue> = {};
  for (const [key, value] of Object.entries(details)) {
    if (sensitiveDetailKeyPattern.test(key)) {
      sanitizedDetails[key] = redactedAuditValue;
    } else if (typeof value === "string" && (sensitiveDetailValuePattern.test(value) || emailLikeDetailValuePattern.test(value))) {
      sanitizedDetails[key] = redactedAuditValue;
    } else if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value === null) {
      sanitizedDetails[key] = value;
    } else {
      sanitizedDetails[key] = redactedAuditValue;
    }
  }
  return sanitizedDetails;
};

const isAuditDetailsRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const sanitizeAdminAuditDetails = (details: AdminAuditDetails | undefined): AdminAuditDetails | undefined => {
  if (!details) {
    return undefined;
  }

  const sanitizedDetails = redactAuditDetailsRecord(details);

  if (JSON.stringify(sanitizedDetails).length > maxDetailsJsonBytes) {
    throw new HttpError(400, "AUDIT_DETAILS_TOO_LARGE", "Audit details exceed allowed size");
  }

  return sanitizedDetails;
};

export const sanitizeAuditDetailsForRead = (detailsJson: unknown): AdminAuditDetails | undefined => {
  if (!isAuditDetailsRecord(detailsJson)) {
    return undefined;
  }

  const sanitizedDetails = redactAuditDetailsRecord(detailsJson);
  if (JSON.stringify(sanitizedDetails).length > maxDetailsJsonBytes) {
    return { truncated: true };
  }

  return sanitizedDetails;
};

const adminAuditLogListItem = (item: StoredAuditLogRecord): AdminAuditLogListItem => {
  const detailsJson = sanitizeAuditDetailsForRead(item.detailsJson);
  const baseItem = {
    id: item.id,
    eventType: item.eventType,
    outcome: item.outcome,
    userId: item.userId,
    actorUserId: item.actorUserId,
    targetUserId: item.targetUserId,
    reasonCode: item.reasonCode,
    createdAt: item.createdAt.toISOString()
  };

  return detailsJson ? { ...baseItem, detailsJson } : baseItem;
};

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
  const detailsJson = sanitizeAdminAuditDetails(event.detailsJson);
  await store.create({
    ...event,
    ...(detailsJson ? { detailsJson } : {})
  });
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

export const recordAdminAuditEvent = async (
  store: AuditLogStore,
  input: AdminAuditEventInput
): Promise<void> => {
  const detailsJson = sanitizeAdminAuditDetails(input.details);
  await recordAuthAuditEvent(store, {
    eventType: input.eventType,
    outcome: "success",
    userId: input.targetUserId,
    actorUserId: input.actorUserId,
    targetUserId: input.targetUserId,
    reasonCode: input.reasonCode,
    ...(detailsJson ? { detailsJson } : {})
  });
};

export const listAdminAuditLogs = async (
  store: AuditLogQueryStore,
  input: AuditLogListInput
): Promise<AdminAuditLogListResult> => {
  const result = await store.queryAuditLogs(input);
  return {
    items: result.items.map(adminAuditLogListItem),
    total: result.total,
    page: input.page,
    pageSize: input.pageSize
  };
};

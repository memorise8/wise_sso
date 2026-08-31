import { describe, expect, it } from "vitest";
import {
  auditEventTypes,
  sanitizeAuditDetailsForRead,
  recordAdminAuditEvent,
  recordAuthAuditEvent,
  recordLoginFailureAuditEvent
} from "./audit.service.js";
import type { AuditLogStore, AuthAuditEvent } from "./audit.service.js";

const forbiddenValues = [
  "plain-password-123",
  "provider-access-token",
  "raw-reset-token",
  "raw-refresh-token",
  "Bearer raw-access-token",
  "oauth-code-sentinel-10",
  "handoff-code-sentinel-10",
  "smtp-secret-sentinel-10",
  "jwt-secret-sentinel-10",
  "person@example.test"
] as const;

const expectNoSensitiveValues = (event: AuthAuditEvent): void => {
  const serialized = JSON.stringify(event);
  for (const forbiddenValue of forbiddenValues) {
    expect(serialized).not.toContain(forbiddenValue);
  }
};

const createStore = (): AuditLogStore & { readonly events: AuthAuditEvent[] } => {
  const events: AuthAuditEvent[] = [];

  return {
    events,
    create: async (event) => {
      events.push(event);
    },
    findUserIdByEmail: async (email) => email === "user@company.com" ? "user-1" : null,
    findUserIdByPasswordEmail: async (email) => email === "user@company.com" ? "user-1" : null
  };
};

describe("audit service", () => {
  it("Given a register request When recording an audit event Then event type user id and request context are stored without secrets", async () => {
    const store = createStore();

    await recordAuthAuditEvent(store, {
      eventType: auditEventTypes.registerRequest,
      outcome: "request",
      userId: "user-1",
      ipAddress: "203.0.113.10",
      userAgent: "Vitest Browser"
    });

    expect(store.events).toEqual([
      {
        eventType: "register_request",
        outcome: "request",
        userId: "user-1",
        ipAddress: "203.0.113.10",
        userAgent: "Vitest Browser"
      }
    ]);
    expectNoSensitiveValues(store.events[0]);
  });

  it("Given a known credential email When login failure is recorded Then the audit row uses the auth user id and no password fields", async () => {
    const store = createStore();

    await recordLoginFailureAuditEvent(store, {
      email: "USER@Company.com",
      reasonCode: "INVALID_CREDENTIALS",
      ipAddress: "203.0.113.10",
      userAgent: "Vitest Browser"
    });

    expect(store.events).toEqual([
      {
        eventType: "login_failure",
        outcome: "failure",
        userId: "user-1",
        ipAddress: "203.0.113.10",
        userAgent: "Vitest Browser",
        reasonCode: "INVALID_CREDENTIALS"
      }
    ]);
    expectNoSensitiveValues(store.events[0]);
  });

  it("Given admin audit metadata includes token-like values When recording the event Then actor target and redacted details are stored", async () => {
    const store = createStore();

    await recordAdminAuditEvent(store, {
      eventType: auditEventTypes.adminUserRoleAssigned,
      actorUserId: "admin-user",
      targetUserId: "target-user",
      reasonCode: "ADMIN_PROMOTE",
      details: {
        serviceKey: "temis",
        roleName: "user",
        refreshToken: "raw-refresh-token"
      }
    });

    expect(store.events).toEqual([
      {
        eventType: "admin_user_role_assigned",
        outcome: "success",
        userId: "target-user",
        actorUserId: "admin-user",
        targetUserId: "target-user",
        reasonCode: "ADMIN_PROMOTE",
        detailsJson: {
          serviceKey: "temis",
          roleName: "user",
          refreshToken: "[REDACTED]"
        }
      }
    ]);
    expectNoSensitiveValues(store.events[0]);
  });

  it("Given email-like PII appears under neutral audit detail keys When recording the event Then details are redacted before persistence", async () => {
    const store = createStore();

    await recordAdminAuditEvent(store, {
      eventType: auditEventTypes.adminUserStatusChanged,
      actorUserId: "admin-user",
      targetUserId: "target-user",
      reasonCode: "ADMIN_DISABLE",
      details: {
        previousValue: "person@example.test",
        note: "Reviewed login for other.person+case@example.test",
        status: "disabled"
      }
    });

    expect(store.events).toEqual([
      {
        eventType: "admin_user_status_changed",
        outcome: "success",
        userId: "target-user",
        actorUserId: "admin-user",
        targetUserId: "target-user",
        reasonCode: "ADMIN_DISABLE",
        detailsJson: {
          previousValue: "[REDACTED]",
          note: "[REDACTED]",
          status: "disabled"
        }
      }
    ]);
    expectNoSensitiveValues(store.events[0]);
  });

  it("Given stored audit details contain email-like PII under neutral keys When formatting for read Then details are redacted before output", () => {
    const sanitizedDetails = sanitizeAuditDetailsForRead({
      previousValue: "person@example.test",
      note: "Reviewed login for other.person+case@example.test",
      status: "disabled"
    });

    expect(sanitizedDetails).toEqual({
      previousValue: "[REDACTED]",
      note: "[REDACTED]",
      status: "disabled"
    });
    expect(JSON.stringify(sanitizedDetails)).not.toContain("person@example.test");
    expect(JSON.stringify(sanitizedDetails)).not.toContain("other.person+case@example.test");
  });

  it("Given todo 10 audit surfaces When event types are exported Then handoff and rate-limit observability names exist", () => {
    expect(auditEventTypes).toMatchObject({
      adminUserStatusChanged: "admin_user_status_changed",
      adminUserRoleAssigned: "admin_user_role_assigned",
      adminUserRoleRemoved: "admin_user_role_removed",
      adminUserSessionsRevoked: "admin_user_sessions_revoked",
      adminAuthorizationFailure: "admin_authorization_failure",
      authHandoffExchangeSuccess: "auth_handoff_exchange_success",
      authHandoffExchangeFailure: "auth_handoff_exchange_failure",
      rateLimitExceeded: "rate_limit_exceeded"
    });
  });

  it("Given sentinel secrets and PII in audit metadata When recording handoff failure Then details are bounded and retention-safe", async () => {
    const store = createStore();

    await recordAuthAuditEvent(store, {
      eventType: auditEventTypes.authHandoffExchangeFailure,
      outcome: "failure",
      userId: null,
      reasonCode: "INVALID_AUTH_HANDOFF_CODE",
      detailsJson: {
        oauthCode: "oauth-code-sentinel-10",
        handoffCode: "handoff-code-sentinel-10",
        refreshToken: "raw-refresh-token",
        accessToken: "provider-access-token",
        smtpSecret: "smtp-secret-sentinel-10",
        jwtSecret: "jwt-secret-sentinel-10",
        targetEmail: "person@example.test",
        clientId: "temis",
        route: "/auth/exchange"
      }
    });

    expect(store.events).toEqual([{
      eventType: "auth_handoff_exchange_failure",
      outcome: "failure",
      userId: null,
      reasonCode: "INVALID_AUTH_HANDOFF_CODE",
      detailsJson: {
        oauthCode: "[REDACTED]",
        handoffCode: "[REDACTED]",
        refreshToken: "[REDACTED]",
        accessToken: "[REDACTED]",
        smtpSecret: "[REDACTED]",
        jwtSecret: "[REDACTED]",
        targetEmail: "[REDACTED]",
        clientId: "temis",
        route: "/auth/exchange"
      }
    }]);
    expect(JSON.stringify(store.events[0]?.detailsJson).length).toBeLessThanOrEqual(2048);
    expectNoSensitiveValues(store.events[0]);
  });

  it("Given oversized audit metadata When recording a rate-limit event Then persistence is rejected before storage", async () => {
    const store = createStore();

    await expect(recordAuthAuditEvent(store, {
      eventType: auditEventTypes.rateLimitExceeded,
      outcome: "failure",
      userId: null,
      reasonCode: "RATE_LIMITED",
      detailsJson: {
        route: "/auth/login",
        note: "x".repeat(3000)
      }
    })).rejects.toMatchObject({
      statusCode: 400,
      code: "AUDIT_DETAILS_TOO_LARGE"
    });
    expect(store.events).toHaveLength(0);
  });
});

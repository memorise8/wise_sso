import { describe, expect, it } from "vitest";
import {
  auditEventTypes,
  recordAuthAuditEvent,
  recordLoginFailureAuditEvent
} from "./audit.service.js";
import type { AuditLogStore, AuthAuditEvent } from "./audit.service.js";

const forbiddenValues = [
  "plain-password-123",
  "provider-access-token",
  "raw-reset-token",
  "raw-refresh-token",
  "Bearer raw-access-token"
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
});

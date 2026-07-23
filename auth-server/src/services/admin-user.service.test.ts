import { describe, expect, it } from "vitest";
import { HttpError } from "../utils/httpError.js";
import { createAdminUserService } from "./admin-user.service.js";
import { createMutationStore, createState } from "./admin-user.service.test-support.js";

describe("admin user service", () => {
  it("Given a status change to suspended When admin updates the user Then status token revocation and audit are committed atomically", async () => {
    const now = new Date("2026-07-22T02:00:00.000Z");
    const store = createMutationStore(createState());
    const service = createAdminUserService(store);

    const result = await service.setUserStatus({
      actorUserId: "admin-user",
      targetUserId: "target-user",
      status: "SUSPENDED",
      reasonCode: "ADMIN_SUSPEND",
      now,
      details: { source: "service-test", refreshToken: "raw-refresh-token" }
    });

    expect(result).toEqual({ statusChanged: true, revokedRefreshTokenCount: 2 });
    expect(store.state.users.get("target-user")?.status).toBe("SUSPENDED");
    expect(store.state.refreshTokens.filter((refreshToken) => refreshToken.userId === "target-user" && refreshToken.revokedAt === now)).toHaveLength(2);
    expect(store.state.refreshTokens.find((refreshToken) => refreshToken.userId === "other-user")?.revokedAt).toBeNull();
    expect(store.state.auditLogs).toEqual([{
      actorUserId: "admin-user",
      targetUserId: "target-user",
      eventType: "admin_user_status_changed",
      outcome: "success",
      reasonCode: "ADMIN_SUSPEND",
      detailsJson: { source: "service-test", refreshToken: "[REDACTED]" }
    }]);
  });

  it("Given audit write fails during status change When admin updates the user Then status and token revocation are rolled back", async () => {
    const state = createState();
    const store = createMutationStore(state, { failAudit: true });
    const service = createAdminUserService(store);

    await expect(service.setUserStatus({
      actorUserId: "admin-user",
      targetUserId: "target-user",
      status: "SUSPENDED",
      reasonCode: "ADMIN_SUSPEND",
      now: new Date("2026-07-22T02:00:00.000Z")
    })).rejects.toMatchObject(new HttpError(503, "AUDIT_WRITE_FAILED", "Audit write failed"));

    expect(state.users.get("target-user")?.status).toBe("ACTIVE");
    expect(state.refreshTokens.filter((refreshToken) => refreshToken.userId === "target-user" && refreshToken.revokedAt !== null)).toHaveLength(0);
    expect(state.auditLogs).toHaveLength(0);
  });

  it("Given a role assignment is repeated When admin assigns the same role twice Then the role mutation is idempotent", async () => {
    const store = createMutationStore(createState());
    const service = createAdminUserService(store);

    const firstResult = await service.assignRole({
      actorUserId: "admin-user",
      targetUserId: "target-user",
      serviceKey: "temis",
      name: "user",
      reasonCode: "ADMIN_PROMOTE"
    });
    const secondResult = await service.assignRole({
      actorUserId: "admin-user",
      targetUserId: "target-user",
      serviceKey: "temis",
      name: "user",
      reasonCode: "ADMIN_PROMOTE"
    });

    expect(firstResult).toEqual({ roleAssigned: true, roleId: "role-1" });
    expect(secondResult).toEqual({ roleAssigned: false, roleId: "role-1" });
    expect(store.state.userRoles).toHaveLength(1);
    expect(store.state.auditLogs.filter((auditLog) => auditLog.eventType === "admin_user_role_assigned")).toHaveLength(1);
  });

  it("Given malformed role input When admin assigns a role Then the service rejects before transaction work", async () => {
    const store = createMutationStore(createState());
    const service = createAdminUserService(store);

    await expect(service.assignRole({
      actorUserId: "admin-user",
      targetUserId: "target-user",
      serviceKey: " ",
      name: "user",
      reasonCode: "ADMIN_PROMOTE"
    })).rejects.toMatchObject(new HttpError(400, "INVALID_ROLE", "Role service key and name are required"));
    expect(store.state.roles).toHaveLength(0);
    expect(store.state.userRoles).toHaveLength(0);
    expect(store.state.auditLogs).toHaveLength(0);
  });

  it("Given an assigned role and active refresh tokens When admin removes the role Then role removal revokes tokens and records audit", async () => {
    const store = createMutationStore(createState());
    const service = createAdminUserService(store);
    await service.assignRole({
      actorUserId: "admin-user",
      targetUserId: "target-user",
      serviceKey: "temis",
      name: "user",
      reasonCode: "ADMIN_PROMOTE"
    });
    store.state.auditLogs.splice(0, store.state.auditLogs.length);

    const result = await service.removeRole({
      actorUserId: "admin-user",
      targetUserId: "target-user",
      serviceKey: "temis",
      name: "user",
      reasonCode: "ADMIN_ROLE_REMOVE",
      details: { route: "service-test", refreshToken: "raw-refresh-token" }
    });

    expect(result).toEqual({ roleRemoved: true, roleId: "role-1", revokedRefreshTokenCount: 2 });
    expect(store.state.userRoles).toHaveLength(0);
    expect(store.state.refreshTokens.filter((refreshToken) => refreshToken.userId === "target-user" && refreshToken.revokedAt !== null)).toHaveLength(2);
    expect(store.state.auditLogs).toEqual([{
      actorUserId: "admin-user",
      targetUserId: "target-user",
      eventType: "admin_user_role_removed",
      outcome: "success",
      reasonCode: "ADMIN_ROLE_REMOVE",
      detailsJson: { route: "service-test", refreshToken: "[REDACTED]" }
    }]);
  });

  it("Given active refresh tokens When admin explicitly revokes sessions Then tokens are revoked and audit is recorded", async () => {
    const now = new Date("2026-07-22T05:00:00.000Z");
    const store = createMutationStore(createState());
    const service = createAdminUserService(store);

    const result = await service.revokeSessions({
      actorUserId: "admin-user",
      targetUserId: "target-user",
      reasonCode: "ADMIN_REVOKE_SESSIONS",
      now,
      details: { route: "service-test", resetCode: "one-time-code" }
    });

    expect(result).toEqual({ revokedCount: 2 });
    expect(store.state.refreshTokens.filter((refreshToken) => refreshToken.userId === "target-user" && refreshToken.revokedAt === now)).toHaveLength(2);
    expect(store.state.auditLogs).toEqual([{
      actorUserId: "admin-user",
      targetUserId: "target-user",
      eventType: "admin_user_sessions_revoked",
      outcome: "success",
      reasonCode: "ADMIN_REVOKE_SESSIONS",
      detailsJson: { route: "service-test", resetCode: "[REDACTED]" }
    }]);
  });

  it("Given malformed status input When admin updates status Then the service rejects before mutation", async () => {
    const state = createState();
    const store = createMutationStore(state);
    const service = createAdminUserService(store);

    await expect(service.setUserStatus({
      actorUserId: "admin-user",
      targetUserId: "target-user",
      status: "disabled",
      reasonCode: "ADMIN_STATUS"
    })).rejects.toMatchObject(new HttpError(400, "INVALID_USER_STATUS", "Unsupported user status"));
    expect(state.users.get("target-user")?.status).toBe("ACTIVE");
  });
});

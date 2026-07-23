// allow: SIZE_OK - Admin route authorization, audit, and user-management contract cases share one mocked app/store matrix for this final blocker pass; splitting during concurrent auth work would obscure regression coverage.
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import {
  adminRouteAuthAuditEvents,
  adminRouteStoreState,
  loadAdminTestApp,
  mocks,
  resetAdminRouteMocks
} from "./admin.routes.test-support.js";

const activeAdmin = {
  id: "admin-user",
  email: "admin@example.test",
  name: "Admin",
  status: "ACTIVE",
  roles: [{ serviceKey: "temis", name: "admin" }]
} as const;

const activeNonAdmin = {
  id: "non-admin-user",
  email: "operator@example.test",
  name: "Operator",
  status: "ACTIVE",
  roles: [{ serviceKey: "temis", name: "user" }]
} as const;

describe("admin routes", () => {
  beforeEach(() => {
    resetAdminRouteMocks();
    mocks.verifyAccessToken.mockReturnValue("admin-user");
    mocks.getCurrentUserWithStatus.mockResolvedValue(activeAdmin);
  });

  it("Given an active DB-backed TEMIS admin When GET /admin/users includes filters Then it returns the paged minimal profile list", async () => {
    const app = await loadAdminTestApp();
    mocks.listAdminUsers.mockResolvedValue({
      items: [{
        id: "target-user",
        email: "target@example.test",
        name: "Target",
        status: "ACTIVE",
        createdAt: "2026-07-22T03:00:00.000Z",
        roles: [{ id: "role-user", serviceKey: "temis", name: "user" }]
      }],
      total: 1,
      page: 2,
      pageSize: 5
    });

    const response = await request(app)
      .get("/admin/users")
      .query({ page: "2", pageSize: "5", status: "ACTIVE", email: "target@example.test", role: "temis:user" })
      .set("Authorization", "Bearer admin-access-token");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      items: [{
        id: "target-user",
        email: "target@example.test",
        name: "Target",
        status: "ACTIVE",
        createdAt: "2026-07-22T03:00:00.000Z",
        roles: [{ id: "role-user", serviceKey: "temis", name: "user" }]
      }],
      total: 1,
      page: 2,
      pageSize: 5
    });
    expect(mocks.listAdminUsers).toHaveBeenCalledWith({
      page: 2,
      pageSize: 5,
      status: "ACTIVE",
      email: "target@example.test",
      role: "temis:user"
    });
  });

  it("Given an active DB-backed TEMIS admin When GET /admin/audit-logs includes filters Then it returns the paged redacted audit list", async () => {
    const app = await loadAdminTestApp();
    mocks.queryAuditLogs.mockResolvedValue({
      items: [
        {
          id: "audit-new",
          eventType: "login_failure",
          outcome: "failure",
          userId: "target-user",
          actorUserId: "admin-user",
          targetUserId: "target-user",
          reasonCode: "INVALID_CREDENTIALS",
          detailsJson: {
            route: "/auth/login",
            accessToken: "raw-access-token",
            oauthCode: "oauth-code-sentinel-10",
            note: "Bearer raw-provider-token"
          },
          createdAt: new Date("2026-07-22T04:00:00.000Z")
        }
      ],
      total: 1
    });

    const response = await request(app)
      .get("/admin/audit-logs")
      .query({
        page: "2",
        pageSize: "5",
        createdAtFrom: "2026-07-01T00:00:00.000Z",
        createdAtTo: "2026-07-23T00:00:00.000Z",
        eventType: "login_failure",
        outcome: "failure",
        userId: "target-user",
        actorUserId: "admin-user",
        targetUserId: "target-user",
        reasonCode: "INVALID_CREDENTIALS"
      })
      .set("Authorization", "Bearer admin-access-token");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      items: [
        {
          id: "audit-new",
          eventType: "login_failure",
          outcome: "failure",
          userId: "target-user",
          actorUserId: "admin-user",
          targetUserId: "target-user",
          reasonCode: "INVALID_CREDENTIALS",
          detailsJson: {
            route: "/auth/login",
            accessToken: "[REDACTED]",
            oauthCode: "[REDACTED]",
            note: "[REDACTED]"
          },
          createdAt: "2026-07-22T04:00:00.000Z"
        }
      ],
      total: 1,
      page: 2,
      pageSize: 5
    });
    expect(JSON.stringify(response.body)).not.toContain("raw-access-token");
    expect(JSON.stringify(response.body)).not.toContain("oauth-code-sentinel-10");
    expect(JSON.stringify(response.body)).not.toContain("Bearer raw-provider-token");
    expect(mocks.queryAuditLogs).toHaveBeenCalledWith({
      page: 2,
      pageSize: 5,
      createdAtFrom: new Date("2026-07-01T00:00:00.000Z"),
      createdAtTo: new Date("2026-07-23T00:00:00.000Z"),
      eventType: "login_failure",
      outcome: "failure",
      userId: "target-user",
      actorUserId: "admin-user",
      targetUserId: "target-user",
      reasonCode: "INVALID_CREDENTIALS"
    });
  });

  it("Given a token whose current DB user lacks temis admin When GET /admin/audit-logs runs Then it rejects with 403", async () => {
    const app = await loadAdminTestApp();
    mocks.verifyAccessToken.mockReturnValue("non-admin-user");
    mocks.getCurrentUserWithStatus.mockResolvedValue(activeNonAdmin);

    const response = await request(app)
      .get("/admin/audit-logs")
      .set("Authorization", "Bearer stale-admin-role-token");

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      error: {
        code: "FORBIDDEN",
        message: "Admin role is required"
      }
    });
    expect(mocks.queryAuditLogs).not.toHaveBeenCalled();
  });

  it("Given malformed audit log filters When GET /admin/audit-logs runs Then it returns 400 before querying", async () => {
    const app = await loadAdminTestApp();

    const response = await request(app)
      .get("/admin/audit-logs")
      .query({ page: "0", createdAtFrom: "not-a-date", outcome: "maybe" })
      .set("Authorization", "Bearer admin-access-token");

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        code: "INVALID_REQUEST",
        message: "Invalid request"
      }
    });
    expect(mocks.queryAuditLogs).not.toHaveBeenCalled();
  });

  it("Given a token whose current DB user lacks temis admin When PATCH /admin/users/:id/status runs Then it rejects with 403", async () => {
    const app = await loadAdminTestApp();
    mocks.verifyAccessToken.mockReturnValue("non-admin-user");
    mocks.getCurrentUserWithStatus.mockResolvedValue(activeNonAdmin);

    const response = await request(app)
      .patch("/admin/users/target-user/status")
      .set("Authorization", "Bearer stale-admin-role-token")
      .send({ status: "SUSPENDED", reasonCode: "ADMIN_SUSPEND" });

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      error: {
        code: "FORBIDDEN",
        message: "Admin role is required"
      }
    });
    expect(mocks.setUserStatus).not.toHaveBeenCalled();
    expect(adminRouteAuthAuditEvents).toEqual([{
      eventType: "admin_authorization_failure",
      outcome: "failure",
      userId: "non-admin-user",
      actorUserId: "non-admin-user",
      targetUserId: null,
      reasonCode: "FORBIDDEN",
      detailsJson: {
        route: "/admin/users/target-user/status",
        method: "PATCH"
      }
    }]);
  });

  it("Given an active DB-backed TEMIS admin When PATCH /admin/users/:id/status suspends a target Then it returns revocation result", async () => {
    const app = await loadAdminTestApp();

    const response = await request(app)
      .patch("/admin/users/target-user/status")
      .set("Authorization", "Bearer admin-access-token")
      .send({ status: "SUSPENDED", reasonCode: "ADMIN_SUSPEND" });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ statusChanged: true, revokedRefreshTokenCount: 2 });
    expect(adminRouteStoreState.auditLogs).toEqual([{
      eventType: "admin_user_status_changed",
      outcome: "success",
      actorUserId: "admin-user",
      targetUserId: "target-user",
      reasonCode: "ADMIN_SUSPEND",
      detailsJson: { route: "PATCH /admin/users/:id/status" }
    }]);
  });

  it("Given an active DB-backed TEMIS admin When PATCH /admin/users/:id/status self-suspends Then it rejects before mutation", async () => {
    const app = await loadAdminTestApp();

    const response = await request(app)
      .patch("/admin/users/admin-user/status")
      .set("Authorization", "Bearer admin-access-token")
      .send({ status: "SUSPENDED", reasonCode: "ADMIN_SUSPEND_SELF" });

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      error: {
        code: "FORBIDDEN",
        message: "Admins cannot suspend or delete their own account"
      }
    });
    expect(mocks.setUserStatus).not.toHaveBeenCalled();
  });

  it("Given an active DB-backed TEMIS admin When DELETE /admin/users/:id/roles/:roleId removes a target role Then it revokes target sessions", async () => {
    const app = await loadAdminTestApp();
    mocks.findAdminRoleById.mockResolvedValue({ id: "role-user", serviceKey: "temis", name: "user" });

    const response = await request(app)
      .delete("/admin/users/target-user/roles/role-user")
      .set("Authorization", "Bearer admin-access-token")
      .send({ reasonCode: "ADMIN_ROLE_REMOVE" });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ roleRemoved: true, roleId: "role-user", revokedRefreshTokenCount: 2 });
    expect(adminRouteStoreState.auditLogs).toEqual([{
      eventType: "admin_user_role_removed",
      outcome: "success",
      actorUserId: "admin-user",
      targetUserId: "target-user",
      reasonCode: "ADMIN_ROLE_REMOVE",
      detailsJson: { roleId: "role-user", route: "DELETE /admin/users/:id/roles/:roleId" }
    }]);
  });

  it("Given an active DB-backed TEMIS admin When POST /admin/users/:id/roles assigns a role Then it returns the assignment result", async () => {
    const app = await loadAdminTestApp();

    const response = await request(app)
      .post("/admin/users/target-user/roles")
      .set("Authorization", "Bearer admin-access-token")
      .send({ serviceKey: "temis", name: "admin", reasonCode: "ADMIN_ROLE_ASSIGN" });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ roleAssigned: true, roleId: "role-2" });
    expect(adminRouteStoreState.auditLogs).toEqual([{
      eventType: "admin_user_role_assigned",
      outcome: "success",
      actorUserId: "admin-user",
      targetUserId: "target-user",
      reasonCode: "ADMIN_ROLE_ASSIGN",
      detailsJson: { route: "POST /admin/users/:id/roles" }
    }]);
  });

  it("Given an active DB-backed TEMIS admin When DELETE /admin/users/:id/roles/:roleId removes their own admin role Then it rejects before mutation", async () => {
    const app = await loadAdminTestApp();
    mocks.findAdminRoleById.mockResolvedValue({ id: "role-admin", serviceKey: "temis", name: "admin" });

    const response = await request(app)
      .delete("/admin/users/admin-user/roles/role-admin")
      .set("Authorization", "Bearer admin-access-token")
      .send({ reasonCode: "ADMIN_ROLE_REMOVE_SELF" });

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      error: {
        code: "FORBIDDEN",
        message: "Admins cannot remove their own admin role"
      }
    });
    expect(mocks.removeRole).not.toHaveBeenCalled();
  });

  it("Given an inactive DB-backed TEMIS admin When GET /admin/users runs Then it rejects with 403", async () => {
    const app = await loadAdminTestApp();
    mocks.getCurrentUserWithStatus.mockResolvedValue({
      ...activeAdmin,
      status: "SUSPENDED"
    });

    const response = await request(app)
      .get("/admin/users")
      .set("Authorization", "Bearer admin-access-token");

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      error: {
        code: "FORBIDDEN",
        message: "Admin role is required"
      }
    });
    expect(mocks.listAdminUsers).not.toHaveBeenCalled();
  });

  it("Given an active DB-backed TEMIS admin When POST /admin/users/:id/revoke-sessions targets self Then it rejects before mutation", async () => {
    const app = await loadAdminTestApp();

    const response = await request(app)
      .post("/admin/users/admin-user/revoke-sessions")
      .set("Authorization", "Bearer admin-access-token")
      .send({ reasonCode: "ADMIN_REVOKE_SELF" });

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      error: {
        code: "FORBIDDEN",
        message: "Admins cannot revoke their own sessions"
      }
    });
    expect(mocks.revokeSessions).not.toHaveBeenCalled();
  });

  it("Given an active DB-backed TEMIS admin When POST /admin/users/:id/revoke-sessions targets another user Then it revokes target sessions", async () => {
    const app = await loadAdminTestApp();

    const response = await request(app)
      .post("/admin/users/target-user/revoke-sessions")
      .set("Authorization", "Bearer admin-access-token")
      .send({ reasonCode: "ADMIN_REVOKE_TARGET" });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ revokedCount: 2 });
    expect(adminRouteStoreState.auditLogs).toEqual([{
      eventType: "admin_user_sessions_revoked",
      outcome: "success",
      actorUserId: "admin-user",
      targetUserId: "target-user",
      reasonCode: "ADMIN_REVOKE_TARGET",
      detailsJson: { route: "POST /admin/users/:id/revoke-sessions" }
    }]);
  });

  it("Given malformed status input When PATCH /admin/users/:id/status runs Then it returns 400 before mutation", async () => {
    const app = await loadAdminTestApp();

    const response = await request(app)
      .patch("/admin/users/target-user/status")
      .set("Authorization", "Bearer admin-access-token")
      .send({ status: "disabled", reasonCode: "ADMIN_STATUS" });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        code: "INVALID_REQUEST",
        message: "Invalid request"
      }
    });
    expect(mocks.setUserStatus).not.toHaveBeenCalled();
  });
});

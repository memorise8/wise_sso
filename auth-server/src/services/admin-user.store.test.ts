import { beforeEach, describe, expect, it, vi } from "vitest";

const calls: string[] = [];

const mocks = vi.hoisted(() => ({
  auditLog: {
    create: vi.fn()
  },
  queryRaw: vi.fn(),
  refreshToken: {
    updateMany: vi.fn()
  },
  role: {
    findUnique: vi.fn()
  },
  transaction: vi.fn(),
  user: {
    updateMany: vi.fn()
  },
  userRole: {
    createMany: vi.fn(),
    deleteMany: vi.fn()
  }
}));

vi.mock("@prisma/client", () => ({
  PrismaClient: vi.fn(function PrismaClient() {
    return {
      $transaction: mocks.transaction
    };
  })
}));

beforeEach(() => {
  vi.resetModules();
  calls.splice(0, calls.length);
  mocks.auditLog.create.mockReset();
  mocks.queryRaw.mockReset();
  mocks.refreshToken.updateMany.mockReset();
  mocks.role.findUnique.mockReset();
  mocks.transaction.mockReset();
  mocks.user.updateMany.mockReset();
  mocks.userRole.createMany.mockReset();
  mocks.userRole.deleteMany.mockReset();
  mocks.transaction.mockImplementation(async (work) => work({
    $queryRaw: mocks.queryRaw,
    auditLog: mocks.auditLog,
    refreshToken: mocks.refreshToken,
    role: mocks.role,
    user: mocks.user,
    userRole: mocks.userRole
  }));
  mocks.queryRaw.mockImplementation(async () => {
    calls.push("lock-user");
    return [{ id: "target-user" }];
  });
  mocks.refreshToken.updateMany.mockImplementation(async () => {
    calls.push("revoke-refresh-tokens");
    return { count: 2 };
  });
  mocks.role.findUnique.mockResolvedValue({
    id: "role-user",
    serviceKey: "temis",
    name: "user"
  });
  mocks.userRole.deleteMany.mockResolvedValue({ count: 1 });
  mocks.auditLog.create.mockResolvedValue({});
});

describe("admin user Prisma revocation locking", () => {
  it("Given role removal races refresh rotation When target refresh tokens are revoked Then the revocation locks the user row before token revocation", async () => {
    const { createAdminUserService } = await import("./admin-user.service.js");
    const { adminUserMutationStore } = await import("./admin-user.store.js");
    const service = createAdminUserService(adminUserMutationStore);

    const result = await service.removeRole({
      actorUserId: "admin-user",
      targetUserId: "target-user",
      serviceKey: "temis",
      name: "user",
      reasonCode: "ADMIN_ROLE_REMOVE"
    });

    expect(result).toEqual({ roleRemoved: true, roleId: "role-user", revokedRefreshTokenCount: 2 });
    expect(calls).toEqual(["lock-user", "revoke-refresh-tokens"]);
  });

  it("Given explicit session revoke races refresh rotation When target refresh tokens are revoked Then the revocation locks the user row before token revocation", async () => {
    const { createAdminUserService } = await import("./admin-user.service.js");
    const { adminUserMutationStore } = await import("./admin-user.store.js");
    const service = createAdminUserService(adminUserMutationStore);

    const result = await service.revokeSessions({
      actorUserId: "admin-user",
      targetUserId: "target-user",
      reasonCode: "ADMIN_REVOKE_SESSIONS",
      now: new Date("2026-07-23T01:00:00.000Z")
    });

    expect(result).toEqual({ revokedCount: 2 });
    expect(calls).toEqual(["lock-user", "revoke-refresh-tokens"]);
  });
});

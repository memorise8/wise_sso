import { beforeEach, describe, expect, it, vi } from "vitest";
import { HttpError } from "../utils/httpError.js";

const mocks = vi.hoisted(() => ({
  user: {
    findMany: vi.fn(),
    count: vi.fn()
  },
  role: {
    findUnique: vi.fn()
  },
  transaction: vi.fn()
}));

vi.mock("@prisma/client", () => ({
  PrismaClient: vi.fn(function PrismaClient() {
    return {
      user: mocks.user,
      role: mocks.role,
      $transaction: mocks.transaction
    };
  })
}));

beforeEach(() => {
  vi.resetModules();
  mocks.user.findMany.mockReset();
  mocks.user.count.mockReset();
  mocks.role.findUnique.mockReset();
  mocks.transaction.mockReset();
  mocks.transaction.mockImplementation(async (operations: readonly Promise<unknown>[]) => Promise.all(operations));
});

describe("listAdminUsers", () => {
  it("Given status email and role filters When admin users are listed Then Prisma receives filtered createdAt-desc pagination and minimal fields are returned", async () => {
    const { listAdminUsers } = await import("./admin-directory.service.js");
    const newestCreatedAt = new Date("2026-07-22T04:00:00.000Z");
    mocks.user.findMany.mockResolvedValue([{
      id: "newest-user",
      email: "newest@example.test",
      name: "Newest",
      status: "ACTIVE",
      createdAt: newestCreatedAt,
      roles: [{
        role: {
          id: "role-user",
          serviceKey: "temis",
          name: "user"
        }
      }],
      passwordCredential: { passwordHash: "must-not-leak" }
    }]);
    mocks.user.count.mockResolvedValue(7);

    const result = await listAdminUsers({
      page: 2,
      pageSize: 5,
      status: "ACTIVE",
      email: " newest@example.test ",
      role: "temis:user"
    });

    expect(result).toEqual({
      items: [{
        id: "newest-user",
        email: "newest@example.test",
        name: "Newest",
        status: "ACTIVE",
        createdAt: "2026-07-22T04:00:00.000Z",
        roles: [{ id: "role-user", serviceKey: "temis", name: "user" }]
      }],
      total: 7,
      page: 2,
      pageSize: 5
    });
    expect(mocks.user.findMany).toHaveBeenCalledWith({
      where: {
        status: "ACTIVE",
        email: { contains: "newest@example.test", mode: "insensitive" },
        roles: { some: { role: { serviceKey: "temis", name: "user" } } }
      },
      orderBy: { createdAt: "desc" },
      skip: 5,
      take: 5,
      select: {
        id: true,
        email: true,
        name: true,
        status: true,
        createdAt: true,
        roles: {
          include: {
            role: true
          }
        }
      }
    });
    expect(result.items[0]).not.toHaveProperty("passwordCredential");
  });

  it("Given malformed role filter When admin users are listed Then the service rejects before querying", async () => {
    const { listAdminUsers } = await import("./admin-directory.service.js");

    await expect(listAdminUsers({
      page: 1,
      pageSize: 25,
      role: "temis:user:extra"
    })).rejects.toMatchObject(new HttpError(400, "INVALID_REQUEST", "Invalid request"));
    expect(mocks.user.findMany).not.toHaveBeenCalled();
  });
});

describe("findAdminRoleById", () => {
  it("Given a role id When the admin role is looked up Then only the admin role profile fields are selected", async () => {
    const { findAdminRoleById } = await import("./admin-directory.service.js");
    mocks.role.findUnique.mockResolvedValue({ id: "role-admin", serviceKey: "temis", name: "admin" });

    const result = await findAdminRoleById("role-admin");

    expect(result).toEqual({ id: "role-admin", serviceKey: "temis", name: "admin" });
    expect(mocks.role.findUnique).toHaveBeenCalledWith({
      where: { id: "role-admin" },
      select: {
        id: true,
        serviceKey: true,
        name: true
      }
    });
  });
});

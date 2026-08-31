// allow: SIZE_OK - User lifecycle, email verification, role, and status regression cases share one cohesive service fixture during this final auth-flow blocker pass.
import { beforeEach, describe, expect, it, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";

process.env["DATABASE_URL"] = "postgresql://user:password@localhost:5432/auth_db";
process.env["JWT_REFRESH_SECRET"] = "test-refresh-secret-long";
process.env["JWT_ISSUER"] = "https://auth.temis.co.kr";
process.env["JWT_AUDIENCE"] = "temis";
process.env["REDIS_URL"] = "redis://localhost:6379";
process.env["FRONTEND_REDIRECT_URL"] = "http://localhost:3000/auth/callback";
process.env["GOOGLE_CLIENT_ID"] = "google";
process.env["GOOGLE_CLIENT_SECRET"] = "google-secret";
process.env["GOOGLE_REDIRECT_URI"] = "http://localhost:4000/auth/google/callback";
process.env["NAVER_CLIENT_ID"] = "naver";
process.env["NAVER_CLIENT_SECRET"] = "naver-secret";
process.env["NAVER_REDIRECT_URI"] = "http://localhost:4000/auth/naver/callback";
process.env["KAKAO_CLIENT_ID"] = "kakao";
process.env["KAKAO_CLIENT_SECRET"] = "kakao-secret";
process.env["KAKAO_REDIRECT_URI"] = "http://localhost:4000/auth/kakao/callback";

const configureAccessKeyEnv = (): void => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001
  });
  const publicJwk = publicKey.export({ format: "jwk" });
  if (publicJwk.kty !== "RSA" || typeof publicJwk.n !== "string" || typeof publicJwk.e !== "string") {
    throw new Error("Generated RSA key did not export a public JWK");
  }
  process.env["JWT_ACCESS_ALGORITHM"] = "RS256";
  process.env["JWT_ACCESS_PRIVATE_KEY"] = privateKey.export({ format: "pem", type: "pkcs8" }).toString().replace(/\n/g, "\\n");
  process.env["JWT_ACCESS_PUBLIC_JWK"] = JSON.stringify({
    kty: "RSA",
    n: publicJwk.n,
    e: publicJwk.e,
    alg: "RS256",
    use: "sig",
    kid: "temis-access-key-1"
  });
  process.env["JWT_ACCESS_KEY_ID"] = "temis-access-key-1";
};

type RoleInput = {
  readonly serviceKey: string;
  readonly name: string;
};

const temisClientPolicy = {
  clientId: "temis",
  audience: "temis",
  allowedRedirectUris: ["https://financenow.kr/auth/callback"],
  allowedOrigins: ["https://financenow.kr"],
  defaultRole: { serviceKey: "temis", name: "pending" }
};
const oauthUser = {
  id: "user-1",
  email: "oauth@example.com",
  name: "OAuth User",
  profileUrl: null,
  emailVerified: false,
  status: "ACTIVE",
  createdAt: new Date("2026-07-22T00:00:00.000Z"),
  updatedAt: new Date("2026-07-22T00:00:00.000Z")
};
process.env["AUTH_CLIENTS_JSON"] = JSON.stringify([temisClientPolicy]);

const setTemisDefaultRole = (name: string): void => {
  process.env["AUTH_CLIENTS_JSON"] = JSON.stringify([{ ...temisClientPolicy, defaultRole: { serviceKey: "temis", name } }]);
};

const setAdditionalClientDefaultRole = (defaultRole: RoleInput): void => {
  process.env["AUTH_CLIENTS_JSON"] = JSON.stringify([
    temisClientPolicy,
    {
      clientId: "payroll",
      audience: "payroll",
      allowedRedirectUris: ["https://payroll.example.com/auth/callback"],
      allowedOrigins: ["https://payroll.example.com"],
      defaultRole
    }
  ]);
};

const mocks = vi.hoisted(() => ({
  socialAccount: {
    findUnique: vi.fn()
  },
  user: {
    findUnique: vi.fn(),
    create: vi.fn(),
    findMany: vi.fn()
  },
  role: {
    upsert: vi.fn()
  },
  userRole: {
    createMany: vi.fn()
  },
  executeRaw: vi.fn(),
  transaction: vi.fn()
}));

vi.mock("@prisma/client", () => ({
  PrismaClient: vi.fn(function PrismaClient() {
    return {
      socialAccount: mocks.socialAccount,
      user: mocks.user,
      role: mocks.role,
      userRole: mocks.userRole,
      $executeRaw: mocks.executeRaw,
      $transaction: mocks.transaction
    };
  })
}));

beforeEach(() => {
  vi.resetModules();
  configureAccessKeyEnv();
  setTemisDefaultRole("pending");
  mocks.socialAccount.findUnique.mockReset();
  mocks.user.findUnique.mockReset();
  mocks.user.create.mockReset();
  mocks.user.findMany.mockReset();
  mocks.role.upsert.mockReset();
  mocks.userRole.createMany.mockReset();
  mocks.executeRaw.mockReset();
  mocks.transaction.mockReset();
  mocks.transaction.mockImplementation(async (work) => work({
    user: mocks.user,
    role: mocks.role,
    userRole: mocks.userRole,
    $executeRaw: mocks.executeRaw
  }));
  mocks.role.upsert.mockImplementation(async (input: { readonly create: RoleInput }) => ({
    id: `role-${input.create.serviceKey}-${input.create.name}`,
    serviceKey: input.create.serviceKey,
    name: input.create.name
  }));
  mocks.userRole.createMany.mockResolvedValue({ count: 1 });
});

describe("findOrCreateUserBySocialProfile", () => {
  it("Given a new OAuth user When the profile is persisted Then TEMIS roles are seeded and only temis pending is assigned", async () => {
    const { findOrCreateUserBySocialProfile } = await import("./user.service.js");
    mocks.socialAccount.findUnique.mockResolvedValue(null);
    mocks.user.findUnique.mockResolvedValue(null);
    mocks.user.create.mockResolvedValue(oauthUser);

    await findOrCreateUserBySocialProfile({
      provider: "google",
      providerUserId: "google-user-1",
      email: "oauth@example.com",
      name: "OAuth User",
      profileUrl: null,
      emailVerified: true
    });

    expect(mocks.role.upsert).toHaveBeenCalledWith(expect.objectContaining({
      create: { serviceKey: "temis", name: "pending" }
    }));
    expect(mocks.role.upsert).toHaveBeenCalledWith(expect.objectContaining({
      create: { serviceKey: "temis", name: "user" }
    }));
    expect(mocks.role.upsert).toHaveBeenCalledWith(expect.objectContaining({
      create: { serviceKey: "temis", name: "admin" }
    }));
    expect(mocks.userRole.createMany).toHaveBeenCalledTimes(1);
    expect(mocks.userRole.createMany).toHaveBeenCalledWith({
      data: {
        userId: "user-1",
        roleId: "role-temis-pending"
      },
      skipDuplicates: true
    });
    expect(mocks.userRole.createMany).not.toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ roleId: "role-temis-user" })
    }));
    expect(mocks.userRole.createMany).not.toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ roleId: "role-temis-admin" })
    }));
  });

  it("Given AUTH_CLIENTS_JSON explicitly defaults TEMIS to user When a new OAuth user is persisted Then it assigns temis user without admin", async () => {
    setTemisDefaultRole("user");
    const { findOrCreateUserBySocialProfile } = await import("./user.service.js");
    mocks.socialAccount.findUnique.mockResolvedValue(null);
    mocks.user.findUnique.mockResolvedValue(null);
    mocks.user.create.mockResolvedValue(oauthUser);

    await findOrCreateUserBySocialProfile({
      provider: "google",
      providerUserId: "google-user-1",
      email: "oauth@example.com",
      name: "OAuth User",
      profileUrl: null,
      emailVerified: true
    });

    expect(mocks.userRole.createMany).toHaveBeenCalledTimes(1);
    expect(mocks.userRole.createMany).toHaveBeenCalledWith({
      data: {
        userId: "user-1",
        roleId: "role-temis-user"
      },
      skipDuplicates: true
    });
    expect(mocks.userRole.createMany).not.toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ roleId: "role-temis-admin" })
    }));
  });

  it("Given OAuth starts for a non-TEMIS client When a new OAuth user is persisted Then that client's pending default role is assigned", async () => {
    setAdditionalClientDefaultRole({ serviceKey: "payroll", name: "pending" });
    const { findOrCreateUserBySocialProfile } = await import("./user.service.js");
    mocks.socialAccount.findUnique.mockResolvedValue(null);
    mocks.user.findUnique.mockResolvedValue(null);
    mocks.user.create.mockResolvedValue(oauthUser);

    await findOrCreateUserBySocialProfile({
      provider: "google",
      providerUserId: "google-user-1",
      email: "oauth@example.com",
      name: "OAuth User",
      profileUrl: null,
      emailVerified: true
    }, "payroll");

    expect(mocks.userRole.createMany).toHaveBeenCalledTimes(1);
    expect(mocks.userRole.createMany).toHaveBeenCalledWith({
      data: {
        userId: "user-1",
        roleId: "role-payroll-pending"
      },
      skipDuplicates: true
    });
  });

  it("Given OAuth explicitly verifies the provider email When a new OAuth user is persisted Then emailVerified is true", async () => {
    const { findOrCreateUserBySocialProfile } = await import("./user.service.js");
    mocks.socialAccount.findUnique.mockResolvedValue(null);
    mocks.user.findUnique.mockResolvedValue(null);
    mocks.user.create.mockResolvedValue({ ...oauthUser, emailVerified: true });

    await findOrCreateUserBySocialProfile({
      provider: "google",
      providerUserId: "google-user-1",
      email: "oauth@example.com",
      name: "OAuth User",
      profileUrl: null,
      emailVerified: true
    });

    expect(mocks.user.create).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        emailVerified: true
      })
    }));
  });

  it("Given OAuth starts without a provider verified email claim When a new OAuth user is persisted Then emailVerified is false", async () => {
    const { findOrCreateUserBySocialProfile } = await import("./user.service.js");
    mocks.socialAccount.findUnique.mockResolvedValue(null);
    mocks.user.findUnique.mockResolvedValue(null);
    mocks.user.create.mockResolvedValue(oauthUser);

    await findOrCreateUserBySocialProfile({
      provider: "naver",
      providerUserId: "naver-user-1",
      email: "oauth@example.com",
      name: "OAuth User",
      profileUrl: null
    });

    expect(mocks.user.create).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({
        emailVerified: false
      })
    }));
  });
});

describe("seedTemisRolesAndAssignDefaultRole", () => {
  it("Given a roleless existing user When default role assignment is repeated Then the operation is idempotent and never grants user or admin", async () => {
    const { seedTemisRolesAndAssignDefaultRole } = await import("./user.service.js");
    const assignedUserRoles = new Set<string>();
    mocks.userRole.createMany.mockImplementation(async (input: { readonly data: { readonly userId: string; readonly roleId: string } }) => {
      const key = `${input.data.userId}:${input.data.roleId}`;
      const created = !assignedUserRoles.has(key);
      assignedUserRoles.add(key);
      return { count: created ? 1 : 0 };
    });

    await seedTemisRolesAndAssignDefaultRole({
      role: mocks.role,
      userRole: mocks.userRole
    }, "user-1");
    await seedTemisRolesAndAssignDefaultRole({
      role: mocks.role,
      userRole: mocks.userRole
    }, "user-1");

    expect(assignedUserRoles).toEqual(new Set(["user-1:role-temis-pending"]));
    expect(assignedUserRoles).not.toContain("user-1:role-temis-user");
    expect(assignedUserRoles).not.toContain("user-1:role-temis-admin");
    expect(mocks.userRole.createMany).toHaveBeenCalledTimes(2);
  });
});

describe("backfillRolelessUsersWithDefaultRole", () => {
  it("Given existing roleless users When backfill runs twice Then it assigns only the default pending role idempotently", async () => {
    const { backfillRolelessUsersWithDefaultRole } = await import("./user.service.js");
    mocks.executeRaw.mockResolvedValueOnce(2).mockResolvedValueOnce(0);

    const firstResult = await backfillRolelessUsersWithDefaultRole({
      role: mocks.role,
      $executeRaw: mocks.executeRaw
    });
    const secondResult = await backfillRolelessUsersWithDefaultRole({
      role: mocks.role,
      $executeRaw: mocks.executeRaw
    });

    expect(firstResult).toEqual({
      defaultRole: { serviceKey: "temis", name: "pending" },
      rolelessUserCount: 2,
      assignedUserRoleCount: 2
    });
    expect(secondResult).toEqual({
      defaultRole: { serviceKey: "temis", name: "pending" },
      rolelessUserCount: 0,
      assignedUserRoleCount: 0
    });
    expect(mocks.executeRaw).toHaveBeenCalledTimes(2);
    expect(mocks.userRole.createMany).not.toHaveBeenCalled();
  });
});

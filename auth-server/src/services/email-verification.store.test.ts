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
process.env["AUTH_CLIENTS_JSON"] = JSON.stringify([
  {
    clientId: "temis",
    audience: "temis",
    allowedRedirectUris: ["https://financenow.kr/auth/callback"],
    allowedOrigins: ["https://financenow.kr"],
    defaultRole: { serviceKey: "temis", name: "pending" }
  }
]);

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

const setTemisDefaultRole = (name: string): void => {
  process.env["AUTH_CLIENTS_JSON"] = JSON.stringify([
    {
      clientId: "temis",
      audience: "temis",
      allowedRedirectUris: ["https://financenow.kr/auth/callback"],
      allowedOrigins: ["https://financenow.kr"],
      defaultRole: { serviceKey: "temis", name }
    }
  ]);
};

type RoleInput = {
  readonly serviceKey: string;
  readonly name: string;
};

const mocks = vi.hoisted(() => ({
  emailVerificationToken: {
    updateMany: vi.fn()
  },
  user: {
    updateMany: vi.fn()
  },
  role: {
    upsert: vi.fn()
  },
  userRole: {
    createMany: vi.fn()
  },
  transaction: vi.fn()
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
  configureAccessKeyEnv();
  setTemisDefaultRole("pending");
  mocks.emailVerificationToken.updateMany.mockReset();
  mocks.user.updateMany.mockReset();
  mocks.role.upsert.mockReset();
  mocks.userRole.createMany.mockReset();
  mocks.transaction.mockReset();
  mocks.transaction.mockImplementation(async (work) => work({
    emailVerificationToken: mocks.emailVerificationToken,
    user: mocks.user,
    role: mocks.role,
    userRole: mocks.userRole
  }));
  mocks.emailVerificationToken.updateMany.mockResolvedValue({ count: 1 });
  mocks.user.updateMany.mockResolvedValue({ count: 1 });
  mocks.role.upsert.mockImplementation(async (input: { readonly create: RoleInput }) => ({
    id: `role-${input.create.serviceKey}-${input.create.name}`,
    serviceKey: input.create.serviceKey,
    name: input.create.name
  }));
  mocks.userRole.createMany.mockResolvedValue({ count: 1 });
});

describe("emailVerificationStore.markTokenUsedAndActivateUser", () => {
  it("Given a valid verification token When the Prisma adapter activates the user Then it assigns only the default TEMIS role in the transaction", async () => {
    const { emailVerificationStore } = await import("./email-verification.store.js");
    const usedAt = new Date("2026-07-22T03:00:00.000Z");

    const result = await emailVerificationStore.markTokenUsedAndActivateUser({
      tokenId: "token-1",
      userId: "user-1",
      usedAt
    });

    expect(result).toBe(true);
    expect(mocks.transaction).toHaveBeenCalledTimes(1);
    expect(mocks.user.updateMany).toHaveBeenCalledWith({
      where: {
        id: "user-1",
        status: "PENDING_EMAIL_VERIFICATION"
      },
      data: { status: "ACTIVE", emailVerified: true }
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

  it("Given AUTH_CLIENTS_JSON explicitly defaults TEMIS to user When the Prisma adapter activates the user Then it assigns temis user without admin", async () => {
    setTemisDefaultRole("user");
    const { emailVerificationStore } = await import("./email-verification.store.js");

    const result = await emailVerificationStore.markTokenUsedAndActivateUser({
      tokenId: "token-1",
      userId: "user-1",
      usedAt: new Date("2026-07-22T03:00:00.000Z")
    });

    expect(result).toBe(true);
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

  it("Given a valid token for a non-pending user When the Prisma adapter consumes it Then the token is burned and activation is rejected", async () => {
    const { emailVerificationStore } = await import("./email-verification.store.js");
    mocks.user.updateMany.mockResolvedValue({ count: 0 });
    const usedAt = new Date("2026-07-22T03:00:00.000Z");

    const result = await emailVerificationStore.markTokenUsedAndActivateUser({
      tokenId: "token-1",
      userId: "user-1",
      usedAt
    });

    expect(result).toBe(false);
    expect(mocks.emailVerificationToken.updateMany).toHaveBeenCalledWith({
      where: {
        id: "token-1",
        userId: "user-1",
        usedAt: null,
        expiresAt: { gt: usedAt }
      },
      data: { usedAt }
    });
    expect(mocks.userRole.createMany).not.toHaveBeenCalled();
  });
});

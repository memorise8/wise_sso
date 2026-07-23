import { createPublicKey, generateKeyPairSync } from "node:crypto";
import type { JsonWebKey } from "node:crypto";
import jwt from "jsonwebtoken";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { userStatuses } from "./user-status.service.js";

process.env["DATABASE_URL"] = "postgresql://user:password@localhost:5432/auth_db";
process.env["JWT_REFRESH_SECRET"] = "test-refresh-secret-long";
process.env["JWT_ISSUER"] = "https://auth.temis.co.kr";
process.env["JWT_AUDIENCE"] = "temis";

const accessKeyId = "temis-access-key-1";

const createAccessKeyFixture = (): JsonWebKey => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001
  });
  const publicJwk = publicKey.export({ format: "jwk" });
  if (publicJwk.kty !== "RSA" || typeof publicJwk.n !== "string" || typeof publicJwk.e !== "string") {
    throw new Error("Generated RSA key did not export a public JWK");
  }
  const accessPublicJwk = {
    kty: "RSA",
    n: publicJwk.n,
    e: publicJwk.e,
    alg: "RS256",
    use: "sig",
    kid: accessKeyId
  } as const;

  process.env["JWT_ACCESS_ALGORITHM"] = "RS256";
  process.env["JWT_ACCESS_PRIVATE_KEY"] = privateKey.export({ format: "pem", type: "pkcs8" }).toString().replace(/\n/g, "\\n");
  process.env["JWT_ACCESS_PUBLIC_JWK"] = JSON.stringify(accessPublicJwk);
  process.env["JWT_ACCESS_KEY_ID"] = accessKeyId;
  return accessPublicJwk;
};

const mocks = vi.hoisted(() => ({
  user: {
    findUnique: vi.fn()
  },
  refreshToken: {
    create: vi.fn(),
    findFirst: vi.fn(),
    updateMany: vi.fn()
  },
  queryRaw: vi.fn(),
  transaction: vi.fn()
}));

vi.mock("@prisma/client", () => ({
  PrismaClient: vi.fn(function PrismaClient() {
    return {
      user: mocks.user,
      $queryRaw: mocks.queryRaw,
      $transaction: mocks.transaction,
      refreshToken: mocks.refreshToken
    };
  })
}));

beforeEach(() => {
  vi.resetModules();
  createAccessKeyFixture();
  mocks.user.findUnique.mockReset();
  mocks.refreshToken.create.mockReset();
  mocks.refreshToken.findFirst.mockReset();
  mocks.refreshToken.updateMany.mockReset();
  mocks.queryRaw.mockReset();
  mocks.transaction.mockReset();
  mocks.transaction.mockImplementation(async (work) => work({
    user: mocks.user,
    refreshToken: mocks.refreshToken,
    $queryRaw: mocks.queryRaw
  }));
  mocks.queryRaw.mockResolvedValue([{ id: "auth-user-1" }]);
  mocks.user.findUnique.mockResolvedValue({
    id: "auth-user-1",
    email: "user@example.com",
    name: "Test User",
    emailVerified: true,
    status: userStatuses.active,
    roles: []
  });
});

describe("token audience isolation", () => {
  it("Given auth user claims for a relying client When access token is created Then payload uses the client audience", async () => {
    const publicJwk = createAccessKeyFixture();
    const { createAccessToken } = await import("./token.service.js");

    const token = createAccessToken({
      id: "auth-user-1",
      email: "user@example.com",
      name: "Ledger User",
      emailVerified: true,
      status: userStatuses.active,
      roles: [{ serviceKey: "ledger", name: "pending" }]
    }, { audience: "ledger-api" });
    const payload = jwt.verify(token, createPublicKey({ key: publicJwk, format: "jwk" }), {
      issuer: "https://auth.temis.co.kr",
      audience: "ledger-api",
      algorithms: ["RS256"]
    });

    expect(payload).toMatchObject({
      sub: "auth-user-1",
      aud: "ledger-api"
    });
    expect(() => jwt.verify(token, createPublicKey({ key: publicJwk, format: "jwk" }), {
      issuer: "https://auth.temis.co.kr",
      audience: "temis",
      algorithms: ["RS256"]
    })).toThrow();
  });

  it("Given an active DB user for a relying client When issuing a token pair Then access and refresh tokens use the client audience", async () => {
    const publicJwk = createAccessKeyFixture();
    const { issueTokenPair } = await import("./token.service.js");

    const tokens = await issueTokenPair("auth-user-1", { audience: "ledger-api" });
    const accessPayload = jwt.verify(tokens.accessToken, createPublicKey({ key: publicJwk, format: "jwk" }), {
      issuer: "https://auth.temis.co.kr",
      audience: "ledger-api",
      algorithms: ["RS256"]
    });
    const refreshPayload = jwt.verify(tokens.refreshToken, "test-refresh-secret-long");

    expect(accessPayload).toMatchObject({ aud: "ledger-api" });
    expect(refreshPayload).toMatchObject({ audience: "ledger-api" });
    expect(mocks.refreshToken.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        userId: "auth-user-1",
        audience: "ledger-api"
      })
    });
  });

  it("Given a valid refresh token for a relying client When refresh rotates Then the new token pair keeps the client audience", async () => {
    const publicJwk = createAccessKeyFixture();
    const { rotateRefreshToken } = await import("./token.service.js");
    const refreshToken = jwt.sign(
      { sub: "auth-user-1", type: "refresh", tokenId: "refresh-token-id", audience: "ledger-api" },
      "test-refresh-secret-long",
      { expiresIn: "30d" }
    );
    mocks.refreshToken.findFirst.mockResolvedValue({
      userId: "auth-user-1",
      audience: "ledger-api"
    });
    mocks.refreshToken.updateMany.mockResolvedValue({ count: 1 });
    mocks.refreshToken.create.mockResolvedValue({});

    const rotation = await rotateRefreshToken(refreshToken);
    const accessPayload = jwt.verify(rotation.tokens.accessToken, createPublicKey({ key: publicJwk, format: "jwk" }), {
      issuer: "https://auth.temis.co.kr",
      audience: "ledger-api",
      algorithms: ["RS256"]
    });
    const refreshPayload = jwt.verify(rotation.tokens.refreshToken, "test-refresh-secret-long");

    expect(accessPayload).toMatchObject({ aud: "ledger-api" });
    expect(refreshPayload).toMatchObject({ audience: "ledger-api" });
    expect(mocks.refreshToken.create).toHaveBeenCalledWith({
      data: expect.objectContaining({
        userId: "auth-user-1",
        audience: "ledger-api"
      })
    });
  });
});

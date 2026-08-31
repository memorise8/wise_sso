// allow: SIZE_OK - Token issuance, refresh, JWKS, and revocation regression cases intentionally stay together as one auth-token contract matrix for the final JWKS audit gate.
import { createPublicKey, generateKeyPairSync } from "node:crypto";
import type { JsonWebKey } from "node:crypto";
import jwt from "jsonwebtoken";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { userStatuses } from "./user-status.service.js";

process.env["DATABASE_URL"] = "postgresql://user:password@localhost:5432/auth_db";
process.env["JWT_REFRESH_SECRET"] = "test-refresh-secret-long";
process.env["JWT_ISSUER"] = "https://auth.temis.co.kr";
process.env["JWT_AUDIENCE"] = "temis";
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

const accessKeyId = "temis-access-key-1";

type AccessKeyFixture = {
  readonly privateKeyPem: string;
  readonly publicJwk: JsonWebKey;
};

const createAccessKeyFixture = (): AccessKeyFixture => {
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
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  process.env["JWT_ACCESS_PRIVATE_KEY"] = privateKeyPem.replace(/\n/g, "\\n");
  process.env["JWT_ACCESS_PUBLIC_JWK"] = JSON.stringify(accessPublicJwk);
  process.env["JWT_ACCESS_KEY_ID"] = accessKeyId;
  return {
    privateKeyPem,
    publicJwk: accessPublicJwk
  };
};

const mocks = vi.hoisted(() => ({
  user: {
    findUnique: vi.fn()
  },
  refreshToken: {
    create: vi.fn(),
    findFirst: vi.fn(),
    update: vi.fn(),
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
  mocks.refreshToken.update.mockReset();
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

describe("createAccessToken", () => {
  it("Given auth user claims When access token is created Then payload contains SSO identity roles issuer audience kid rs256 and type access", async () => {
    const fixture = createAccessKeyFixture();
    const { createAccessToken } = await import("./token.service.js");

    const token = createAccessToken({
      id: "auth-user-1",
      email: "user@example.com",
      name: "홍길동",
      emailVerified: true,
      status: userStatuses.active,
      roles: [{ serviceKey: "temis", name: "user" }]
    });
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || typeof decoded === "string") {
      throw new Error("Access token did not decode with a JOSE header");
    }
    const payload = jwt.verify(token, createPublicKey({ key: fixture.publicJwk, format: "jwk" }), {
      issuer: "https://auth.temis.co.kr",
      audience: "temis",
      algorithms: ["RS256"]
    });

    expect(decoded.header).toMatchObject({
      alg: "RS256",
      kid: accessKeyId
    });
    expect(payload).toMatchObject({
      sub: "auth-user-1",
      email: "user@example.com",
      name: "홍길동",
      email_verified: true,
      type: "access",
      roles: [{ serviceKey: "temis", name: "user" }],
      iss: "https://auth.temis.co.kr",
      aud: "temis"
    });
  });

  it("Given newly active pending user claims When access token is created Then payload contains temis pending and no elevated TEMIS roles", async () => {
    const fixture = createAccessKeyFixture();
    const { createAccessToken } = await import("./token.service.js");

    const token = createAccessToken({
      id: "auth-user-1",
      email: "user@example.com",
      name: "Pending User",
      emailVerified: false,
      status: userStatuses.active,
      roles: [{ serviceKey: "temis", name: "pending" }]
    });
    const payload = jwt.verify(token, createPublicKey({ key: fixture.publicJwk, format: "jwk" }), {
      issuer: "https://auth.temis.co.kr",
      audience: "temis",
      algorithms: ["RS256"]
    });

    expect(payload).toMatchObject({
      sub: "auth-user-1",
      roles: [{ serviceKey: "temis", name: "pending" }]
    });
    expect(payload).not.toMatchObject({
      roles: expect.arrayContaining([
        { serviceKey: "temis", name: "user" },
        { serviceKey: "temis", name: "admin" }
      ])
    });
  });

  it.each([
    userStatuses.pendingEmailVerification,
    userStatuses.suspended,
    userStatuses.deleted
  ])("Given %s auth user claims When access token is created Then token creation is rejected", async (status) => {
    const { createAccessToken } = await import("./token.service.js");
    const { HttpError } = await import("../utils/httpError.js");

    expect(() => createAccessToken({
      id: "auth-user-1",
      email: "user@example.com",
      name: "Inactive User",
      emailVerified: false,
      status,
      roles: []
    })).toThrow(new HttpError(401, "UNAUTHORIZED", "Authentication is required"));
  });
});

describe("verifyAccessToken", () => {
  it("Given a non access token or wrong algorithm When access token is verified Then it is rejected", async () => {
    const fixture = createAccessKeyFixture();
    const { verifyAccessToken } = await import("./token.service.js");
    const refreshLikeToken = jwt.sign(
      { sub: "auth-user-1", type: "refresh" },
      fixture.privateKeyPem,
      {
        algorithm: "RS256",
        keyid: accessKeyId,
        issuer: "https://auth.temis.co.kr",
        audience: "temis"
      }
    );
    const hsToken = jwt.sign(
      { sub: "auth-user-1", type: "access" },
      "test-access-secret-long",
      {
        issuer: "https://auth.temis.co.kr",
        audience: "temis"
      }
    );

    expect(() => verifyAccessToken(refreshLikeToken)).toThrow();
    expect(() => verifyAccessToken(hsToken)).toThrow();
    expect(() => jwt.verify(hsToken, createPublicKey({ key: fixture.publicJwk, format: "jwk" }), {
      algorithms: ["RS256"],
      issuer: "https://auth.temis.co.kr",
      audience: "temis"
    })).toThrow();
  });
});

describe("issueTokenPair", () => {
  it.each([
    userStatuses.pendingEmailVerification,
    userStatuses.suspended,
    userStatuses.deleted
  ])("Given a %s DB user When issuing a token pair Then no refresh token is stored", async (_status) => {
    const { issueTokenPair } = await import("./token.service.js");
    const { HttpError } = await import("../utils/httpError.js");
    mocks.queryRaw.mockResolvedValue([]);

    await expect(issueTokenPair("auth-user-1")).rejects.toMatchObject(
      new HttpError(401, "UNAUTHORIZED", "Authentication is required")
    );
    expect(mocks.refreshToken.create).not.toHaveBeenCalled();
  });

  it("Given a user is suspended before the issuance write When issuing a token pair Then the active-row lock blocks minting", async () => {
    const { issueTokenPair } = await import("./token.service.js");
    const { HttpError } = await import("../utils/httpError.js");
    mocks.queryRaw.mockResolvedValue([]);

    await expect(issueTokenPair("auth-user-1")).rejects.toMatchObject(
      new HttpError(401, "UNAUTHORIZED", "Authentication is required")
    );
    expect(mocks.transaction).toHaveBeenCalledTimes(1);
    expect(mocks.user.findUnique).not.toHaveBeenCalled();
    expect(mocks.refreshToken.create).not.toHaveBeenCalled();
  });

  it("Given an active DB user When issuing a token pair Then the active-status check and refresh-token write share one transaction", async () => {
    const { issueTokenPair } = await import("./token.service.js");

    await issueTokenPair("auth-user-1");

    expect(mocks.transaction).toHaveBeenCalledTimes(1);
    expect(mocks.queryRaw).toHaveBeenCalledTimes(1);
    expect(mocks.refreshToken.create).toHaveBeenCalledTimes(1);
  });

});

describe("rotateRefreshToken", () => {
  it("Given the same valid refresh token is used concurrently When refresh rotates Then only one request mints a new token pair", async () => {
    const { HttpError } = await import("../utils/httpError.js");
    const { rotateRefreshToken } = await import("./token.service.js");
    const refreshToken = jwt.sign(
      { sub: "auth-user-1", type: "refresh", tokenId: "refresh-token-id" },
      "test-refresh-secret-long",
      { expiresIn: "30d" }
    );
    mocks.refreshToken.findFirst.mockResolvedValue({
      id: "stored-refresh-token",
      userId: "auth-user-1",
      audience: "temis",
      revokedAt: null,
      expiresAt: new Date(Date.now() + 60_000)
    });
    mocks.refreshToken.update.mockResolvedValue({});
    mocks.refreshToken.updateMany
      .mockResolvedValueOnce({ count: 1 })
      .mockResolvedValueOnce({ count: 0 });
    mocks.user.findUnique.mockResolvedValue({
      id: "auth-user-1",
      email: "user@example.com",
      name: "Test User",
      status: userStatuses.active,
      roles: []
    });
    mocks.refreshToken.create.mockResolvedValue({});

    const results = await Promise.allSettled([
      rotateRefreshToken(refreshToken),
      rotateRefreshToken(refreshToken)
    ]);

    const fulfilledResults = results.filter((result) => result.status === "fulfilled");
    const rejectedResults = results.filter((result) => result.status === "rejected");
    expect(fulfilledResults).toHaveLength(1);
    expect(rejectedResults).toHaveLength(1);
    expect(mocks.refreshToken.create).toHaveBeenCalledTimes(1);
    expect(mocks.transaction).toHaveBeenCalledTimes(2);
    expect(mocks.queryRaw).toHaveBeenCalledTimes(2);
    expect(rejectedResults[0]?.reason).toBeInstanceOf(HttpError);
  });

  it.each([
    userStatuses.pendingEmailVerification,
    userStatuses.suspended,
    userStatuses.deleted
  ])("Given a valid refresh token for a %s user When refresh rotates Then it fails generically and does not mint or revoke", async (_status) => {
    const { HttpError } = await import("../utils/httpError.js");
    const { rotateRefreshToken } = await import("./token.service.js");
    const refreshToken = jwt.sign(
      { sub: "auth-user-1", type: "refresh", tokenId: "refresh-token-id", audience: "temis" },
      "test-refresh-secret-long",
      { expiresIn: "30d" }
    );
    mocks.refreshToken.findFirst.mockResolvedValue({
      userId: "auth-user-1",
      audience: "temis"
    });
    mocks.refreshToken.updateMany.mockResolvedValue({ count: 1 });
    mocks.queryRaw.mockResolvedValue([]);

    await expect(rotateRefreshToken(refreshToken)).rejects.toMatchObject(
      new HttpError(401, "INVALID_REFRESH_TOKEN", "Invalid refresh token")
    );
    expect(
      mocks.queryRaw,
      "matching refresh-token audience must reach the inactive-user active-row lock"
    ).toHaveBeenCalledTimes(1);
    expect(mocks.refreshToken.updateMany).not.toHaveBeenCalled();
    expect(mocks.refreshToken.create).not.toHaveBeenCalled();
  });

});

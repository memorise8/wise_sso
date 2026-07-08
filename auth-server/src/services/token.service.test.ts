import jwt from "jsonwebtoken";
import { beforeEach, describe, expect, it, vi } from "vitest";

process.env["DATABASE_URL"] = "postgresql://user:password@localhost:5432/auth_db";
process.env["JWT_ACCESS_SECRET"] = "test-access-secret-long";
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

const mocks = vi.hoisted(() => ({
  refreshToken: {
    create: vi.fn(),
    findFirst: vi.fn(),
    update: vi.fn(),
    updateMany: vi.fn()
  },
  getCurrentUser: vi.fn()
}));

vi.mock("@prisma/client", () => ({
  PrismaClient: vi.fn(function PrismaClient() {
    return {
      refreshToken: mocks.refreshToken
    };
  })
}));

vi.mock("./user.service.js", () => ({
  getCurrentUser: mocks.getCurrentUser
}));

beforeEach(() => {
  vi.resetModules();
  mocks.refreshToken.create.mockReset();
  mocks.refreshToken.findFirst.mockReset();
  mocks.refreshToken.update.mockReset();
  mocks.refreshToken.updateMany.mockReset();
  mocks.getCurrentUser.mockReset();
});

describe("createAccessToken", () => {
  it("Given auth user claims When access token is created Then payload contains SSO identity roles issuer and audience", async () => {
    const { createAccessToken } = await import("./token.service.js");

    const token = createAccessToken({
      id: "auth-user-1",
      email: "user@example.com",
      name: "홍길동",
      roles: [{ serviceKey: "temis", name: "user" }]
    });
    const payload = jwt.verify(token, "test-access-secret-long", {
      issuer: "https://auth.temis.co.kr",
      audience: "temis"
    });

    expect(payload).toMatchObject({
      sub: "auth-user-1",
      email: "user@example.com",
      name: "홍길동",
      roles: [{ serviceKey: "temis", name: "user" }],
      iss: "https://auth.temis.co.kr",
      aud: "temis"
    });
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
      revokedAt: null,
      expiresAt: new Date(Date.now() + 60_000)
    });
    mocks.refreshToken.update.mockResolvedValue({});
    mocks.refreshToken.updateMany
      .mockResolvedValueOnce({ count: 1 })
      .mockResolvedValueOnce({ count: 0 });
    mocks.getCurrentUser.mockResolvedValue({
      id: "auth-user-1",
      email: "user@example.com",
      name: "Test User",
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
    expect(mocks.getCurrentUser).toHaveBeenCalledTimes(1);
    expect(rejectedResults[0]?.reason).toBeInstanceOf(HttpError);
  });
});

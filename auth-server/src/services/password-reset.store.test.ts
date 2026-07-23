import { beforeEach, describe, expect, it, vi } from "vitest";

const calls: string[] = [];

const mocks = vi.hoisted(() => ({
  passwordCredential: {
    update: vi.fn()
  },
  passwordResetToken: {
    findFirst: vi.fn(),
    updateMany: vi.fn()
  },
  queryRaw: vi.fn(),
  refreshToken: {
    updateMany: vi.fn()
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
  calls.splice(0, calls.length);
  mocks.passwordCredential.update.mockReset();
  mocks.passwordResetToken.findFirst.mockReset();
  mocks.passwordResetToken.updateMany.mockReset();
  mocks.queryRaw.mockReset();
  mocks.refreshToken.updateMany.mockReset();
  mocks.transaction.mockReset();
  mocks.transaction.mockImplementation(async (work) => work({
    $queryRaw: mocks.queryRaw,
    passwordCredential: mocks.passwordCredential,
    passwordResetToken: mocks.passwordResetToken,
    refreshToken: mocks.refreshToken
  }));
  mocks.passwordResetToken.findFirst.mockResolvedValue({
    id: "reset-token-1",
    userId: "target-user"
  });
  mocks.passwordResetToken.updateMany.mockResolvedValue({ count: 1 });
  mocks.passwordCredential.update.mockResolvedValue({});
  mocks.queryRaw.mockImplementation(async () => {
    calls.push("lock-user");
    return [{ id: "target-user" }];
  });
  mocks.refreshToken.updateMany.mockImplementation(async () => {
    calls.push("revoke-refresh-tokens");
    return { count: 2 };
  });
});

describe("passwordResetStore.resetPasswordWithToken", () => {
  it("Given password reset races refresh rotation When reset confirms Then the revocation locks the user row before token revocation", async () => {
    const { passwordResetStore } = await import("./password-reset.store.js");

    const result = await passwordResetStore.resetPasswordWithToken({
      tokenHash: "token-hash",
      passwordHash: "new-password-hash",
      now: new Date("2026-07-23T01:30:00.000Z")
    });

    expect(result).toEqual({ userId: "target-user" });
    expect(calls).toEqual(["lock-user", "revoke-refresh-tokens"]);
  });
});

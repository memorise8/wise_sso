import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  failedLoginCount: 0,
  lockedUntil: null as Date | null
}));

const mocks = vi.hoisted(() => ({
  transaction: vi.fn(),
  updateMany: vi.fn()
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
  state.failedLoginCount = 0;
  state.lockedUntil = null;
  mocks.transaction.mockReset();
  mocks.updateMany.mockReset();
  mocks.transaction.mockImplementation(async (work) => work({
    passwordCredential: { updateMany: mocks.updateMany }
  }));
  mocks.updateMany.mockImplementation(async ({ where, data }) => {
    if (data.failedLoginCount) {
      await Promise.resolve();
      state.failedLoginCount += data.failedLoginCount.increment;
      return { count: 1 };
    }

    if (state.failedLoginCount >= where.failedLoginCount.gte) {
      state.lockedUntil = data.lockedUntil;
      return { count: 1 };
    }
    return { count: 0 };
  });
});

describe("passwordAuthStore.markLoginFailure", () => {
  it("Given fewer than five failed logins When failures are recorded Then the account remains unlocked", async () => {
    const { passwordAuthStore } = await import("./password-auth.store.js");

    await Promise.all(Array.from({ length: 4 }, () => passwordAuthStore.markLoginFailure("user-1")));

    expect(state.failedLoginCount).toBe(4);
    expect(state.lockedUntil).toBeNull();
  });

  it("Given concurrent failed logins When failures are recorded Then no increments are lost and the account is locked", async () => {
    const { passwordAuthStore } = await import("./password-auth.store.js");

    await Promise.all(Array.from({ length: 5 }, () => passwordAuthStore.markLoginFailure("user-1")));

    expect(state.failedLoginCount).toBe(5);
    expect(state.lockedUntil).toBeInstanceOf(Date);
    expect(mocks.updateMany).toHaveBeenCalledWith({
      where: { userId: "user-1" },
      data: { failedLoginCount: { increment: 1 } }
    });
  });

  it("Given a missing credential When a failure is recorded Then it remains a no-op", async () => {
    mocks.updateMany.mockResolvedValueOnce({ count: 0 });
    const { passwordAuthStore } = await import("./password-auth.store.js");

    await expect(passwordAuthStore.markLoginFailure("missing-user")).resolves.toBeUndefined();

    expect(mocks.updateMany).toHaveBeenCalledTimes(1);
  });
});

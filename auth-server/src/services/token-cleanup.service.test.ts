import { describe, expect, it } from "vitest";
import { cleanupRefreshTokens } from "./token-cleanup.service.js";
import type { RefreshTokenCleanupStore } from "./token-cleanup.service.js";

type StoredRefreshToken = {
  readonly id: string;
  readonly expiresAt: Date;
  readonly revokedAt: Date | null;
};

type TestStore = RefreshTokenCleanupStore & {
  readonly tokens: () => readonly StoredRefreshToken[];
};

const fixedNow = new Date("2026-07-08T00:00:00.000Z");
const oldDate = new Date("2026-06-01T00:00:00.000Z");
const recentDate = new Date("2026-07-01T00:00:00.000Z");
const futureDate = new Date("2026-08-01T00:00:00.000Z");

const isCleanupEligible = (token: StoredRefreshToken, cutoff: Date): boolean =>
  token.expiresAt < cutoff || (token.revokedAt !== null && token.revokedAt < cutoff);

const createStore = (initialTokens: readonly StoredRefreshToken[]): TestStore => {
  const tokens = [...initialTokens];

  return {
    tokens: () => tokens,
    countRefreshTokensEligibleForCleanup: async (cutoff) =>
      tokens.filter((token) => isCleanupEligible(token, cutoff)).length,
    deleteRefreshTokensEligibleForCleanup: async (cutoff) => {
      const deletedCount = tokens.filter((token) => isCleanupEligible(token, cutoff)).length;
      for (let index = tokens.length - 1; index >= 0; index -= 1) {
        const token = tokens[index];
        if (token && isCleanupEligible(token, cutoff)) {
          tokens.splice(index, 1);
        }
      }
      return deletedCount;
    }
  };
};

describe("refresh token cleanup service", () => {
  it("Given expired and revoked refresh tokens older than retention When cleanup runs Then it deletes only cleanup-eligible tokens", async () => {
    const store = createStore([
      { id: "expired-old", expiresAt: oldDate, revokedAt: null },
      { id: "revoked-old", expiresAt: futureDate, revokedAt: oldDate },
      { id: "expired-recent", expiresAt: recentDate, revokedAt: null },
      { id: "revoked-recent", expiresAt: futureDate, revokedAt: recentDate },
      { id: "active", expiresAt: futureDate, revokedAt: null }
    ]);

    const result = await cleanupRefreshTokens(store, {
      dryRun: false,
      now: fixedNow,
      retentionDays: 14
    });

    expect(result).toEqual({
      deletedCount: 2,
      dryRun: false,
      retentionDays: 14,
      cutoff: new Date("2026-06-24T00:00:00.000Z")
    });
    expect(store.tokens().map((token) => token.id)).toEqual(["expired-recent", "revoked-recent", "active"]);
  });

  it("Given cleanup-eligible refresh tokens When cleanup runs in dry-run mode Then it reports the count without deleting rows", async () => {
    const store = createStore([
      { id: "expired-old", expiresAt: oldDate, revokedAt: null },
      { id: "revoked-old", expiresAt: futureDate, revokedAt: oldDate },
      { id: "active", expiresAt: futureDate, revokedAt: null }
    ]);

    const result = await cleanupRefreshTokens(store, {
      dryRun: true,
      now: fixedNow,
      retentionDays: 14
    });

    expect(result.deletedCount).toBe(2);
    expect(result.dryRun).toBe(true);
    expect(store.tokens().map((token) => token.id)).toEqual(["expired-old", "revoked-old", "active"]);
  });
});

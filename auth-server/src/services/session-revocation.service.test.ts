import { describe, expect, it } from "vitest";
import { HttpError } from "../utils/httpError.js";
import { revokeAllRefreshTokensForUser } from "./session-revocation.service.js";
import type { RefreshTokenRevocationStore } from "./session-revocation.service.js";

type RefreshTokenRecord = {
  readonly userId: string;
  readonly revokedAt: Date | null;
};

const createStore = (
  refreshTokens: readonly RefreshTokenRecord[]
): RefreshTokenRevocationStore & { readonly refreshTokens: RefreshTokenRecord[] } => {
  const tokenRecords = [...refreshTokens];

  return {
    refreshTokens: tokenRecords,
    revokeAllRefreshTokensForUser: async (input) => {
      let revokedCount = 0;

      for (const [index, refreshToken] of tokenRecords.entries()) {
        if (refreshToken.userId === input.userId && refreshToken.revokedAt === null) {
          tokenRecords.splice(index, 1, {
            ...refreshToken,
            revokedAt: input.revokedAt
          });
          revokedCount += 1;
        }
      }

      return revokedCount;
    }
  };
};

describe("revokeAllRefreshTokensForUser", () => {
  it("Given refresh tokens for two users When one user is revoked Then only that user's active refresh tokens are revoked", async () => {
    const revokedAt = new Date("2026-07-22T01:00:00.000Z");
    const alreadyRevokedAt = new Date("2026-07-21T01:00:00.000Z");
    const store = createStore([
      { userId: "target-user", revokedAt: null },
      { userId: "target-user", revokedAt: alreadyRevokedAt },
      { userId: "target-user", revokedAt: null },
      { userId: "other-user", revokedAt: null }
    ]);

    const result = await revokeAllRefreshTokensForUser(store, {
      userId: "target-user",
      revokedAt
    });

    expect(result).toEqual({ revokedCount: 2 });
    expect(store.refreshTokens.filter((refreshToken) => refreshToken.userId === "target-user" && refreshToken.revokedAt === revokedAt)).toHaveLength(2);
    expect(store.refreshTokens.find((refreshToken) => refreshToken.userId === "other-user")?.revokedAt).toBeNull();
    expect(store.refreshTokens.find((refreshToken) => refreshToken.revokedAt === alreadyRevokedAt)?.revokedAt).toBe(alreadyRevokedAt);
  });

  it("Given a malformed user id When refresh tokens are revoked Then the service rejects before store mutation", async () => {
    const store = createStore([{ userId: "target-user", revokedAt: null }]);

    await expect(revokeAllRefreshTokensForUser(store, {
      userId: " ",
      revokedAt: new Date("2026-07-22T01:00:00.000Z")
    })).rejects.toMatchObject(new HttpError(400, "INVALID_USER_ID", "User id is required"));
    expect(store.refreshTokens[0]?.revokedAt).toBeNull();
  });
});

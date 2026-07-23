import { describe, expect, it } from "vitest";
import { createOAuthStateStore } from "./oauth-state.store.js";
import type { RedisTtlStoreClient } from "./redis.client.js";

type StoredValue = {
  readonly value: string;
  readonly ttlSeconds: number;
};

const createRedisFake = (): RedisTtlStoreClient & {
  readonly values: Map<string, StoredValue>;
  readonly ttlSecondsByKey: Map<string, number>;
} => {
  const values = new Map<string, StoredValue>();
  const ttlSecondsByKey = new Map<string, number>();

  return {
    values,
    ttlSecondsByKey,
    setIfAbsent: async (key, value, ttlSeconds) => {
      if (values.has(key)) {
        return false;
      }

      values.set(key, { value, ttlSeconds });
      ttlSecondsByKey.set(key, ttlSeconds);
      return true;
    },
    consume: async (key) => {
      const stored = values.get(key);
      if (!stored) {
        return null;
      }

      values.delete(key);
      return stored.value;
    }
  };
};

describe("OAuthStateStore", () => {
  it("Given a created Google state with metadata When it is consumed once by Google Then it returns metadata and uses a ten-minute Redis TTL", async () => {
    const redis = createRedisFake();
    const store = createOAuthStateStore(redis);
    const metadata = {
      clientId: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      callerState: "qa-state",
      codeChallenge: "challenge",
      codeChallengeMethod: "S256"
    } as const;

    const state = await store.create("google", metadata);
    const ttlSeconds = [...redis.ttlSecondsByKey.values()];
    const consumed = await store.consume("google", state);
    const secondConsume = await store.consume("google", state);

    expect(consumed).toEqual(metadata);
    expect(secondConsume).toBeNull();
    expect(ttlSeconds).toEqual([600]);
    expect([...redis.values.values()]).toEqual([]);
  });

  it("Given a created Google state When it is consumed by another provider Then it is rejected and cannot be replayed", async () => {
    const redis = createRedisFake();
    const store = createOAuthStateStore(redis);
    const metadata = {
      clientId: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      callerState: null,
      codeChallenge: "challenge",
      codeChallengeMethod: "S256"
    } as const;

    const state = await store.create("google", metadata);
    const wrongProviderConsume = await store.consume("naver", state);
    const replay = await store.consume("google", state);

    expect(wrongProviderConsume).toBeNull();
    expect(replay).toBeNull();
  });
});

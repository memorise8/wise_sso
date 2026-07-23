import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createAuthHandoffStore } from "./auth-handoff.store.js";
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
    get: async (key) => values.get(key)?.value ?? null,
    consume: async (key) => {
      const stored = values.get(key);
      if (!stored) {
        return null;
      }

      values.delete(key);
      return stored.value;
    },
    consumeIfValue: async (key, expectedValue) => {
      const stored = values.get(key);
      if (!stored || stored.value !== expectedValue) {
        return null;
      }

      values.delete(key);
      return stored.value;
    }
  };
};

describe("AuthHandoffStore", () => {
  const codeVerifier = "verifier-123456789012345678901234567890123";
  const codeChallenge = createHash("sha256").update(codeVerifier).digest("base64url");

  it("Given a created handoff When Redis is inspected Then the raw code is not used as a key and no token pair is stored", async () => {
    const redis = createRedisFake();
    const store = createAuthHandoffStore(redis);
    const handoff = {
      accessToken: "access-token",
      refreshToken: "refresh-token",
      clientId: "temis",
      audience: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      userId: "user-1",
      provider: "google",
      loginMethod: "oauth",
      codeChallenge,
      codeChallengeMethod: "S256",
      state: "oauth-state"
    };

    const code = await store.create(handoff);
    const ttlSeconds = [...redis.ttlSecondsByKey.values()];
    const storedKeys = [...redis.values.keys()];
    const storedValues = [...redis.values.values()].map((storedValue) => storedValue.value);

    expect(storedKeys).toHaveLength(1);
    expect(storedKeys[0]).not.toContain(code);
    expect(storedValues.join("\n")).not.toContain("access-token");
    expect(storedValues.join("\n")).not.toContain("refresh-token");
    expect(ttlSeconds).toEqual([120]);
  });

  it("Given a client and PKCE bound handoff When it is consumed twice Then matching metadata is returned once", async () => {
    const redis = createRedisFake();
    const store = createAuthHandoffStore(redis);
    const code = await store.create({
      clientId: "temis",
      audience: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      userId: "user-1",
      provider: "google",
      loginMethod: "oauth",
      codeChallenge,
      codeChallengeMethod: "S256",
      state: "oauth-state"
    });

    const firstConsume = await store.consume({
      clientId: "temis",
      audience: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      code,
      codeVerifier
    });
    const secondConsume = await store.consume({
      clientId: "temis",
      audience: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      code,
      codeVerifier
    });

    expect(firstConsume).toMatchObject({
      clientId: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      userId: "user-1",
      provider: "google",
      loginMethod: "oauth",
      codeChallengeMethod: "S256",
      state: "oauth-state"
    });
    expect(secondConsume).toBeNull();
    expect([...redis.values.values()]).toEqual([]);
  });

  it("Given a client and PKCE bound handoff When two matching consumes race Then metadata is returned once", async () => {
    const redis = createRedisFake();
    const store = createAuthHandoffStore(redis);
    const code = await store.create({
      clientId: "temis",
      audience: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      userId: "user-1",
      provider: "google",
      loginMethod: "oauth",
      codeChallenge,
      codeChallengeMethod: "S256",
      state: "oauth-state"
    });
    const validConsume = {
      clientId: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      code,
      codeVerifier
    };

    const results = await Promise.all([
      store.consume(validConsume),
      store.consume(validConsume)
    ]);
    const successes = results.filter((result) => result !== null);
    const failures = results.filter((result) => result === null);

    expect(successes).toHaveLength(1);
    expect(successes).toEqual([
      expect.objectContaining({
        clientId: "temis",
        redirectUri: "https://financenow.kr/auth/callback",
        userId: "user-1"
      })
    ]);
    expect(failures).toHaveLength(1);
    expect([...redis.values.values()]).toEqual([]);
  });

  it.each([
    ["wrong client", { clientId: "other", redirectUri: "https://financenow.kr/auth/callback", codeVerifier }],
    ["wrong redirect", { clientId: "temis", redirectUri: "https://evil.example/callback", codeVerifier }],
    ["wrong verifier", { clientId: "temis", redirectUri: "https://financenow.kr/auth/callback", codeVerifier: "wrong" }]
  ])("Given a bound handoff When it is consumed with the %s Then it fails without consuming the code", async (_name, attempt) => {
    const redis = createRedisFake();
    const store = createAuthHandoffStore(redis);
    const code = await store.create({
      clientId: "temis",
      audience: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      userId: "user-1",
      provider: "google",
      loginMethod: "oauth",
      codeChallenge,
      codeChallengeMethod: "S256",
      state: "oauth-state"
    });

    const rejected = await store.consume({ ...attempt, code });
    const validConsume = await store.consume({
      clientId: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      code,
      codeVerifier
    });
    const replay = await store.consume({
      clientId: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      code,
      codeVerifier
    });

    expect(rejected).toBeNull();
    expect(validConsume).toMatchObject({
      clientId: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      userId: "user-1",
      provider: "google",
      loginMethod: "oauth",
      codeChallengeMethod: "S256",
      state: "oauth-state"
    });
    expect(replay).toBeNull();
  });

  it("Given a handoff older than two minutes When it is consumed Then it fails generically and consumes the code", async () => {
    const redis = createRedisFake();
    let now = 1_000_000;
    const store = createAuthHandoffStore(redis, { now: () => now });
    const code = await store.create({
      clientId: "temis",
      audience: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      userId: "user-1",
      provider: "google",
      loginMethod: "oauth",
      codeChallenge,
      codeChallengeMethod: "S256",
      state: "oauth-state"
    });
    now += 121_000;

    const expired = await store.consume({
      clientId: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      code,
      codeVerifier
    });
    const replay = await store.consume({
      clientId: "temis",
      redirectUri: "https://financenow.kr/auth/callback",
      code,
      codeVerifier
    });

    expect(expired).toBeNull();
    expect(replay).toBeNull();
  });
});

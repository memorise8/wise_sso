import { randomUUID } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { createClient } from "redis";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

const integrationEnabled = process.env.PHASE0_INTEGRATION === "1";
const databaseUrl = process.env.PHASE0_DATABASE_URL ?? "";
const redisUrl = process.env.PHASE0_REDIS_URL ?? "";

const requireDisposableEndpoint = (
  rawUrl: string,
  expectedPort: string,
  expectedProtocol: "postgresql:" | "redis:"
): void => {
  const url = new URL(rawUrl);
  if (
    url.protocol !== expectedProtocol
    || !["127.0.0.1", "localhost"].includes(url.hostname)
    || url.port !== expectedPort
  ) {
    throw new Error(`Phase 0 integration tests require disposable ${expectedProtocol} on localhost:${expectedPort}`);
  }
};

if (integrationEnabled) {
  requireDisposableEndpoint(databaseUrl, "5433", "postgresql:");
  requireDisposableEndpoint(redisUrl, "6380", "redis:");
  process.env.DATABASE_URL = databaseUrl;
  process.env.REDIS_URL = redisUrl;
}

const integrationDescribe = integrationEnabled ? describe : describe.skip;

integrationDescribe("Phase 0 real PostgreSQL and Redis concurrency", () => {
  const fixturePrisma = new PrismaClient({
    datasources: { db: { url: databaseUrl } }
  });
  const redisInspector = createClient({ url: redisUrl });
  const fixtureUserIds = new Set<string>();
  const redisKeys = new Set<string>();
  let passwordAuthStore: typeof import("./password-auth.store.js").passwordAuthStore;
  let redisTtlStoreClient: typeof import("./redis.client.js").redisTtlStoreClient;
  let connectRedis: typeof import("./redis.client.js").connectRedis;
  let closeRedis: typeof import("./redis.client.js").closeRedis;

  const createPasswordCredential = async (): Promise<string> => {
    const fixtureId = randomUUID();
    const user = await fixturePrisma.user.create({
      data: {
        email: `phase0-${fixtureId}@integration.invalid`,
        status: "ACTIVE",
        passwordCredential: {
          create: {
            email: `phase0-${fixtureId}@integration.invalid`,
            passwordHash: "phase0-integration-fixture-only"
          }
        }
      }
    });
    fixtureUserIds.add(user.id);
    return user.id;
  };

  const uniqueRedisKey = (label: string): string => {
    const key = `wiseacct:phase0-integration:${label}:${randomUUID()}`;
    redisKeys.add(key);
    return key;
  };

  const waitUntilRedisKeyExpires = async (key: string, timeoutMs: number): Promise<void> => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if ((await redisInspector.exists(key)) === 0) {
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new Error(`Redis key did not expire within ${timeoutMs}ms: ${key}`);
  };

  beforeAll(async () => {
    const passwordStoreModule = await import("./password-auth.store.js");
    const redisModule = await import("./redis.client.js");
    passwordAuthStore = passwordStoreModule.passwordAuthStore;
    redisTtlStoreClient = redisModule.redisTtlStoreClient;
    connectRedis = redisModule.connectRedis;
    closeRedis = redisModule.closeRedis;
    await fixturePrisma.$connect();
    await redisInspector.connect();
    await connectRedis();
  });

  afterEach(async () => {
    if (fixtureUserIds.size > 0) {
      await fixturePrisma.user.deleteMany({ where: { id: { in: [...fixtureUserIds] } } });
      fixtureUserIds.clear();
    }
    if (redisKeys.size > 0) {
      await redisInspector.del([...redisKeys]);
      redisKeys.clear();
    }
  });

  afterAll(async () => {
    await closeRedis();
    if (redisInspector.isOpen) {
      await redisInspector.close();
    }
    await fixturePrisma.$disconnect();
  });

  it("records exactly 20 failures and locks the credential when 20 independent operations race", async () => {
    const userId = await createPasswordCredential();

    await Promise.all(Array.from({ length: 20 }, () => passwordAuthStore.markLoginFailure(userId)));

    const credential = await fixturePrisma.passwordCredential.findUniqueOrThrow({ where: { userId } });
    expect(credential.failedLoginCount).toBe(20);
    expect(credential.lockedUntil).toBeInstanceOf(Date);
    expect(credential.lockedUntil!.getTime()).toBeGreaterThan(Date.now() + 14 * 60 * 1000);
  });

  it("leaves a credential unlocked below the five-failure threshold", async () => {
    const userId = await createPasswordCredential();

    await Promise.all(Array.from({ length: 4 }, () => passwordAuthStore.markLoginFailure(userId)));

    const credential = await fixturePrisma.passwordCredential.findUniqueOrThrow({ where: { userId } });
    expect(credential.failedLoginCount).toBe(4);
    expect(credential.lockedUntil).toBeNull();
  });

  it("locks a credential when the fifth failure reaches the threshold", async () => {
    const userId = await createPasswordCredential();

    await Promise.all(Array.from({ length: 5 }, () => passwordAuthStore.markLoginFailure(userId)));

    const credential = await fixturePrisma.passwordCredential.findUniqueOrThrow({ where: { userId } });
    expect(credential.failedLoginCount).toBe(5);
    expect(credential.lockedUntil).toBeInstanceOf(Date);
  });

  it("returns successfully without creating a credential when the user is missing", async () => {
    const missingUserId = randomUUID();

    await expect(passwordAuthStore.markLoginFailure(missingUserId)).resolves.toBeUndefined();

    await expect(fixturePrisma.passwordCredential.findUnique({ where: { userId: missingUserId } }))
      .resolves.toBeNull();
  });

  it("returns every count from 1 through 50 when 50 Redis increments race", async () => {
    const key = uniqueRedisKey("concurrent-counts");

    const counts = await Promise.all(
      Array.from({ length: 50 }, () => redisTtlStoreClient.incrementWithTtl(key, 10))
    );

    expect(counts.toSorted((left, right) => left - right)).toEqual(
      Array.from({ length: 50 }, (_, index) => index + 1)
    );
  });

  it("stores value 50 with a TTL after 50 concurrent Redis increments", async () => {
    const key = uniqueRedisKey("final-value-and-ttl");

    await Promise.all(Array.from({ length: 50 }, () => redisTtlStoreClient.incrementWithTtl(key, 10)));

    expect(await redisInspector.get(key)).toBe("50");
    expect(await redisInspector.pTTL(key)).toBeGreaterThan(0);
  });

  it("does not extend the initial Redis TTL on a later increment", async () => {
    const key = uniqueRedisKey("ttl-not-extended");
    await redisTtlStoreClient.incrementWithTtl(key, 4);
    await new Promise((resolve) => setTimeout(resolve, 1_100));
    const ttlBeforeSecondIncrement = await redisInspector.pTTL(key);

    await redisTtlStoreClient.incrementWithTtl(key, 4);

    const ttlAfterSecondIncrement = await redisInspector.pTTL(key);
    expect(ttlAfterSecondIncrement).toBeLessThanOrEqual(ttlBeforeSecondIncrement);
    expect(ttlAfterSecondIncrement).toBeLessThan(3_500);
  });

  it("repairs a legacy Redis rate-limit key that has no TTL", async () => {
    const key = uniqueRedisKey("legacy-without-ttl");
    await redisInspector.set(key, "7");
    expect(await redisInspector.ttl(key)).toBe(-1);

    await expect(redisTtlStoreClient.incrementWithTtl(key, 10)).resolves.toBe(8);

    expect(await redisInspector.get(key)).toBe("8");
    expect(await redisInspector.pTTL(key)).toBeGreaterThan(0);
  });

  it("expires the Redis rate-limit key after its initial TTL", async () => {
    const key = uniqueRedisKey("expires");
    await redisTtlStoreClient.incrementWithTtl(key, 1);

    await waitUntilRedisKeyExpires(key, 2_500);

    expect(await redisInspector.exists(key)).toBe(0);
  });

  it("fails closed when Redis is unavailable", async () => {
    await closeRedis();

    await expect(redisTtlStoreClient.incrementWithTtl(uniqueRedisKey("unavailable"), 10))
      .rejects.toMatchObject({
        name: "RedisUnavailableError",
        message: "Redis is unavailable for authentication state storage"
      });

    await connectRedis();
  });
});

import { createClient } from "redis";
import { env } from "../config/env.js";

const consumeOnceScript = [
  "local value = redis.call('GET', KEYS[1])",
  "if value then redis.call('DEL', KEYS[1]) end",
  "return value"
].join("\n");
const consumeIfValueScript = [
  "local value = redis.call('GET', KEYS[1])",
  "if not value then return nil end",
  "if value == ARGV[1] then redis.call('DEL', KEYS[1]); return value end",
  "return nil"
].join("\n");

export type RedisTtlStoreClient = {
  readonly setIfAbsent: (key: string, value: string, ttlSeconds: number) => Promise<boolean>;
  readonly get?: (key: string) => Promise<string | null>;
  readonly incrementWithTtl: (key: string, ttlSeconds: number) => Promise<number>;
  readonly consume: (key: string) => Promise<string | null>;
  readonly consumeIfValue?: (key: string, expectedValue: string) => Promise<string | null>;
};

export class RedisUnavailableError extends Error {
  public constructor(cause: unknown) {
    super("Redis is unavailable for authentication state storage", { cause });
    this.name = "RedisUnavailableError";
  }
}

const redisClient = createClient({
  url: env.REDIS_URL,
  disableOfflineQueue: true,
  socket: { reconnectStrategy: false }
});

redisClient.on("error", () => undefined);

const ensureReady = (): void => {
  if (!redisClient.isReady) {
    throw new RedisUnavailableError(new Error("Redis client is not connected"));
  }
};

const withRedis = async <Value>(operation: () => Promise<Value>): Promise<Value> => {
  try {
    ensureReady();
    return await operation();
  } catch (error) {
    if (error instanceof RedisUnavailableError) {
      throw error;
    }
    throw new RedisUnavailableError(error);
  }
};

export const redisTtlStoreClient: RedisTtlStoreClient = {
  setIfAbsent: async (key, value, ttlSeconds) => withRedis(async () => {
    const result = await redisClient.set(key, value, { EX: ttlSeconds, NX: true });
    return result === "OK";
  }),
  get: async (key) => withRedis(async () => {
    const result = await redisClient.get(key);
    return typeof result === "string" ? result : null;
  }),
  incrementWithTtl: async (key, ttlSeconds) => withRedis(async () => {
    const count = await redisClient.incr(key);
    if (count === 1) {
      await redisClient.expire(key, ttlSeconds);
    }
    return count;
  }),
  consume: async (key) => withRedis(async () => {
    const result = await redisClient.eval(consumeOnceScript, {
      keys: [key],
      arguments: []
    });
    return typeof result === "string" ? result : null;
  }),
  consumeIfValue: async (key, expectedValue) => withRedis(async () => {
    const result = await redisClient.eval(consumeIfValueScript, {
      keys: [key],
      arguments: [expectedValue]
    });
    return typeof result === "string" ? result : null;
  })
};

export const connectRedis = async (): Promise<void> => {
  if (redisClient.isReady) {
    return;
  }

  try {
    await redisClient.connect();
  } catch (error) {
    throw new RedisUnavailableError(error);
  }
};

export const closeRedis = async (): Promise<void> => {
  if (redisClient.isOpen) {
    await redisClient.close();
  }
};

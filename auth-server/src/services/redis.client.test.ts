import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  client: {
    close: vi.fn(),
    connect: vi.fn(),
    eval: vi.fn(),
    get: vi.fn(),
    isOpen: false,
    isReady: false,
    on: vi.fn(),
    set: vi.fn()
  }
}));

vi.mock("redis", () => ({
  createClient: vi.fn(() => mocks.client)
}));

beforeEach(() => {
  vi.resetModules();
  mocks.client.eval.mockReset();
  mocks.client.isReady = false;
});

describe("redisTtlStoreClient", () => {
  it("Given Redis has not connected When an auth state operation is requested Then it fails closed", async () => {
    const { RedisUnavailableError, redisTtlStoreClient } = await import("./redis.client.js");

    await expect(redisTtlStoreClient.setIfAbsent("auth:test", "value", 60))
      .rejects.toBeInstanceOf(RedisUnavailableError);
  });

  it("Given a rate-limit key When it is incremented Then count and initial TTL are set by one atomic script", async () => {
    mocks.client.isReady = true;
    mocks.client.eval.mockResolvedValue(1);
    const { redisTtlStoreClient } = await import("./redis.client.js");

    await expect(redisTtlStoreClient.incrementWithTtl("rate:test", 60)).resolves.toBe(1);

    expect(mocks.client.eval).toHaveBeenCalledTimes(1);
    expect(mocks.client.eval).toHaveBeenCalledWith(
      expect.stringContaining("redis.call('INCR', KEYS[1])"),
      { keys: ["rate:test"], arguments: ["60"] }
    );
    expect(mocks.client.eval.mock.calls[0]?.[0]).toContain("redis.call('EXPIRE', KEYS[1], ARGV[1])");
  });

  it("Given a legacy rate-limit key without a TTL When it is incremented Then the atomic script repairs its expiry", async () => {
    mocks.client.isReady = true;
    mocks.client.eval.mockResolvedValue(8);
    const { redisTtlStoreClient } = await import("./redis.client.js");

    await expect(redisTtlStoreClient.incrementWithTtl("rate:legacy", 60)).resolves.toBe(8);

    const script = mocks.client.eval.mock.calls[0]?.[0];
    expect(script).toContain("count == 1 or redis.call('TTL', KEYS[1]) < 0");
    expect(script).toContain("redis.call('EXPIRE', KEYS[1], ARGV[1])");
  });

  it("Given Redis rejects the atomic rate-limit operation When incrementing Then it fails closed", async () => {
    mocks.client.isReady = true;
    mocks.client.eval.mockRejectedValue(new Error("redis unavailable"));
    const { RedisUnavailableError, redisTtlStoreClient } = await import("./redis.client.js");

    await expect(redisTtlStoreClient.incrementWithTtl("rate:test", 60))
      .rejects.toBeInstanceOf(RedisUnavailableError);
  });
});

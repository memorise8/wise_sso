import { describe, expect, it } from "vitest";
import { RedisUnavailableError, redisTtlStoreClient } from "./redis.client.js";

describe("redisTtlStoreClient", () => {
  it("Given Redis has not connected When an auth state operation is requested Then it fails closed", async () => {
    await expect(redisTtlStoreClient.setIfAbsent("auth:test", "value", 60))
      .rejects.toBeInstanceOf(RedisUnavailableError);
  });
});

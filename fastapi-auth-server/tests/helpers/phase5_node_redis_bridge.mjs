import { createHash } from "node:crypto";
import { createRequire } from "node:module";

const require = createRequire(`${process.cwd()}/package.json`);
const { createClient } = require("redis");

const [mode, redisUrl, payload] = process.argv.slice(2);
const client = createClient({ url: redisUrl });

const consumeIfExact = `
local value = redis.call('GET', KEYS[1])
if not value then return nil end
if value == ARGV[1] then redis.call('DEL', KEYS[1]); return value end
return nil
`.trim();

try {
  await client.connect();
  if (mode === "produce-oauth-state") {
    const input = JSON.parse(payload);
    const key = `wiseacct:oauth-state:${input.state}`;
    const value = JSON.stringify(input.record);
    await client.set(key, value, { EX: 600 });
    process.stdout.write(JSON.stringify({ key, value }));
  } else if (mode === "consume-handoff") {
    const input = JSON.parse(payload);
    const key = `wiseacct:auth-handoff:${createHash("sha256").update(input.code).digest("hex")}`;
    const value = await client.get(key);
    if (!value) throw new Error("handoff missing");
    const record = JSON.parse(value);
    const challenge = createHash("sha256").update(input.codeVerifier).digest("base64url");
    if (record.clientId !== input.clientId || record.redirectUri !== input.redirectUri || record.codeChallenge !== challenge) {
      throw new Error("handoff binding mismatch");
    }
    const consumed = await client.eval(consumeIfExact, { keys: [key], arguments: [value] });
    if (consumed !== value) throw new Error("handoff compare-and-delete failed");
    process.stdout.write(value);
  } else {
    throw new Error(`unknown mode: ${mode}`);
  }
} finally {
  if (client.isOpen) await client.quit();
}

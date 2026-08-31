import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import type { Provider } from "./user.service.js";
import { redisTtlStoreClient } from "./redis.client.js";
import type { RedisTtlStoreClient } from "./redis.client.js";

const AUTH_HANDOFF_CODE_BYTES = 32;
const AUTH_HANDOFF_TTL_SECONDS = 2 * 60;
const AUTH_HANDOFF_KEY_PREFIX = "wiseacct:auth-handoff:";
const MAX_HANDOFF_GENERATION_ATTEMPTS = 3;

const authHandoffMetadataSchema = z.object({
  clientId: z.string().min(1),
  audience: z.string().min(1),
  redirectUri: z.string().url(),
  userId: z.string().min(1),
  provider: z.enum(["google", "naver", "kakao"]).optional(),
  loginMethod: z.enum(["oauth", "password"]),
  codeChallenge: z.string().min(1),
  codeChallengeMethod: z.literal("S256"),
  state: z.string().min(1).nullable(),
  expiresAtEpochMs: z.number().int().positive()
}).strict();

type StoredAuthHandoffMetadata = z.infer<typeof authHandoffMetadataSchema>;

export type AuthHandoffCreateInput = {
  readonly clientId: string;
  readonly audience: string;
  readonly redirectUri: string;
  readonly userId: string;
  readonly provider?: Provider;
  readonly loginMethod: "oauth" | "password";
  readonly codeChallenge: string;
  readonly codeChallengeMethod: "S256";
  readonly state: string | null;
};

export type AuthHandoffConsumeInput = {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly code: string;
  readonly codeVerifier: string;
};

export type AuthHandoffStore = {
  readonly create: (metadata: AuthHandoffCreateInput) => Promise<string>;
  readonly consume: (input: AuthHandoffConsumeInput) => Promise<StoredAuthHandoffMetadata | null>;
};

type AuthHandoffStoreOptions = {
  readonly now?: () => number;
};

type ValidatedConsumeRedisClient = RedisTtlStoreClient & {
  readonly get: (key: string) => Promise<string | null>;
  readonly consumeIfValue: (key: string, expectedValue: string) => Promise<string | null>;
};

export class AuthHandoffCreationError extends Error {
  public constructor() {
    super("Unable to generate a unique authorization handoff code");
    this.name = "AuthHandoffCreationError";
  }
}

export class AuthHandoffPersistenceError extends Error {
  public constructor() {
    super("Auth handoff storage does not support validated atomic consume");
    this.name = "AuthHandoffPersistenceError";
  }
}

const sha256Hex = (value: string): string => createHash("sha256").update(value).digest("hex");
const sha256Base64Url = (value: string): string => createHash("sha256").update(value).digest("base64url");

const keyForCode = (code: string): string => `${AUTH_HANDOFF_KEY_PREFIX}${sha256Hex(code)}`;

const parseStoredMetadata = (serializedMetadata: string): StoredAuthHandoffMetadata | null => {
  try {
    return authHandoffMetadataSchema.safeParse(JSON.parse(serializedMetadata)).data ?? null;
  } catch (error) {
    if (error instanceof SyntaxError) {
      return null;
    }
    throw error;
  }
};

const safeEqual = (left: string, right: string): boolean => {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
};

const matchesExchangeBinding = (
  metadata: StoredAuthHandoffMetadata,
  input: AuthHandoffConsumeInput
): boolean => {
  return metadata.clientId === input.clientId &&
    metadata.redirectUri === input.redirectUri &&
    safeEqual(metadata.codeChallenge, sha256Base64Url(input.codeVerifier));
};

const supportsValidatedConsume = (redis: RedisTtlStoreClient): redis is ValidatedConsumeRedisClient => {
  return typeof redis.get === "function" && typeof redis.consumeIfValue === "function";
};

export const createAuthHandoffStore = (
  redis: RedisTtlStoreClient,
  options: AuthHandoffStoreOptions = {}
): AuthHandoffStore => {
  const now = options.now ?? Date.now;

  return {
    create: async (metadata) => {
      const storedMetadata = authHandoffMetadataSchema.parse({
        clientId: metadata.clientId,
        audience: metadata.audience,
        redirectUri: metadata.redirectUri,
        userId: metadata.userId,
        ...(metadata.provider ? { provider: metadata.provider } : {}),
        loginMethod: metadata.loginMethod,
        codeChallenge: metadata.codeChallenge,
        codeChallengeMethod: metadata.codeChallengeMethod,
        state: metadata.state,
        expiresAtEpochMs: now() + AUTH_HANDOFF_TTL_SECONDS * 1000
      });
      const serializedMetadata = JSON.stringify(storedMetadata);

      for (let attempt = 0; attempt < MAX_HANDOFF_GENERATION_ATTEMPTS; attempt += 1) {
        const code = randomBytes(AUTH_HANDOFF_CODE_BYTES).toString("base64url");
        const stored = await redis.setIfAbsent(
          keyForCode(code),
          serializedMetadata,
          AUTH_HANDOFF_TTL_SECONDS
        );
        if (stored) {
          return code;
        }
      }

      throw new AuthHandoffCreationError();
    },
    consume: async (input) => {
      if (!supportsValidatedConsume(redis)) {
        throw new AuthHandoffPersistenceError();
      }

      const key = keyForCode(input.code);
      const serializedMetadata = await redis.get(key);
      if (!serializedMetadata) {
        return null;
      }

      const metadata = parseStoredMetadata(serializedMetadata);
      if (!metadata || metadata.expiresAtEpochMs <= now()) {
        await redis.consumeIfValue(key, serializedMetadata);
        return null;
      }
      if (!matchesExchangeBinding(metadata, input)) {
        return null;
      }

      const consumedMetadata = await redis.consumeIfValue(key, serializedMetadata);
      return consumedMetadata ? metadata : null;
    }
  };
};

export const authHandoffStore = createAuthHandoffStore(redisTtlStoreClient);

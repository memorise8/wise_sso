import { randomBytes } from "node:crypto";
import { z } from "zod";
import type { Provider } from "./user.service.js";
import { redisTtlStoreClient } from "./redis.client.js";
import type { RedisTtlStoreClient } from "./redis.client.js";

const OAUTH_STATE_BYTES = 32;
const OAUTH_STATE_TTL_SECONDS = 10 * 60;
const OAUTH_STATE_KEY_PREFIX = "wiseacct:oauth-state:";
const MAX_STATE_GENERATION_ATTEMPTS = 3;

const oauthStateMetadataSchema = z.object({
  clientId: z.string().min(1),
  redirectUri: z.string().url(),
  callerState: z.string().min(1).nullable(),
  codeChallenge: z.string().min(1).nullable(),
  codeChallengeMethod: z.literal("S256").nullable()
}).strict();

const oauthStateRecordSchema = oauthStateMetadataSchema.extend({
  provider: z.enum(["google", "naver", "kakao"])
}).strict();

export type OAuthStateMetadata = z.infer<typeof oauthStateMetadataSchema>;

export type OAuthStateStore = {
  readonly create: (provider: Provider, metadata: OAuthStateMetadata) => Promise<string>;
  readonly consume: (provider: Provider, state: string) => Promise<OAuthStateMetadata | null>;
};

export class OAuthStateCreationError extends Error {
  public constructor() {
    super("Unable to generate a unique OAuth state");
    this.name = "OAuthStateCreationError";
  }
}

const keyForState = (state: string): string => `${OAUTH_STATE_KEY_PREFIX}${state}`;

const parseStoredState = (storedState: string): z.infer<typeof oauthStateRecordSchema> | null => {
  try {
    return oauthStateRecordSchema.safeParse(JSON.parse(storedState)).data ?? null;
  } catch (error) {
    if (error instanceof SyntaxError) {
      return null;
    }
    throw error;
  }
};

export const createOAuthStateStore = (redis: RedisTtlStoreClient): OAuthStateStore => ({
  create: async (provider, metadata) => {
    const serializedState = JSON.stringify({ provider, ...metadata });

    for (let attempt = 0; attempt < MAX_STATE_GENERATION_ATTEMPTS; attempt += 1) {
      const state = randomBytes(OAUTH_STATE_BYTES).toString("base64url");
      const stored = await redis.setIfAbsent(keyForState(state), serializedState, OAUTH_STATE_TTL_SECONDS);
      if (stored) {
        return state;
      }
    }

    throw new OAuthStateCreationError();
  },
  consume: async (provider, state) => {
    const storedState = await redis.consume(keyForState(state));
    if (!storedState) {
      return null;
    }

    const parsedState = parseStoredState(storedState);
    if (parsedState?.provider !== provider) {
      return null;
    }

    return {
      clientId: parsedState.clientId,
      redirectUri: parsedState.redirectUri,
      callerState: parsedState.callerState,
      codeChallenge: parsedState.codeChallenge,
      codeChallengeMethod: parsedState.codeChallengeMethod
    };
  }
});

export const oauthStateStore = createOAuthStateStore(redisTtlStoreClient);

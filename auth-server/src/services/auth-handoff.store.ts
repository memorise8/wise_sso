import { randomBytes } from "node:crypto";

const AUTH_HANDOFF_CODE_BYTES = 32;
const AUTH_HANDOFF_TTL_MS = 2 * 60 * 1000;

type TokenPair = {
  readonly accessToken: string;
  readonly refreshToken: string;
};

type StoredAuthHandoff = {
  readonly tokens: TokenPair;
  readonly expiresAtMs: number;
};

export type AuthHandoffStore = {
  readonly create: (tokens: TokenPair) => string;
  readonly consume: (code: string) => TokenPair | null;
  readonly clear: () => void;
};

const handoffs = new Map<string, StoredAuthHandoff>();

const pruneExpiredHandoffs = (nowMs: number): void => {
  for (const [code, handoff] of handoffs.entries()) {
    if (handoff.expiresAtMs <= nowMs) {
      handoffs.delete(code);
    }
  }
};

export const authHandoffStore: AuthHandoffStore = {
  create: (tokens) => {
    const nowMs = Date.now();
    pruneExpiredHandoffs(nowMs);
    const code = randomBytes(AUTH_HANDOFF_CODE_BYTES).toString("base64url");
    handoffs.set(code, {
      tokens,
      expiresAtMs: nowMs + AUTH_HANDOFF_TTL_MS
    });
    return code;
  },
  consume: (code) => {
    const handoff = handoffs.get(code);
    if (!handoff) {
      return null;
    }

    handoffs.delete(code);
    if (handoff.expiresAtMs <= Date.now()) {
      return null;
    }
    return handoff.tokens;
  },
  clear: () => {
    handoffs.clear();
  }
};

// TODO: Replace with Redis or DB before multi-instance production.
// In-memory handoff codes are process-local and are lost on restart.

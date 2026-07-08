import { randomBytes } from "node:crypto";
import type { Provider } from "./user.service.js";

const OAUTH_STATE_BYTES = 32;
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;

type StoredOAuthState = {
  readonly provider: Provider;
  readonly expiresAtMs: number;
};

export type OAuthStateStore = {
  readonly create: (provider: Provider) => string;
  readonly consume: (provider: Provider, state: string) => boolean;
  readonly clear: () => void;
};

const states = new Map<string, StoredOAuthState>();

const pruneExpiredStates = (nowMs: number): void => {
  for (const [state, storedState] of states.entries()) {
    if (storedState.expiresAtMs <= nowMs) {
      states.delete(state);
    }
  }
};

export const oauthStateStore: OAuthStateStore = {
  create: (provider) => {
    const nowMs = Date.now();
    pruneExpiredStates(nowMs);
    const state = randomBytes(OAUTH_STATE_BYTES).toString("base64url");
    states.set(state, {
      provider,
      expiresAtMs: nowMs + OAUTH_STATE_TTL_MS
    });
    return state;
  },
  consume: (provider, state) => {
    const storedState = states.get(state);
    if (!storedState) {
      return false;
    }

    states.delete(state);
    return storedState.provider === provider && storedState.expiresAtMs > Date.now();
  },
  clear: () => {
    states.clear();
  }
};

// TODO: Replace with a shared TTL store such as Redis before multi-instance production.
// This in-memory store is lost on process restart and cannot validate states created by another instance.

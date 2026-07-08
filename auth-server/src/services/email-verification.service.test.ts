import { describe, expect, it } from "vitest";
import type { MailService } from "./mail.service.js";
import { HttpError } from "../utils/httpError.js";
import {
  confirmEmailVerification,
  requestEmailVerification
} from "./email-verification.service.js";
import type {
  EmailVerificationStore,
  EmailVerificationTokenRecord,
  EmailVerificationUser
} from "./email-verification.service.js";

type StoredVerificationToken = EmailVerificationTokenRecord & {
  readonly tokenHash: string;
};

type SentVerificationMessage = {
  readonly kind: "email-verification";
  readonly to: string;
  readonly link: string;
};

type TestStore = EmailVerificationStore & {
  readonly users: ReadonlyMap<string, EmailVerificationUser>;
  readonly tokens: readonly StoredVerificationToken[];
};

const fixedNow = new Date("2026-07-08T00:00:00.000Z");

const createFakeVerificationMailService = (): MailService & {
  readonly messages: readonly SentVerificationMessage[];
} => {
  const messages: SentVerificationMessage[] = [];

  return {
    messages,
    sendEmailVerification: async (input) => {
      messages.push({
        kind: "email-verification",
        to: input.to,
        link: input.verificationUrl
      });
    },
    sendPasswordReset: async () => {}
  };
};

const createStore = (initialUsers: readonly EmailVerificationUser[] = []): TestStore => {
  const users = new Map<string, EmailVerificationUser>();
  const tokens: StoredVerificationToken[] = [];

  for (const user of initialUsers) {
    if (user.email) {
      users.set(user.email.toLowerCase(), user);
    }
  }

  return {
    users,
    tokens,
    findUserByEmail: async (email) => users.get(email.toLowerCase()) ?? null,
    createVerificationToken: async (input) => {
      tokens.push({
        id: `token-${tokens.length + 1}`,
        tokenHash: input.tokenHash,
        userId: input.userId,
        expiresAt: input.expiresAt,
        usedAt: null
      });
    },
    findVerificationTokenByHash: async (tokenHash) =>
      tokens.find((token) => token.tokenHash === tokenHash) ?? null,
    markTokenUsedAndActivateUser: async (input) => {
      const index = tokens.findIndex((token) =>
        token.id === input.tokenId && token.userId === input.userId && token.usedAt === null && token.expiresAt > input.usedAt
      );
      const token = tokens[index];
      if (!token) {
        return false;
      }

      tokens[index] = { ...token, usedAt: input.usedAt };
      for (const [email, user] of users) {
        if (user.id === input.userId) {
          users.set(email, { ...user, status: "active" });
        }
      }

      return true;
    }
  };
};

describe("email verification service", () => {
  it("Given a known email When verification is requested Then only a token hash is stored and a verification email is sent", async () => {
    const store = createStore([{ id: "user-1", email: "user@example.com", status: "pending" }]);
    const mailer = createFakeVerificationMailService();

    const result = await requestEmailVerification({
      store,
      mailer,
      input: { email: "User@Example.com" },
      verificationUrlBase: "https://app.example.com/verify-email",
      now: () => fixedNow
    });

    expect(result).toEqual({ status: "accepted" });
    expect(store.tokens).toHaveLength(1);
    expect(store.tokens[0]?.userId).toBe("user-1");
    expect(store.tokens[0]?.expiresAt).toEqual(new Date("2026-07-09T00:00:00.000Z"));
    expect(mailer.messages).toHaveLength(1);
    const link = mailer.messages[0]?.link;
    expect(link).toContain("https://app.example.com/verify-email?token=");
    const token = link ? new URL(link).searchParams.get("token") : null;
    expect(token).toBeTruthy();
    expect(store.tokens[0]?.tokenHash).not.toBe(token);
  });

  it("Given an unknown email When verification is requested Then the response is generic and no email is sent", async () => {
    const store = createStore();
    const mailer = createFakeVerificationMailService();

    const result = await requestEmailVerification({
      store,
      mailer,
      input: { email: "unknown@example.com" },
      verificationUrlBase: "https://app.example.com/verify-email",
      now: () => fixedNow
    });

    expect(result).toEqual({ status: "accepted" });
    expect(store.tokens).toEqual([]);
    expect(mailer.messages).toEqual([]);
  });

  it("Given a fresh token When verification is confirmed Then the token is used and the user becomes active", async () => {
    const store = createStore([{ id: "user-1", email: "user@example.com", status: "pending" }]);
    const mailer = createFakeVerificationMailService();
    await requestEmailVerification({
      store,
      mailer,
      input: { email: "user@example.com" },
      verificationUrlBase: "https://app.example.com/verify-email",
      now: () => fixedNow
    });
    const link = mailer.messages[0]?.link;
    const token = link ? new URL(link).searchParams.get("token") : null;

    const result = await confirmEmailVerification({
      store,
      input: { token: token ?? "" },
      now: () => fixedNow
    });

    expect(result).toEqual({ status: "verified", userId: "user-1" });
    expect(store.tokens[0]?.usedAt).toEqual(fixedNow);
    expect(store.users.get("user@example.com")?.status).toBe("active");
  });

  it("Given an expired token When verification is confirmed Then confirmation is rejected", async () => {
    const store = createStore([{ id: "user-1", email: "user@example.com", status: "pending" }]);
    const mailer = createFakeVerificationMailService();
    await requestEmailVerification({
      store,
      mailer,
      input: { email: "user@example.com" },
      verificationUrlBase: "https://app.example.com/verify-email",
      now: () => fixedNow
    });
    const link = mailer.messages[0]?.link;
    const token = link ? new URL(link).searchParams.get("token") : null;

    await expect(confirmEmailVerification({
      store,
      input: { token: token ?? "" },
      now: () => new Date("2026-07-10T00:00:00.000Z")
    })).rejects.toMatchObject(new HttpError(400, "INVALID_VERIFICATION_TOKEN", "Invalid or expired verification token"));
  });

  it("Given a used token When verification is confirmed again Then confirmation is rejected", async () => {
    const store = createStore([{ id: "user-1", email: "user@example.com", status: "pending" }]);
    const mailer = createFakeVerificationMailService();
    await requestEmailVerification({
      store,
      mailer,
      input: { email: "user@example.com" },
      verificationUrlBase: "https://app.example.com/verify-email",
      now: () => fixedNow
    });
    const link = mailer.messages[0]?.link;
    const token = link ? new URL(link).searchParams.get("token") : "";
    await confirmEmailVerification({
      store,
      input: { token },
      now: () => fixedNow
    });

    await expect(confirmEmailVerification({
      store,
      input: { token },
      now: () => fixedNow
    })).rejects.toMatchObject(new HttpError(400, "INVALID_VERIFICATION_TOKEN", "Invalid or expired verification token"));
  });

  it("Given two concurrent confirmations for the same token When both attempt verification Then only one succeeds", async () => {
    const store = createStore([{ id: "user-1", email: "user@example.com", status: "pending" }]);
    const mailer = createFakeVerificationMailService();
    await requestEmailVerification({
      store,
      mailer,
      input: { email: "user@example.com" },
      verificationUrlBase: "https://app.example.com/verify-email",
      now: () => fixedNow
    });
    const token = new URL(mailer.messages[0]?.link ?? "").searchParams.get("token") ?? "";

    const results = await Promise.allSettled([
      confirmEmailVerification({
        store,
        input: { token },
        now: () => fixedNow
      }),
      confirmEmailVerification({
        store,
        input: { token },
        now: () => fixedNow
      })
    ]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(store.tokens[0]?.usedAt).toEqual(fixedNow);
    expect(store.users.get("user@example.com")?.status).toBe("active");
  });
});

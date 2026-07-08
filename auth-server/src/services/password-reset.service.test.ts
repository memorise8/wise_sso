import argon2 from "argon2";
import { describe, expect, it } from "vitest";
import type { MailService } from "./mail.service.js";
import {
  confirmPasswordReset,
  requestPasswordReset,
  type PasswordResetStore
} from "./password-reset.service.js";
import { HttpError } from "../utils/httpError.js";

type ResetUser = {
  readonly id: string;
  readonly email: string;
  readonly passwordHash: string;
};

type SentResetMessage = {
  readonly kind: "password-reset";
  readonly to: string;
  readonly link: string;
};

const createFakeResetMailService = (): MailService & { readonly messages: readonly SentResetMessage[] } => {
  const messages: SentResetMessage[] = [];

  return {
    messages,
    sendEmailVerification: async () => {},
    sendPasswordReset: async (input) => {
      messages.push({
        kind: "password-reset",
        to: input.to,
        link: input.resetUrl
      });
    }
  };
};

type ResetTokenRecord = {
  readonly tokenHash: string;
  readonly userId: string;
  readonly expiresAt: Date;
  readonly usedAt: Date | null;
};

type RefreshTokenRecord = {
  readonly userId: string;
  readonly revokedAt: Date | null;
};

type StoreState = {
  readonly usersByEmail: Map<string, ResetUser>;
  readonly resetTokens: ResetTokenRecord[];
  readonly refreshTokens: RefreshTokenRecord[];
};

const createStore = (initialUsers: readonly ResetUser[] = []): PasswordResetStore & { readonly state: StoreState } => {
  const state: StoreState = {
    usersByEmail: new Map(initialUsers.map((user) => [user.email, user])),
    resetTokens: [],
    refreshTokens: []
  };

  return {
    state,
    findUserByEmail: async (email) => state.usersByEmail.get(email) ?? null,
    createResetToken: async (input) => {
      state.resetTokens.push({
        tokenHash: input.tokenHash,
        userId: input.userId,
        expiresAt: input.expiresAt,
        usedAt: null
      });
    },
    resetPasswordWithToken: async (input) => {
      const token = state.resetTokens.find((candidate) =>
        candidate.tokenHash === input.tokenHash && candidate.usedAt === null && candidate.expiresAt > input.now
      );
      if (!token) {
        return null;
      }

      const user = Array.from(state.usersByEmail.values()).find((candidate) => candidate.id === token.userId);
      if (!user) {
        return null;
      }

      state.resetTokens.splice(state.resetTokens.indexOf(token), 1, {
        ...token,
        usedAt: input.now
      });
      state.usersByEmail.set(user.email, {
        ...user,
        passwordHash: input.passwordHash
      });

      for (const [index, refreshToken] of state.refreshTokens.entries()) {
        if (refreshToken.userId === user.id && refreshToken.revokedAt === null) {
          state.refreshTokens.splice(index, 1, { ...refreshToken, revokedAt: input.now });
        }
      }

      return { userId: user.id };
    }
  };
};

const createUser = async (): Promise<ResetUser> => ({
  id: "user-1",
  email: "user@company.com",
  passwordHash: await argon2.hash("old-password-123", {
    type: argon2.argon2id,
    memoryCost: 19_456,
    timeCost: 2,
    parallelism: 1
  })
});

describe("password reset", () => {
  it("Given existing and unknown emails When reset is requested Then both receive the same generic response without exposing raw token storage", async () => {
    const user = await createUser();
    const store = createStore([user]);
    const mailer = createFakeResetMailService();

    const existing = await requestPasswordReset(store, mailer, {
      email: "User@Company.com",
      resetUrlBase: "https://app.example.com/reset-password"
    });
    const unknown = await requestPasswordReset(store, mailer, {
      email: "unknown@company.com",
      resetUrlBase: "https://app.example.com/reset-password"
    });

    expect(existing).toEqual({ status: "accepted" });
    expect(unknown).toEqual({ status: "accepted" });
    expect(store.state.resetTokens).toHaveLength(1);
    expect(store.state.resetTokens[0]?.tokenHash).toHaveLength(64);
    expect(mailer.messages).toHaveLength(1);
    expect(mailer.messages[0]).toMatchObject({
      kind: "password-reset",
      to: "user@company.com"
    });
    expect(mailer.messages[0]?.link).toContain("https://app.example.com/reset-password?token=");
    expect(mailer.messages[0]?.link).not.toContain(store.state.resetTokens[0]?.tokenHash ?? "");
  });

  it("Given a valid reset token When password reset is confirmed Then password hash changes and refresh tokens are revoked", async () => {
    const user = await createUser();
    const store = createStore([user]);
    const mailer = createFakeResetMailService();
    store.state.refreshTokens.push(
      { userId: user.id, revokedAt: null },
      { userId: user.id, revokedAt: null },
      { userId: "other-user", revokedAt: null }
    );
    await requestPasswordReset(store, mailer, {
      email: user.email,
      resetUrlBase: "https://app.example.com/reset-password"
    });
    const resetLink = mailer.messages[0]?.link ?? "";
    const token = new URL(resetLink).searchParams.get("token") ?? "";

    const result = await confirmPasswordReset(store, {
      token,
      password: "new-password-123"
    });

    expect(result).toEqual({ userId: user.id });
    const updatedUser = store.state.usersByEmail.get(user.email);
    expect(updatedUser).toBeDefined();
    expect(await argon2.verify(updatedUser?.passwordHash ?? "", "new-password-123")).toBe(true);
    expect(await argon2.verify(updatedUser?.passwordHash ?? "", "old-password-123")).toBe(false);
    expect(store.state.refreshTokens.filter((refreshToken) => refreshToken.userId === user.id && refreshToken.revokedAt !== null)).toHaveLength(2);
    expect(store.state.refreshTokens.find((refreshToken) => refreshToken.userId === "other-user")?.revokedAt).toBeNull();
  });

  it("Given an expired reset token When password reset is confirmed Then it is rejected", async () => {
    const user = await createUser();
    const store = createStore([user]);
    const mailer = createFakeResetMailService();
    await requestPasswordReset(store, mailer, {
      email: user.email,
      resetUrlBase: "https://app.example.com/reset-password",
      now: new Date("2026-07-08T00:00:00.000Z")
    });
    const token = new URL(mailer.messages[0]?.link ?? "").searchParams.get("token") ?? "";

    await expect(confirmPasswordReset(store, {
      token,
      password: "new-password-123",
      now: new Date("2026-07-08T02:00:00.000Z")
    })).rejects.toMatchObject(new HttpError(400, "INVALID_RESET_TOKEN", "Invalid or expired reset token"));
  });

  it("Given a used reset token When password reset is confirmed again Then it is rejected", async () => {
    const user = await createUser();
    const store = createStore([user]);
    const mailer = createFakeResetMailService();
    await requestPasswordReset(store, mailer, {
      email: user.email,
      resetUrlBase: "https://app.example.com/reset-password"
    });
    const token = new URL(mailer.messages[0]?.link ?? "").searchParams.get("token") ?? "";

    await confirmPasswordReset(store, {
      token,
      password: "new-password-123"
    });

    await expect(confirmPasswordReset(store, {
      token,
      password: "newer-password-123"
    })).rejects.toMatchObject(new HttpError(400, "INVALID_RESET_TOKEN", "Invalid or expired reset token"));
  });

  it("Given two concurrent confirmations for the same reset token When both attempt reset Then only one succeeds", async () => {
    const user = await createUser();
    const store = createStore([user]);
    const mailer = createFakeResetMailService();
    await requestPasswordReset(store, mailer, {
      email: user.email,
      resetUrlBase: "https://app.example.com/reset-password"
    });
    const token = new URL(mailer.messages[0]?.link ?? "").searchParams.get("token") ?? "";

    const results = await Promise.allSettled([
      confirmPasswordReset(store, {
        token,
        password: "new-password-123"
      }),
      confirmPasswordReset(store, {
        token,
        password: "newer-password-123"
      })
    ]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(store.state.resetTokens[0]?.usedAt).not.toBeNull();
  });
});

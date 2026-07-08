import { describe, expect, it } from "vitest";
import { HttpError } from "../utils/httpError.js";
import { isPasswordAuthFailure, loginWithPassword, registerWithPassword } from "./password-auth.service.js";
import type { PasswordAuthStore } from "./password-auth.service.js";

type TestPasswordAuthStore = PasswordAuthStore & {
  readonly activateUser: (userId: string) => Promise<void>;
};

const createStore = (): TestPasswordAuthStore => {
  const users = new Map<string, { readonly id: string; readonly email: string; readonly name: string | null; readonly status: string }>();
  const credentials = new Map<string, {
    readonly userId: string;
    readonly passwordHash: string;
    readonly failedLoginCount: number;
    readonly lockedUntil: Date | null;
    readonly userStatus: string;
  }>();

  return {
    findUserByEmail: async (email) => users.get(email.toLowerCase()) ?? null,
    createUserWithPassword: async (input) => {
      const id = `user-${users.size + 1}`;
      users.set(input.email.toLowerCase(), { id, email: input.email, name: input.name, status: input.status });
      credentials.set(input.email.toLowerCase(), {
        userId: id,
        passwordHash: input.passwordHash,
        failedLoginCount: 0,
        lockedUntil: null,
        userStatus: input.status
      });
      return { id, email: input.email, name: input.name, roles: [] };
    },
    findCredentialByEmail: async (email) => {
      const credential = credentials.get(email.toLowerCase());
      return credential ? { ...credential, email } : null;
    },
    markLoginSuccess: async (userId) => {
      for (const [email, credential] of credentials) {
        if (credential.userId === userId) {
          credentials.set(email, { ...credential, failedLoginCount: 0, lockedUntil: null });
        }
      }
    },
    markLoginFailure: async (userId) => {
      for (const [email, credential] of credentials) {
        if (credential.userId === userId) {
          credentials.set(email, { ...credential, failedLoginCount: credential.failedLoginCount + 1, lockedUntil: null });
        }
      }
    },
    getCurrentUser: async (userId) => {
      const user = Array.from(users.values()).find((candidate) => candidate.id === userId);
      return user ? { id: user.id, email: user.email, name: user.name, roles: [] } : null;
    },
    activateUser: async (userId) => {
      for (const [email, user] of users) {
        if (user.id === userId) {
          users.set(email, { ...user, status: "active" });
        }
      }
      for (const [email, credential] of credentials) {
        if (credential.userId === userId) {
          credentials.set(email, { ...credential, userStatus: "active" });
        }
      }
    }
  };
};

describe("password auth", () => {
  it("Given a new company user When registering Then the user is pending verification and cannot login", async () => {
    const store = createStore();

    const registered = await registerWithPassword(store, {
      email: "User@Company.com",
      password: "correct-password-123",
      name: "Company User"
    });

    const credential = await store.findCredentialByEmail("user@company.com");
    expect(credential?.userStatus).toBe("pending_verification");
    await expect(loginWithPassword(store, {
      email: "user@company.com",
      password: "correct-password-123"
    })).rejects.toMatchObject(new HttpError(401, "INVALID_CREDENTIALS", "Invalid email or password"));
    await expect(loginWithPassword(store, {
      email: "user@company.com",
      password: "correct-password-123"
    })).rejects.toMatchObject({
      audit: {
        userId: registered.user.id,
        reasonCode: "USER_INACTIVE"
      }
    });
    expect((await store.findCredentialByEmail("user@company.com"))?.failedLoginCount).toBe(0);
  });

  it("Given a verified company user When logging in Then the same auth user is returned", async () => {
    const store = createStore();

    const registered = await registerWithPassword(store, {
      email: "User@Company.com",
      password: "correct-password-123",
      name: "Company User"
    });
    await store.activateUser(registered.user.id);
    const loggedIn = await loginWithPassword(store, {
      email: "user@company.com",
      password: "correct-password-123"
    });

    expect(loggedIn.user.id).toBe(registered.user.id);
    expect(loggedIn.user.email).toBe("user@company.com");
  });

  it("Given a valid company user When the password is wrong Then login is rejected", async () => {
    const store = createStore();
    const registered = await registerWithPassword(store, {
      email: "user@company.com",
      password: "correct-password-123",
      name: null
    });
    await store.activateUser(registered.user.id);

    await expect(loginWithPassword(store, {
      email: "user@company.com",
      password: "wrong-password-123"
    })).rejects.toMatchObject(new HttpError(401, "INVALID_CREDENTIALS", "Invalid email or password"));
  });

  it("Given an unknown company email When logging in Then login is rejected with generic credentials error", async () => {
    const store = createStore();

    await expect(loginWithPassword(store, {
      email: "unknown@company.com",
      password: "wrong-password-123"
    })).rejects.toMatchObject(new HttpError(401, "INVALID_CREDENTIALS", "Invalid email or password"));
  });

  it("Given an existing company email When registering again Then the existing auth user is returned without creating a duplicate", async () => {
    const store = createStore();
    const first = await registerWithPassword(store, {
      email: "user@company.com",
      password: "correct-password-123",
      name: "First"
    });

    const second = await registerWithPassword(store, {
      email: "USER@company.com",
      password: "another-password-123",
      name: "Second"
    });

    expect(second.user.id).toBe(first.user.id);
    expect(second.user.name).toBe("First");
  });

  it("Given a locked company credential When logging in Then the public error is generic and audit context carries the user id", async () => {
    const users = new Map([[
      "user@company.com",
      { id: "user-1", email: "user@company.com", name: null, status: "active" }
    ]]);
    const store: PasswordAuthStore = {
      findUserByEmail: async (email) => users.get(email.toLowerCase()) ?? null,
      createUserWithPassword: async () => {
        throw new Error("not used");
      },
      findCredentialByEmail: async (email) => ({
        userId: "user-1",
        email,
        passwordHash: "$argon2id$v=19$m=19456,t=2,p=1$SdlW23hIuyR5YOcdnZi8wg$U6czHfbJGnRhZehGLUmnc9E06qyzWWjlouMxjSv3gTM",
        failedLoginCount: 5,
        lockedUntil: new Date(Date.now() + 60_000),
        userStatus: "active"
      }),
      markLoginSuccess: async () => undefined,
      markLoginFailure: async () => undefined,
      getCurrentUser: async () => null
    };

    try {
      await loginWithPassword(store, {
        email: "user@company.com",
        password: "correct-password-123"
      });
      throw new Error("expected login to fail");
    } catch (error) {
      expect(error).toMatchObject(new HttpError(401, "INVALID_CREDENTIALS", "Invalid email or password"));
      expect(isPasswordAuthFailure(error)).toBe(true);
      if (isPasswordAuthFailure(error)) {
        expect(error.audit).toEqual({
          userId: "user-1",
          reasonCode: "ACCOUNT_LOCKED"
        });
      }
    }
  });
});

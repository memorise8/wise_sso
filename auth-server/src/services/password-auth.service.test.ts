import { describe, expect, it } from "vitest";
import { HttpError } from "../utils/httpError.js";
import { isPasswordAuthFailure, loginWithPassword, registerWithPassword } from "./password-auth.service.js";
import type { PasswordAuthStore } from "./password-auth.service.js";
import { userStatuses } from "./user-status.service.js";
import type { UserStatusValue } from "./user-status.service.js";

type TestPasswordAuthStore = PasswordAuthStore & {
  readonly activateUser: (userId: string) => Promise<void>;
  readonly setUserStatus: (userId: string, status: UserStatusValue) => Promise<void>;
  readonly seedVerifiedOAuthUser: (input: { readonly email: string; readonly id: string }) => Promise<void>;
  readonly hasPendingPasswordCredential: (email: string) => Promise<boolean>;
};

const createStore = (): TestPasswordAuthStore => {
  const users = new Map<string, {
    readonly id: string;
    readonly email: string;
    readonly emailVerified: boolean;
    readonly name: string | null;
    readonly status: UserStatusValue;
  }>();
  const credentials = new Map<string, {
    readonly userId: string;
    readonly passwordHash: string;
    readonly failedLoginCount: number;
    readonly lockedUntil: Date | null;
    readonly userStatus: UserStatusValue;
  }>();
  const pendingCredentials = new Map<string, {
    readonly userId: string;
    readonly passwordHash: string;
    readonly expiresAt: Date;
  }>();
  const setUserStatus = async (userId: string, status: UserStatusValue): Promise<void> => {
    for (const [email, user] of users) {
      if (user.id === userId) {
        users.set(email, { ...user, status, emailVerified: status === userStatuses.active ? true : user.emailVerified });
      }
    }
    for (const [email, credential] of credentials) {
      if (credential.userId === userId) {
        credentials.set(email, { ...credential, userStatus: status });
      }
    }
  };

  return {
    findUserByEmail: async (email) => {
      const user = users.get(email.toLowerCase());
      return user ? { id: user.id, email: user.email, emailVerified: user.emailVerified, name: user.name, roles: [] } : null;
    },
    createUserWithPassword: async (input) => {
      const id = `user-${users.size + 1}`;
      users.set(input.email.toLowerCase(), {
        id,
        email: input.email,
        emailVerified: input.status === userStatuses.active,
        name: input.name,
        status: input.status
      });
      credentials.set(input.email.toLowerCase(), {
        userId: id,
        passwordHash: input.passwordHash,
        failedLoginCount: 0,
        lockedUntil: null,
        userStatus: input.status
      });
      return { id, email: input.email, emailVerified: input.status === userStatuses.active, name: input.name, roles: [] };
    },
    createPendingPasswordCredential: async (input) => {
      pendingCredentials.set(input.email.toLowerCase(), {
        userId: input.userId,
        passwordHash: input.passwordHash,
        expiresAt: input.expiresAt
      });
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
      return user ? { id: user.id, email: user.email, emailVerified: user.emailVerified, name: user.name, roles: [] } : null;
    },
    activateUser: async (userId) => {
      await setUserStatus(userId, userStatuses.active);
    },
    setUserStatus,
    seedVerifiedOAuthUser: async (input) => {
      users.set(input.email.toLowerCase(), {
        id: input.id,
        email: input.email.toLowerCase(),
        emailVerified: true,
        name: null,
        status: userStatuses.active
      });
    },
    hasPendingPasswordCredential: async (email) => pendingCredentials.has(email.toLowerCase())
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
    expect(credential?.userStatus).toBe(userStatuses.pendingEmailVerification);
    await expect(loginWithPassword(store, {
      email: "user@company.com",
      password: "correct-password-123"
    })).rejects.toMatchObject(new HttpError(403, "EMAIL_VERIFICATION_REQUIRED", "Email verification is required before login"));
    await expect(loginWithPassword(store, {
      email: "user@company.com",
      password: "correct-password-123"
    })).rejects.toMatchObject({
      audit: {
        userId: registered.user.id,
        reasonCode: "EMAIL_VERIFICATION_REQUIRED"
      }
    });
    expect((await store.findCredentialByEmail("user@company.com"))?.failedLoginCount).toBe(0);
  });

  it.each([
    userStatuses.suspended,
    userStatuses.deleted
  ])("Given a %s company user When logging in Then the public error is generic and inactive audit context is kept", async (status) => {
    const store = createStore();
    const registered = await registerWithPassword(store, {
      email: "user@company.com",
      password: "correct-password-123",
      name: "Company User"
    });
    await store.setUserStatus(registered.user.id, status);

    await expect(loginWithPassword(store, {
      email: "user@company.com",
      password: "correct-password-123"
    })).rejects.toMatchObject(new HttpError(401, "INVALID_CREDENTIALS", "Invalid email or password"));
    try {
      await loginWithPassword(store, {
        email: "user@company.com",
        password: "correct-password-123"
      });
      throw new Error("expected login to fail");
    } catch (error) {
      if (!isPasswordAuthFailure(error)) {
        throw error;
      }
      expect(error.audit).toEqual({
        userId: registered.user.id,
        reasonCode: "USER_INACTIVE"
      });
    }
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

  it("Given an eight character password When registering Then the password policy accepts it", async () => {
    const store = createStore();

    const registered = await registerWithPassword(store, {
      email: "short@example.com",
      password: "abcd1234",
      name: "Short Password"
    });

    expect(registered.user.email).toBe("short@example.com");
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

  it("Given a verified OAuth user without password When registering with the same email Then a pending password link is created for the same subject", async () => {
    const store = createStore();
    await store.seedVerifiedOAuthUser({ id: "google-user-1", email: "oauth@example.com" });

    const registered = await registerWithPassword(store, {
      email: "OAuth@Example.com",
      password: "correct-password-123",
      name: "Ignored Name"
    });

    expect(registered.user.id).toBe("google-user-1");
    expect(await store.hasPendingPasswordCredential("oauth@example.com")).toBe(true);
    await expect(loginWithPassword(store, {
      email: "oauth@example.com",
      password: "correct-password-123"
    })).rejects.toMatchObject(new HttpError(401, "INVALID_CREDENTIALS", "Invalid email or password"));
  });

  it("Given a locked company credential When logging in Then the public error is generic and audit context carries the user id", async () => {
    const users = new Map([[
      "user@company.com",
      { id: "user-1", email: "user@company.com", name: null, status: userStatuses.active }
    ]]);
    const store: PasswordAuthStore = {
      findUserByEmail: async (email) => users.get(email.toLowerCase()) ?? null,
      createUserWithPassword: async () => {
        throw new Error("not used");
      },
      createPendingPasswordCredential: async () => undefined,
      findCredentialByEmail: async (email) => ({
        userId: "user-1",
        email,
        passwordHash: "$argon2id$v=19$m=19456,t=2,p=1$SdlW23hIuyR5YOcdnZi8wg$U6czHfbJGnRhZehGLUmnc9E06qyzWWjlouMxjSv3gTM",
        failedLoginCount: 5,
        lockedUntil: new Date(Date.now() + 60_000),
        userStatus: userStatuses.active
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
      if (!isPasswordAuthFailure(error)) {
        throw error;
      }
      expect(error).toMatchObject(new HttpError(401, "INVALID_CREDENTIALS", "Invalid email or password"));
      expect(error.audit).toEqual({
        userId: "user-1",
        reasonCode: "ACCOUNT_LOCKED"
      });
    }
  });
});

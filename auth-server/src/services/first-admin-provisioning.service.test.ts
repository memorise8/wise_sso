import { describe, expect, it } from "vitest";
import { HttpError } from "../utils/httpError.js";
import { grantFirstAdmin } from "./first-admin-provisioning.service.js";
import type {
  AdminAuditRecord,
  AdminUserMutationStore,
  AuthControlTransactionStore,
  RoleRecord
} from "./admin-user.service.js";
import type { UserStatusValue } from "./user-status.service.js";

type UserRecord = {
  readonly id: string;
  readonly email: string;
  readonly status: UserStatusValue;
};

type RefreshTokenRecord = {
  readonly userId: string;
  readonly revokedAt: Date | null;
};

type StoreState = {
  readonly users: Map<string, UserRecord>;
  readonly refreshTokens: RefreshTokenRecord[];
  readonly roles: Map<string, RoleRecord>;
  readonly userRoles: Set<string>;
  readonly auditLogs: AdminAuditRecord[];
};

const roleKey = (serviceKey: string, name: string): string => `${serviceKey}:${name}`;
const userRoleKey = (userId: string, roleId: string): string => `${userId}:${roleId}`;

const cloneState = (state: StoreState): StoreState => ({
  users: new Map(state.users),
  refreshTokens: state.refreshTokens.map((refreshToken) => ({ ...refreshToken })),
  roles: new Map(state.roles),
  userRoles: new Set(state.userRoles),
  auditLogs: state.auditLogs.map((auditLog) => ({ ...auditLog }))
});

const replaceState = (target: StoreState, source: StoreState): void => {
  target.users.clear();
  for (const [key, value] of source.users) {
    target.users.set(key, value);
  }
  target.refreshTokens.splice(0, target.refreshTokens.length, ...source.refreshTokens);
  target.roles.clear();
  for (const [key, value] of source.roles) {
    target.roles.set(key, value);
  }
  target.userRoles.clear();
  for (const value of source.userRoles) {
    target.userRoles.add(value);
  }
  target.auditLogs.splice(0, target.auditLogs.length, ...source.auditLogs);
};

const createStore = (state: StoreState): AuthControlTransactionStore => ({
  findActiveUserByEmail: async (email) => {
    for (const user of state.users.values()) {
      if (user.email === email && user.status === "ACTIVE") {
        return { id: user.id };
      }
    }
    return null;
  },
  updateUserStatus: async () => false,
  revokeAllRefreshTokensForUser: async (input) => {
    let revokedCount = 0;
    for (const [index, refreshToken] of state.refreshTokens.entries()) {
      if (refreshToken.userId === input.userId && refreshToken.revokedAt === null) {
        state.refreshTokens.splice(index, 1, { ...refreshToken, revokedAt: input.revokedAt });
        revokedCount += 1;
      }
    }
    return revokedCount;
  },
  upsertRole: async (input) => {
    const key = roleKey(input.serviceKey, input.name);
    const role = state.roles.get(key) ?? {
      id: `role-${state.roles.size + 1}`,
      serviceKey: input.serviceKey,
      name: input.name
    };
    state.roles.set(key, role);
    return role;
  },
  findRole: async (input) => state.roles.get(roleKey(input.serviceKey, input.name)) ?? null,
  assignRoleToUser: async (input) => {
    const key = userRoleKey(input.userId, input.roleId);
    const assigned = !state.userRoles.has(key);
    state.userRoles.add(key);
    return assigned;
  },
  removeRoleFromUser: async (input) => state.userRoles.delete(userRoleKey(input.userId, input.roleId)),
  createAdminAuditLog: async (input) => {
    state.auditLogs.push(input);
  }
});

const createMutationStore = (state: StoreState): AdminUserMutationStore & { readonly state: StoreState } => ({
  state,
  runInTransaction: async (work) => {
    const transactionState = cloneState(state);
    const result = await work(createStore(transactionState));
    replaceState(state, transactionState);
    return result;
  }
});

const createState = (): StoreState => ({
  users: new Map([
    ["target-user", { id: "target-user", email: "target@example.test", status: "ACTIVE" }],
    ["pending-user", { id: "pending-user", email: "pending@example.test", status: "PENDING_EMAIL_VERIFICATION" }]
  ]),
  refreshTokens: [
    { userId: "target-user", revokedAt: null },
    { userId: "target-user", revokedAt: null },
    { userId: "other-user", revokedAt: null }
  ],
  roles: new Map(),
  userRoles: new Set(),
  auditLogs: []
});

describe("first admin provisioning service", () => {
  it("Given an active existing user by email When ops grants the first admin Then admin role audit and refresh-token revocation are committed", async () => {
    const now = new Date("2026-07-22T03:00:00.000Z");
    const store = createMutationStore(createState());

    const result = await grantFirstAdmin(store, {
      email: " TARGET@example.test ",
      now
    });

    expect(result).toEqual({
      userId: "target-user",
      roleAssigned: true,
      revokedRefreshTokenCount: 2
    });
    expect(store.state.userRoles).toEqual(new Set(["target-user:role-1"]));
    expect(store.state.refreshTokens.filter((refreshToken) => refreshToken.userId === "target-user" && refreshToken.revokedAt === now)).toHaveLength(2);
    expect(store.state.auditLogs).toEqual([{
      actorUserId: null,
      targetUserId: "target-user",
      eventType: "admin_user_role_assigned",
      outcome: "success",
      reasonCode: "OPS_BOOTSTRAP_ADMIN",
      detailsJson: {
        serviceKey: "temis",
        roleName: "admin"
      }
    }]);
  });

  it.each([
    ["unknown@example.test"],
    ["pending@example.test"]
  ])("Given no active user for %s When ops grants first admin Then it fails generically without mutation", async (email) => {
    const store = createMutationStore(createState());

    await expect(grantFirstAdmin(store, { email }))
      .rejects.toMatchObject(new HttpError(404, "USER_NOT_FOUND", "No active user found"));
    expect(store.state.roles).toHaveLength(0);
    expect(store.state.userRoles).toHaveLength(0);
    expect(store.state.refreshTokens.filter((refreshToken) => refreshToken.revokedAt !== null)).toHaveLength(0);
    expect(store.state.auditLogs).toHaveLength(0);
  });
});

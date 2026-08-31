import { HttpError } from "../utils/httpError.js";
import type {
  AdminAuditRecord,
  AdminUserMutationStore,
  AuthControlTransactionStore,
  RoleRecord,
  UserStatusValue
} from "./admin-user.service.js";

type UserRecord = {
  readonly id: string;
  readonly email: string;
  readonly status: UserStatusValue;
};

type RefreshTokenRecord = {
  readonly userId: string;
  readonly revokedAt: Date | null;
};

export type StoreState = {
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

const createStore = (state: StoreState, failAudit = false): AuthControlTransactionStore => ({
  findActiveUserByEmail: async (email) => {
    for (const user of state.users.values()) {
      if (user.email === email && user.status === "ACTIVE") {
        return { id: user.id };
      }
    }
    return null;
  },
  updateUserStatus: async (input) => {
    const user = state.users.get(input.userId);
    if (!user) {
      return false;
    }

    state.users.set(input.userId, {
      ...user,
      status: input.status
    });
    return true;
  },
  revokeAllRefreshTokensForUser: async (input) => {
    let revokedCount = 0;
    for (const [index, refreshToken] of state.refreshTokens.entries()) {
      if (refreshToken.userId === input.userId && refreshToken.revokedAt === null) {
        state.refreshTokens.splice(index, 1, {
          ...refreshToken,
          revokedAt: input.revokedAt
        });
        revokedCount += 1;
      }
    }
    return revokedCount;
  },
  upsertRole: async (input) => {
    const key = roleKey(input.serviceKey, input.name);
    const existingRole = state.roles.get(key);
    if (existingRole) {
      return existingRole;
    }

    const role = {
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
    if (state.userRoles.has(key)) {
      return false;
    }

    state.userRoles.add(key);
    return true;
  },
  removeRoleFromUser: async (input) => state.userRoles.delete(userRoleKey(input.userId, input.roleId)),
  createAdminAuditLog: async (input) => {
    if (failAudit) {
      throw new HttpError(503, "AUDIT_WRITE_FAILED", "Audit write failed");
    }

    state.auditLogs.push(input);
  }
});

export const createMutationStore = (
  state: StoreState,
  options: { readonly failAudit?: boolean } = {}
): AdminUserMutationStore & { readonly state: StoreState } => ({
  state,
  runInTransaction: async (work) => {
    const transactionState = cloneState(state);
    const result = await work(createStore(transactionState, options.failAudit ?? false));
    replaceState(state, transactionState);
    return result;
  }
});

export const createState = (): StoreState => ({
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

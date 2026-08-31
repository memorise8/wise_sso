import { generateKeyPairSync } from "node:crypto";
import type { Express } from "express";
import { vi } from "vitest";
import type {
  AdminAuditRecord,
  AdminUserMutationStore,
  AuthControlTransactionStore,
  RoleRecord
} from "../services/auth-control.store.js";
import type { AuditLogQueryStore, AuditLogStore, AuthAuditEvent } from "../services/audit.service.js";
import type { UserStatusValue } from "../services/user-status.service.js";

const accessKeyId = "temis-access-key-1";

const createAccessKeyEnv = (): void => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048, publicExponent: 0x10001 });
  const publicJwk = publicKey.export({ format: "jwk" });
  if (publicJwk.kty !== "RSA" || typeof publicJwk.n !== "string" || typeof publicJwk.e !== "string") {
    throw new Error("Generated RSA key did not export a public JWK");
  }

  process.env["JWT_ACCESS_ALGORITHM"] = "RS256";
  process.env["JWT_ACCESS_PRIVATE_KEY"] = privateKey.export({ format: "pem", type: "pkcs8" }).toString().replace(/\n/g, "\\n");
  process.env["JWT_ACCESS_PUBLIC_JWK"] = JSON.stringify({ kty: "RSA", n: publicJwk.n, e: publicJwk.e, alg: "RS256", use: "sig", kid: accessKeyId });
  process.env["JWT_ACCESS_KEY_ID"] = accessKeyId;
};

createAccessKeyEnv();
process.env["NODE_ENV"] = "test";
process.env["DATABASE_URL"] = "postgresql://user:password@localhost:5432/auth_db";
process.env["JWT_REFRESH_SECRET"] = "test-refresh-secret-long";
process.env["JWT_ISSUER"] = "https://auth.temis.co.kr";
process.env["JWT_AUDIENCE"] = "temis";
process.env["REDIS_URL"] = "redis://localhost:6379";
process.env["FRONTEND_REDIRECT_URL"] = "http://localhost:3000/auth/callback";
process.env["GOOGLE_CLIENT_ID"] = "google";
process.env["GOOGLE_CLIENT_SECRET"] = "google-secret";
process.env["GOOGLE_REDIRECT_URI"] = "http://localhost:4000/auth/google/callback";
process.env["NAVER_CLIENT_ID"] = "naver";
process.env["NAVER_CLIENT_SECRET"] = "naver-secret";
process.env["NAVER_REDIRECT_URI"] = "http://localhost:4000/auth/naver/callback";
process.env["KAKAO_CLIENT_ID"] = "kakao";
process.env["KAKAO_CLIENT_SECRET"] = "kakao-secret";
process.env["KAKAO_REDIRECT_URI"] = "http://localhost:4000/auth/kakao/callback";
process.env["CORS_ALLOWED_ORIGINS"] = "http://localhost:3000";
process.env["AUTH_RATE_LIMIT_WINDOW_SECONDS"] = "60";
process.env["AUTH_RATE_LIMIT_MAX_REQUESTS"] = "20";
process.env["AUTH_CLIENTS_JSON"] = JSON.stringify([
  {
    clientId: "temis",
    audience: "temis",
    allowedRedirectUris: ["https://financenow.kr/auth/callback", "https://temis.me/auth/callback", "https://ti.temis.me/auth/callback"],
    allowedOrigins: ["https://financenow.kr"],
    defaultRole: { serviceKey: "temis", name: "user" }
  }
]);

const routeMocks = vi.hoisted(() => ({
  verifyAccessToken: vi.fn(),
  getCurrentUserWithStatus: vi.fn(),
  listAdminUsers: vi.fn(),
  queryAuditLogs: vi.fn(),
  findAdminRoleById: vi.fn(),
  setUserStatus: vi.fn(),
  assignRole: vi.fn(),
  removeRole: vi.fn(),
  revokeSessions: vi.fn()
}));

type UserRecord = {
  readonly id: string;
  readonly email: string;
  readonly status: UserStatusValue;
};

type RefreshTokenRecord = {
  readonly userId: string;
  readonly revokedAt: Date | null;
};

type AdminRouteStoreState = {
  readonly users: Map<string, UserRecord>;
  readonly refreshTokens: RefreshTokenRecord[];
  readonly roles: Map<string, RoleRecord>;
  readonly userRoles: Set<string>;
  readonly auditLogs: AdminAuditRecord[];
};

const roleKey = (serviceKey: string, name: string): string => `${serviceKey}:${name}`;

const userRoleKey = (userId: string, roleId: string): string => `${userId}:${roleId}`;

export const adminRouteStoreState: AdminRouteStoreState = {
  users: new Map(),
  refreshTokens: [],
  roles: new Map(),
  userRoles: new Set(),
  auditLogs: []
};

export const adminRouteAuthAuditEvents: AuthAuditEvent[] = [];

export const resetAdminRouteStoreState = (): void => {
  adminRouteStoreState.users.clear();
  adminRouteStoreState.users.set("target-user", {
    id: "target-user",
    email: "target@example.test",
    status: "ACTIVE"
  });
  adminRouteStoreState.refreshTokens.splice(0, adminRouteStoreState.refreshTokens.length,
    { userId: "target-user", revokedAt: null },
    { userId: "target-user", revokedAt: null },
    { userId: "other-user", revokedAt: null }
  );
  adminRouteStoreState.roles.clear();
  adminRouteStoreState.roles.set(roleKey("temis", "user"), {
    id: "role-user",
    serviceKey: "temis",
    name: "user"
  });
  adminRouteStoreState.userRoles.clear();
  adminRouteStoreState.userRoles.add(userRoleKey("target-user", "role-user"));
  adminRouteStoreState.auditLogs.splice(0, adminRouteStoreState.auditLogs.length);
  adminRouteAuthAuditEvents.splice(0, adminRouteAuthAuditEvents.length);
};

const cloneAdminRouteStoreState = (state: AdminRouteStoreState): AdminRouteStoreState => ({
  users: new Map(state.users),
  refreshTokens: state.refreshTokens.map((refreshToken) => ({ ...refreshToken })),
  roles: new Map(state.roles),
  userRoles: new Set(state.userRoles),
  auditLogs: state.auditLogs.map((auditLog) => ({ ...auditLog }))
});

const replaceAdminRouteStoreState = (target: AdminRouteStoreState, source: AdminRouteStoreState): void => {
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

const createTransactionStore = (state: AdminRouteStoreState): AuthControlTransactionStore => ({
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
    state.auditLogs.push(input);
  }
});

export const adminRouteMutationStore: AdminUserMutationStore = {
  runInTransaction: async (work) => {
    const transactionState = cloneAdminRouteStoreState(adminRouteStoreState);
    const result = await work(createTransactionStore(transactionState));
    replaceAdminRouteStoreState(adminRouteStoreState, transactionState);
    return result;
  }
};

vi.mock("../services/token.service.js", () => ({
  verifyAccessToken: routeMocks.verifyAccessToken,
  issueTokenPair: vi.fn(),
  refreshAccessToken: vi.fn(),
  rotateRefreshToken: vi.fn(),
  revokeRefreshToken: vi.fn()
}));

vi.mock("../services/user.service.js", () => ({
  getCurrentUserWithStatus: routeMocks.getCurrentUserWithStatus
}));

vi.mock("../services/admin-user.store.js", () => ({
  adminUserMutationStore: adminRouteMutationStore
}));

vi.mock("../services/audit.store.js", () => ({
  auditLogStore: {
    create: async (event) => {
      adminRouteAuthAuditEvents.push(event);
    },
    queryAuditLogs: routeMocks.queryAuditLogs,
    findUserIdByEmail: async () => null,
    findUserIdByPasswordEmail: async () => null
  } satisfies AuditLogStore & AuditLogQueryStore
}));

vi.mock("../services/admin-directory.service.js", () => ({
  findAdminRoleById: routeMocks.findAdminRoleById,
  listAdminUsers: routeMocks.listAdminUsers
}));

export const mocks = routeMocks;

export const resetAdminRouteMocks = (): void => {
  for (const mock of Object.values(mocks)) {
    mock.mockReset();
  }
  resetAdminRouteStoreState();
};

export const loadAdminTestApp = async (): Promise<Express> => {
  vi.resetModules();
  const { app } = await import("../app.js");
  return app;
};

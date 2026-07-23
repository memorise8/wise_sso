import type { AdminAuditDetails, AdminAuditEventInput } from "./audit.service.js";
import type { UserStatusValue } from "./user-status.service.js";

export type RoleRecord = {
  readonly id: string;
  readonly serviceKey: string;
  readonly name: string;
};

export type AdminAuditRecord = {
  readonly eventType: AdminAuditEventInput["eventType"];
  readonly outcome: "success";
  readonly actorUserId: string | null;
  readonly targetUserId: string | null;
  readonly reasonCode: string;
  readonly detailsJson?: AdminAuditDetails;
};

export type AuthControlTransactionStore = {
  readonly findActiveUserByEmail: (email: string) => Promise<{ readonly id: string } | null>;
  readonly updateUserStatus: (input: {
    readonly userId: string;
    readonly status: UserStatusValue;
  }) => Promise<boolean>;
  readonly revokeAllRefreshTokensForUser: (input: {
    readonly userId: string;
    readonly revokedAt: Date;
  }) => Promise<number>;
  readonly upsertRole: (input: {
    readonly serviceKey: string;
    readonly name: string;
  }) => Promise<RoleRecord>;
  readonly findRole: (input: {
    readonly serviceKey: string;
    readonly name: string;
  }) => Promise<RoleRecord | null>;
  readonly assignRoleToUser: (input: {
    readonly userId: string;
    readonly roleId: string;
  }) => Promise<boolean>;
  readonly removeRoleFromUser: (input: {
    readonly userId: string;
    readonly roleId: string;
  }) => Promise<boolean>;
  readonly createAdminAuditLog: (event: AdminAuditRecord) => Promise<void>;
};

export type AdminUserMutationStore = {
  readonly runInTransaction: <T>(work: (store: AuthControlTransactionStore) => Promise<T>) => Promise<T>;
};

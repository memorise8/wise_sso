import {
  recordAdminAuditEvent,
  type AdminAuditDetails,
  type AdminAuditEventInput
} from "./audit.service.js";
import type {
  AdminUserMutationStore,
  AuthControlTransactionStore
} from "./auth-control.store.js";
import {
  revokeAllRefreshTokensForUser,
  type RevokeAllRefreshTokensResult
} from "./session-revocation.service.js";
import {
  parseUserStatusValue,
  userStatuses,
  type UserStatusValue
} from "./user-status.service.js";
import { HttpError } from "../utils/httpError.js";

export type {
  AdminAuditRecord,
  AdminUserMutationStore,
  AuthControlTransactionStore,
  RoleRecord
} from "./auth-control.store.js";
export type { UserStatusValue } from "./user-status.service.js";

export type SetUserStatusInput = {
  readonly actorUserId: string | null;
  readonly targetUserId: string;
  readonly status: string;
  readonly reasonCode: string;
  readonly now?: Date;
  readonly details?: AdminAuditDetails;
};

export type AssignRoleInput = {
  readonly actorUserId: string | null;
  readonly targetUserId: string;
  readonly serviceKey: string;
  readonly name: string;
  readonly reasonCode: string;
  readonly details?: AdminAuditDetails;
};

export type RemoveRoleInput = AssignRoleInput;

export type SetUserStatusResult = {
  readonly statusChanged: boolean;
  readonly revokedRefreshTokenCount: number;
};

export type AssignRoleResult = {
  readonly roleAssigned: boolean;
  readonly roleId: string;
};

export type RemoveRoleResult = {
  readonly roleRemoved: boolean;
  readonly roleId: string | null;
  readonly revokedRefreshTokenCount: number;
};

export type AdminUserService = {
  readonly setUserStatus: (input: SetUserStatusInput) => Promise<SetUserStatusResult>;
  readonly assignRole: (input: AssignRoleInput) => Promise<AssignRoleResult>;
  readonly removeRole: (input: RemoveRoleInput) => Promise<RemoveRoleResult>;
  readonly revokeSessions: (input: {
    readonly actorUserId: string | null;
    readonly targetUserId: string;
    readonly reasonCode: string;
    readonly now?: Date;
    readonly details?: AdminAuditDetails;
  }) => Promise<RevokeAllRefreshTokensResult>;
};

const assertUserId = (userId: string): void => {
  if (userId.trim() === "") {
    throw new HttpError(400, "INVALID_USER_ID", "User id is required");
  }
};

const assertRoleInput = (input: Pick<AssignRoleInput, "serviceKey" | "name">): void => {
  if (input.serviceKey.trim() === "" || input.name.trim() === "") {
    throw new HttpError(400, "INVALID_ROLE", "Role service key and name are required");
  }
};

const shouldRevokeForStatus = (status: UserStatusValue): boolean => {
  switch (status) {
    case userStatuses.active:
    case userStatuses.pendingEmailVerification:
      return false;
    case userStatuses.suspended:
    case userStatuses.deleted:
      return true;
  }
};

const recordAudit = async (
  store: AuthControlTransactionStore,
  input: AdminAuditEventInput
): Promise<void> => {
  await recordAdminAuditEvent({
    create: async (event) => {
      await store.createAdminAuditLog({
        eventType: input.eventType,
        outcome: "success",
        actorUserId: event.actorUserId ?? null,
        targetUserId: event.targetUserId ?? null,
        reasonCode: event.reasonCode ?? input.reasonCode,
        ...(event.detailsJson ? { detailsJson: event.detailsJson } : {})
      });
    },
    findUserIdByEmail: async () => null,
    findUserIdByPasswordEmail: async () => null
  }, input);
};

export const createAdminUserService = (mutationStore: AdminUserMutationStore): AdminUserService => ({
  setUserStatus: async (input) => {
    assertUserId(input.targetUserId);
    const status = parseUserStatusValue(input.status);
    const changedAt = input.now ?? new Date();

    return mutationStore.runInTransaction(async (store) => {
      const statusChanged = await store.updateUserStatus({
        userId: input.targetUserId,
        status
      });
      const revokeResult = shouldRevokeForStatus(status)
        ? await revokeAllRefreshTokensForUser(store, {
          userId: input.targetUserId,
          revokedAt: changedAt
        })
        : { revokedCount: 0 };

      if (statusChanged) {
        await recordAudit(store, {
          eventType: "admin_user_status_changed",
          actorUserId: input.actorUserId,
          targetUserId: input.targetUserId,
          reasonCode: input.reasonCode,
          ...(input.details ? { details: input.details } : {})
        });
      }

      return {
        statusChanged,
        revokedRefreshTokenCount: revokeResult.revokedCount
      };
    });
  },
  assignRole: async (input) => {
    assertUserId(input.targetUserId);
    assertRoleInput(input);

    return mutationStore.runInTransaction(async (store) => {
      const role = await store.upsertRole({
        serviceKey: input.serviceKey,
        name: input.name
      });
      const roleAssigned = await store.assignRoleToUser({
        userId: input.targetUserId,
        roleId: role.id
      });

      if (roleAssigned) {
        await recordAudit(store, {
          eventType: "admin_user_role_assigned",
          actorUserId: input.actorUserId,
          targetUserId: input.targetUserId,
          reasonCode: input.reasonCode,
          details: input.details ?? {
            serviceKey: role.serviceKey,
            roleName: role.name
          }
        });
      }

      return {
        roleAssigned,
        roleId: role.id
      };
    });
  },
  removeRole: async (input) => {
    assertUserId(input.targetUserId);
    assertRoleInput(input);
    const revokedAt = new Date();

    return mutationStore.runInTransaction(async (store) => {
      const role = await store.findRole({
        serviceKey: input.serviceKey,
        name: input.name
      });
      if (!role) {
        return {
          roleRemoved: false,
          roleId: null,
          revokedRefreshTokenCount: 0
        };
      }

      const roleRemoved = await store.removeRoleFromUser({
        userId: input.targetUserId,
        roleId: role.id
      });
      const revokeResult = roleRemoved
        ? await revokeAllRefreshTokensForUser(store, {
          userId: input.targetUserId,
          revokedAt
        })
        : { revokedCount: 0 };

      if (roleRemoved) {
        await recordAudit(store, {
          eventType: "admin_user_role_removed",
          actorUserId: input.actorUserId,
          targetUserId: input.targetUserId,
          reasonCode: input.reasonCode,
          details: input.details ?? {
            serviceKey: role.serviceKey,
            roleName: role.name
          }
        });
      }

      return {
        roleRemoved,
        roleId: role.id,
        revokedRefreshTokenCount: revokeResult.revokedCount
      };
    });
  },
  revokeSessions: async (input) => {
    assertUserId(input.targetUserId);
    const revokedAt = input.now ?? new Date();

    return mutationStore.runInTransaction(async (store) => {
      const revokeResult = await revokeAllRefreshTokensForUser(store, {
        userId: input.targetUserId,
        revokedAt
      });
      await recordAudit(store, {
        eventType: "admin_user_sessions_revoked",
        actorUserId: input.actorUserId,
        targetUserId: input.targetUserId,
        reasonCode: input.reasonCode,
        ...(input.details ? { details: input.details } : {})
      });
      return revokeResult;
    });
  }
});

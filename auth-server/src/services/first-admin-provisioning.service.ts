import {
  recordAdminAuditEvent,
  type AdminAuditEventInput
} from "./audit.service.js";
import type {
  AdminUserMutationStore,
  AuthControlTransactionStore
} from "./auth-control.store.js";
import { revokeAllRefreshTokensForUser } from "./session-revocation.service.js";
import { HttpError } from "../utils/httpError.js";

export type GrantFirstAdminInput = {
  readonly email: string;
  readonly now?: Date;
};

export type GrantFirstAdminResult = {
  readonly userId: string;
  readonly roleAssigned: boolean;
  readonly revokedRefreshTokenCount: number;
};

const normalizeEmail = (email: string): string => email.trim().toLowerCase();

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

export const grantFirstAdmin = async (
  mutationStore: AdminUserMutationStore,
  input: GrantFirstAdminInput
): Promise<GrantFirstAdminResult> => {
  const email = normalizeEmail(input.email);
  const revokedAt = input.now ?? new Date();

  return mutationStore.runInTransaction(async (store) => {
    const user = await store.findActiveUserByEmail(email);
    if (!user) {
      throw new HttpError(404, "USER_NOT_FOUND", "No active user found");
    }

    const role = await store.upsertRole({
      serviceKey: "temis",
      name: "admin"
    });
    const roleAssigned = await store.assignRoleToUser({
      userId: user.id,
      roleId: role.id
    });
    const revokeResult = await revokeAllRefreshTokensForUser(store, {
      userId: user.id,
      revokedAt
    });
    await recordAudit(store, {
      eventType: "admin_user_role_assigned",
      actorUserId: null,
      targetUserId: user.id,
      reasonCode: "OPS_BOOTSTRAP_ADMIN",
      details: {
        serviceKey: role.serviceKey,
        roleName: role.name
      }
    });

    return {
      userId: user.id,
      roleAssigned,
      revokedRefreshTokenCount: revokeResult.revokedCount
    };
  });
};

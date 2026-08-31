import { PrismaClient } from "@prisma/client";
import type { Prisma } from "@prisma/client";
import type {
  AdminAuditRecord,
  AdminUserMutationStore,
  AuthControlTransactionStore
} from "./auth-control.store.js";

const prisma = new PrismaClient();

type AuthControlPrismaClient = Pick<
  Prisma.TransactionClient,
  "$queryRaw" | "user" | "refreshToken" | "role" | "userRole" | "auditLog"
>;

const lockUserForRefreshTokenRevocation = async (
  client: AuthControlPrismaClient,
  userId: string
): Promise<boolean> => {
  const lockedUsers = await client.$queryRaw<readonly { readonly id: string }[]>`
    SELECT "id" FROM "User" WHERE "id" = ${userId} FOR UPDATE
  `;
  return lockedUsers.length === 1;
};

export const createAuthControlTransactionStore = (client: AuthControlPrismaClient): AuthControlTransactionStore => ({
  findActiveUserByEmail: async (email) =>
    client.user.findFirst({
      where: {
        email,
        status: "ACTIVE"
      },
      select: { id: true }
    }),
  updateUserStatus: async (input) => {
    const result = await client.user.updateMany({
      where: { id: input.userId },
      data: { status: input.status }
    });
    return result.count === 1;
  },
  revokeAllRefreshTokensForUser: async (input) => {
    const userLocked = await lockUserForRefreshTokenRevocation(client, input.userId);
    if (!userLocked) {
      return 0;
    }

    const result = await client.refreshToken.updateMany({
      where: {
        userId: input.userId,
        revokedAt: null
      },
      data: { revokedAt: input.revokedAt }
    });
    return result.count;
  },
  upsertRole: async (input) =>
    client.role.upsert({
      where: {
        serviceKey_name: {
          serviceKey: input.serviceKey,
          name: input.name
        }
      },
      create: {
        serviceKey: input.serviceKey,
        name: input.name
      },
      update: {}
    }),
  findRole: async (input) =>
    client.role.findUnique({
      where: {
        serviceKey_name: {
          serviceKey: input.serviceKey,
          name: input.name
        }
      }
    }),
  assignRoleToUser: async (input) => {
    const result = await client.userRole.createMany({
      data: {
        userId: input.userId,
        roleId: input.roleId
      },
      skipDuplicates: true
    });
    return result.count === 1;
  },
  removeRoleFromUser: async (input) => {
    const result = await client.userRole.deleteMany({
      where: {
        userId: input.userId,
        roleId: input.roleId
      }
    });
    return result.count > 0;
  },
  createAdminAuditLog: async (event: AdminAuditRecord) => {
    await client.auditLog.create({
      data: {
        eventType: event.eventType,
        outcome: event.outcome,
        userId: event.targetUserId,
        actorUserId: event.actorUserId,
        targetUserId: event.targetUserId,
        reasonCode: event.reasonCode,
        ...(event.detailsJson ? { detailsJson: event.detailsJson } : {})
      }
    });
  }
});

export const createPrismaAdminUserMutationStore = (client: PrismaClient): AdminUserMutationStore => ({
  runInTransaction: async (work) =>
    client.$transaction(async (transaction) => work(createAuthControlTransactionStore(transaction)))
});

export const adminUserMutationStore: AdminUserMutationStore = createPrismaAdminUserMutationStore(prisma);

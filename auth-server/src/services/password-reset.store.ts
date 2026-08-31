import { PrismaClient } from "@prisma/client";
import type { Prisma } from "@prisma/client";
import type {
  CreateResetTokenInput,
  PasswordResetStore,
  PasswordResetUser,
  ResetPasswordWithTokenResult,
  ResetPasswordWithTokenInput
} from "./password-reset.service.js";
import { revokeAllRefreshTokensForUser } from "./session-revocation.service.js";

const prisma = new PrismaClient();

type PasswordResetTransactionClient = Pick<Prisma.TransactionClient, "$queryRaw">;

const lockUserForRefreshTokenRevocation = async (
  client: PasswordResetTransactionClient,
  userId: string
): Promise<boolean> => {
  const lockedUsers = await client.$queryRaw<readonly { readonly id: string }[]>`
    SELECT "id" FROM "User" WHERE "id" = ${userId} FOR UPDATE
  `;
  return lockedUsers.length === 1;
};

export const passwordResetStore: PasswordResetStore = {
  findUserByEmail: async (email): Promise<PasswordResetUser | null> => {
    const credential = await prisma.passwordCredential.findUnique({
      where: { email },
      include: { user: true }
    });
    if (!credential || credential.user.status !== "ACTIVE") {
      return null;
    }

    return {
      id: credential.userId,
      email: credential.email
    };
  },
  createResetToken: async (input: CreateResetTokenInput): Promise<void> => {
    await prisma.passwordResetToken.create({
      data: {
        userId: input.userId,
        tokenHash: input.tokenHash,
        expiresAt: input.expiresAt
      }
    });
  },
  resetPasswordWithToken: async (input: ResetPasswordWithTokenInput): Promise<ResetPasswordWithTokenResult | null> =>
    prisma.$transaction(async (transaction) => {
      const resetToken = await transaction.passwordResetToken.findFirst({
        where: {
          tokenHash: input.tokenHash,
          usedAt: null,
          expiresAt: { gt: input.now }
        }
      });
      if (!resetToken) {
        return null;
      }

      const tokenUpdate = await transaction.passwordResetToken.updateMany({
        where: {
          id: resetToken.id,
          usedAt: null,
          expiresAt: { gt: input.now }
        },
        data: { usedAt: input.now }
      });
      if (tokenUpdate.count !== 1) {
        return null;
      }

      const userLocked = await lockUserForRefreshTokenRevocation(transaction, resetToken.userId);
      if (!userLocked) {
        return null;
      }

      await transaction.passwordCredential.update({
        where: { userId: resetToken.userId },
        data: {
          passwordHash: input.passwordHash,
          failedLoginCount: 0,
          lockedUntil: null,
          passwordUpdatedAt: input.now
        }
      });
      await revokeAllRefreshTokensForUser({
        revokeAllRefreshTokensForUser: async (revokeInput) => {
          const revokeResult = await transaction.refreshToken.updateMany({
            where: {
              userId: revokeInput.userId,
              revokedAt: null
            },
            data: { revokedAt: revokeInput.revokedAt }
          });
          return revokeResult.count;
        }
      }, {
        userId: resetToken.userId,
        revokedAt: input.now
      });

      return { userId: resetToken.userId };
    })
};

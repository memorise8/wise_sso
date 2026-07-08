import { PrismaClient } from "@prisma/client";
import type {
  CreateResetTokenInput,
  PasswordResetStore,
  PasswordResetUser,
  ResetPasswordWithTokenResult,
  ResetPasswordWithTokenInput
} from "./password-reset.service.js";

const prisma = new PrismaClient();

export const passwordResetStore: PasswordResetStore = {
  findUserByEmail: async (email): Promise<PasswordResetUser | null> => {
    const credential = await prisma.passwordCredential.findUnique({
      where: { email },
      include: { user: true }
    });
    if (!credential || credential.user.status !== "active") {
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

      await transaction.passwordCredential.update({
        where: { userId: resetToken.userId },
        data: {
          passwordHash: input.passwordHash,
          failedLoginCount: 0,
          lockedUntil: null,
          passwordUpdatedAt: input.now
        }
      });
      await transaction.refreshToken.updateMany({
        where: {
          userId: resetToken.userId,
          revokedAt: null
        },
        data: { revokedAt: input.now }
      });

      return { userId: resetToken.userId };
    })
};

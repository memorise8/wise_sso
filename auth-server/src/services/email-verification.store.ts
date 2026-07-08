import { PrismaClient } from "@prisma/client";
import type {
  EmailVerificationStore,
  EmailVerificationTokenRecord,
  EmailVerificationUser
} from "./email-verification.service.js";

const prisma = new PrismaClient();

export const emailVerificationStore: EmailVerificationStore = {
  findUserByEmail: async (email): Promise<EmailVerificationUser | null> => {
    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        status: true
      }
    });

    return user;
  },
  createVerificationToken: async (input) => {
    await prisma.emailVerificationToken.create({
      data: {
        userId: input.userId,
        tokenHash: input.tokenHash,
        expiresAt: input.expiresAt
      }
    });
  },
  findVerificationTokenByHash: async (tokenHash): Promise<EmailVerificationTokenRecord | null> => {
    const token = await prisma.emailVerificationToken.findUnique({
      where: { tokenHash },
      select: {
        id: true,
        userId: true,
        expiresAt: true,
        usedAt: true
      }
    });

    return token;
  },
  markTokenUsedAndActivateUser: async (input): Promise<boolean> =>
    prisma.$transaction(async (transaction) => {
      const tokenUpdate = await transaction.emailVerificationToken.updateMany({
        where: {
          id: input.tokenId,
          userId: input.userId,
          usedAt: null,
          expiresAt: { gt: input.usedAt }
        },
        data: { usedAt: input.usedAt }
      });
      if (tokenUpdate.count !== 1) {
        return false;
      }

      await transaction.user.update({
        where: { id: input.userId },
        data: { status: "active" }
      });

      return true;
    })
};

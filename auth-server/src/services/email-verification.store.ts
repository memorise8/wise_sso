import { PrismaClient } from "@prisma/client";
import type {
  EmailVerificationHandoff,
  EmailVerificationStore,
  EmailVerificationTokenRecord,
  EmailVerificationUser
} from "./email-verification.service.js";
import { seedTemisRolesAndAssignDefaultRole } from "./user.service.js";
import { userStatuses } from "./user-status.service.js";

const prisma = new PrismaClient();

export const emailVerificationStore: EmailVerificationStore = {
  findUserByEmail: async (email): Promise<EmailVerificationUser | null> => {
    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        status: true,
        pendingPasswordCredential: {
          select: {
            expiresAt: true
          }
        }
      }
    });

    return user ? {
      id: user.id,
      email: user.email,
      status: user.status,
      hasPendingPasswordCredential: (user.pendingPasswordCredential?.expiresAt ?? new Date(0)) > new Date()
    } : null;
  },
  createVerificationToken: async (input) => {
    await prisma.emailVerificationToken.create({
      data: {
        userId: input.userId,
        tokenHash: input.tokenHash,
        expiresAt: input.expiresAt,
        handoffClientId: input.handoff?.clientId ?? null,
        handoffAudience: input.handoff?.audience ?? null,
        handoffRedirectUri: input.handoff?.redirectUri ?? null,
        handoffState: input.handoff?.state ?? null,
        handoffCodeChallenge: input.handoff?.codeChallenge ?? null,
        handoffCodeChallengeMethod: input.handoff?.codeChallengeMethod ?? null
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
        usedAt: true,
        handoffClientId: true,
        handoffAudience: true,
        handoffRedirectUri: true,
        handoffState: true,
        handoffCodeChallenge: true,
        handoffCodeChallengeMethod: true
      }
    });

    if (!token) {
      return null;
    }

    const handoff: EmailVerificationHandoff | null = token.handoffClientId &&
      token.handoffAudience &&
      token.handoffRedirectUri &&
      token.handoffCodeChallenge &&
      token.handoffCodeChallengeMethod === "S256"
      ? {
          clientId: token.handoffClientId,
          audience: token.handoffAudience,
          redirectUri: token.handoffRedirectUri,
          state: token.handoffState,
          codeChallenge: token.handoffCodeChallenge,
          codeChallengeMethod: "S256"
        }
      : null;

    return {
      id: token.id,
      userId: token.userId,
      expiresAt: token.expiresAt,
      usedAt: token.usedAt,
      handoff
    };
  },
  markTokenUsedAndActivateUser: async (input): Promise<string | null> =>
    prisma.$transaction(async (transaction) => {
      const user = await transaction.user.findUnique({
        where: { id: input.userId },
        select: { id: true, email: true, status: true }
      });
      const pendingPasswordCredential = await transaction.pendingPasswordCredential.findUnique({
        where: { userId: input.userId }
      });
      const canActivateUser = user?.status === userStatuses.pendingEmailVerification;
      const canAttachPassword = pendingPasswordCredential !== null && pendingPasswordCredential.expiresAt > input.usedAt;
      if (!canActivateUser && !canAttachPassword) {
        return null;
      }

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
        return null;
      }

      if (canActivateUser) {
        const subjectReservation = user.email
          ? await transaction.subjectReservation.findUnique({ where: { email: user.email.toLowerCase() } })
          : null;
        const reservedSubjectId = subjectReservation?.subjectId ?? null;
        if (reservedSubjectId && reservedSubjectId !== input.userId) {
          const subjectUser = await transaction.user.findUnique({
            where: { id: reservedSubjectId },
            select: { id: true }
          });
          if (subjectUser) {
            return null;
          }
        }
        const activatedUserId = reservedSubjectId ?? input.userId;
        const userUpdate = await transaction.user.updateMany({
          where: {
            id: input.userId,
            status: userStatuses.pendingEmailVerification
          },
          data: {
            ...(reservedSubjectId ? { id: activatedUserId } : {}),
            status: userStatuses.active,
            emailVerified: true
          }
        });
        if (userUpdate.count !== 1) {
          return null;
        }
        await seedTemisRolesAndAssignDefaultRole(transaction, activatedUserId);
        return activatedUserId;
      }

      if (!pendingPasswordCredential) {
        return null;
      }
      await transaction.passwordCredential.create({
        data: {
          userId: pendingPasswordCredential.userId,
          email: pendingPasswordCredential.email,
          passwordHash: pendingPasswordCredential.passwordHash
        }
      });
      await transaction.pendingPasswordCredential.delete({
        where: { userId: input.userId }
      });

      return input.userId;
    })
};

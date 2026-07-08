import { PrismaClient } from "@prisma/client";
import type { PasswordAuthStore, PasswordCredentialRecord } from "./password-auth.service.js";
import type { CurrentUser } from "./user.service.js";

const prisma = new PrismaClient();

const toCurrentUser = (user: {
  readonly id: string;
  readonly email: string | null;
  readonly name: string | null;
  readonly roles: readonly {
    readonly role: {
      readonly serviceKey: string;
      readonly name: string;
    };
  }[];
}): CurrentUser => ({
  id: user.id,
  email: user.email,
  name: user.name,
  roles: user.roles.map((userRole) => ({
    serviceKey: userRole.role.serviceKey,
    name: userRole.role.name
  }))
});

export const passwordAuthStore: PasswordAuthStore = {
  findUserByEmail: async (email) => {
    const user = await prisma.user.findUnique({
      where: { email },
      include: { roles: { include: { role: true } } }
    });
    return user ? toCurrentUser(user) : null;
  },
  createUserWithPassword: async (input) => {
    const user = await prisma.user.create({
      data: {
        email: input.email,
        name: input.name,
        status: input.status,
        passwordCredential: {
          create: {
            email: input.email.toLowerCase(),
            passwordHash: input.passwordHash
          }
        }
      },
      include: { roles: { include: { role: true } } }
    });
    return toCurrentUser(user);
  },
  findCredentialByEmail: async (email): Promise<PasswordCredentialRecord | null> => {
    const credential = await prisma.passwordCredential.findUnique({
      where: { email },
      include: { user: true }
    });
    if (!credential) {
      return null;
    }
    return {
      userId: credential.userId,
      email: credential.email,
      passwordHash: credential.passwordHash,
      failedLoginCount: credential.failedLoginCount,
      lockedUntil: credential.lockedUntil,
      userStatus: credential.user.status
    };
  },
  markLoginSuccess: async (userId) => {
    await prisma.passwordCredential.update({
      where: { userId },
      data: { failedLoginCount: 0, lockedUntil: null }
    });
  },
  markLoginFailure: async (userId) => {
    const credential = await prisma.passwordCredential.findUnique({ where: { userId } });
    if (!credential) {
      return;
    }

    const failedLoginCount = credential.failedLoginCount + 1;
    const lockedUntil = failedLoginCount >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null;
    await prisma.passwordCredential.update({
      where: { userId },
      data: { failedLoginCount, lockedUntil }
    });
  },
  getCurrentUser: async (userId) => {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { roles: { include: { role: true } } }
    });
    return user ? toCurrentUser(user) : null;
  }
};

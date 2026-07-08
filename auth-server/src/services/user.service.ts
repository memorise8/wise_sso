import { PrismaClient } from "@prisma/client";
import type { User } from "@prisma/client";

const prisma = new PrismaClient();

export type Provider = "google" | "naver" | "kakao";

export type OAuthProfile = {
  readonly provider: Provider;
  readonly providerUserId: string;
  readonly email: string | null;
  readonly name: string | null;
  readonly profileUrl: string | null;
};

export type CurrentUser = {
  readonly id: string;
  readonly email: string | null;
  readonly name: string | null;
  readonly roles: readonly {
    readonly serviceKey: string;
    readonly name: string;
  }[];
};

const nullableEmailForSeparateAccount = async (email: string | null): Promise<string | null> => {
  if (!email) {
    return null;
  }

  const existingUser = await prisma.user.findUnique({ where: { email } });
  return existingUser ? null : email;
};

export const findOrCreateUserBySocialProfile = async (profile: OAuthProfile): Promise<User> => {
  const socialAccount = await prisma.socialAccount.findUnique({
    where: {
      provider_providerUserId: {
        provider: profile.provider,
        providerUserId: profile.providerUserId
      }
    },
    include: { user: true }
  });

  if (socialAccount) {
    return socialAccount.user;
  }

  const userEmail = await nullableEmailForSeparateAccount(profile.email);
  return prisma.user.create({
    data: {
      email: userEmail,
      name: profile.name,
      profileUrl: profile.profileUrl,
      socialAccounts: {
        create: {
          provider: profile.provider,
          providerUserId: profile.providerUserId,
          providerEmail: profile.email
        }
      }
    }
  });
};

export const getCurrentUser = async (userId: string): Promise<CurrentUser | null> => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: {
      roles: {
        include: {
          role: true
        }
      }
    }
  });

  if (!user) {
    return null;
  }

  return {
    id: user.id,
    email: user.email,
    name: user.name,
    roles: user.roles.map((userRole) => ({
      serviceKey: userRole.role.serviceKey,
      name: userRole.role.name
    }))
  };
};

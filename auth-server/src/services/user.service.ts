import { PrismaClient, Prisma } from "@prisma/client";
import type { User } from "@prisma/client";
import { env } from "../config/env.js";
import { userStatuses } from "./user-status.service.js";
import type { CurrentUserWithStatus } from "./user-status.service.js";

const prisma = new PrismaClient();

export type Provider = "google" | "naver" | "kakao";

export type OAuthProfile = {
  readonly provider: Provider;
  readonly providerUserId: string;
  readonly email: string | null;
  readonly emailVerified?: boolean;
  readonly name: string | null;
  readonly profileUrl: string | null;
};

export type CurrentUser = {
  readonly id: string;
  readonly email: string | null;
  readonly emailVerified: boolean;
  readonly name: string | null;
  readonly roles: readonly {
    readonly serviceKey: string;
    readonly name: string;
  }[];
};

type RoleAssignment = {
  readonly serviceKey: string;
  readonly name: string;
};

type RoleRecord = RoleAssignment & {
  readonly id: string;
};

export type DefaultRoleBackfillResult = {
  readonly defaultRole: RoleAssignment;
  readonly rolelessUserCount: number;
  readonly assignedUserRoleCount: number;
};

type RoleSeedClient = Pick<Prisma.TransactionClient, "role">;

type RoleAssignmentClient = Pick<Prisma.TransactionClient, "role" | "userRole">;

type UserLookupClient = Pick<Prisma.TransactionClient, "user">;

type DefaultRoleBackfillClient = Pick<Prisma.TransactionClient, "$executeRaw" | "role">;

const temisRoles: readonly RoleAssignment[] = [
  { serviceKey: "temis", name: "pending" },
  { serviceKey: "temis", name: "user" },
  { serviceKey: "temis", name: "admin" }
];

const defaultRoleAssignment = (clientId: string = "temis"): RoleAssignment => {
  const client = env.AUTH_CLIENTS_JSON.find((candidate) => candidate.clientId === clientId);
  return client?.defaultRole ?? { serviceKey: "temis", name: "pending" };
};

const toCurrentUser = (user: {
  readonly id: string;
  readonly email: string | null;
  readonly emailVerified: boolean;
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
  emailVerified: user.emailVerified,
  name: user.name,
  roles: user.roles.map((userRole) => ({
    serviceKey: userRole.role.serviceKey,
    name: userRole.role.name
  }))
});

const seedTemisRolesAndResolveDefaultRole = async (
  client: RoleSeedClient,
  clientId: string = "temis"
): Promise<RoleRecord> => {
  for (const role of temisRoles) {
    await client.role.upsert({
      where: {
        serviceKey_name: {
          serviceKey: role.serviceKey,
          name: role.name
        }
      },
      create: role,
      update: {}
    });
  }

  const defaultRole = defaultRoleAssignment(clientId);
  return client.role.upsert({
    where: {
      serviceKey_name: {
        serviceKey: defaultRole.serviceKey,
        name: defaultRole.name
      }
    },
    create: defaultRole,
    update: {}
  });
};

export const seedTemisRolesAndAssignDefaultRole = async (
  client: RoleAssignmentClient,
  userId: string,
  clientId: string = "temis"
): Promise<void> => {
  const assignedRole = await seedTemisRolesAndResolveDefaultRole(client, clientId);

  await client.userRole.createMany({
    data: {
      userId,
      roleId: assignedRole.id
    },
    skipDuplicates: true
  });
};

export const backfillRolelessUsersWithDefaultRole = async (
  client: DefaultRoleBackfillClient
): Promise<DefaultRoleBackfillResult> => {
  const assignedRole = await seedTemisRolesAndResolveDefaultRole(client);
  const assignedUserRoleCount = await client.$executeRaw`
    INSERT INTO "UserRole" ("id", "userId", "roleId")
    SELECT
      concat('default-role-', md5("User"."id" || ${assignedRole.id})),
      "User"."id",
      ${assignedRole.id}
    FROM "User"
    WHERE NOT EXISTS (
      SELECT 1 FROM "UserRole" WHERE "UserRole"."userId" = "User"."id"
    )
    ON CONFLICT ("userId", "roleId") DO NOTHING
  `;

  return {
    defaultRole: {
      serviceKey: assignedRole.serviceKey,
      name: assignedRole.name
    },
    rolelessUserCount: assignedUserRoleCount,
    assignedUserRoleCount
  };
};

const nullableEmailForSeparateAccount = async (
  client: UserLookupClient,
  email: string | null
): Promise<string | null> => {
  if (!email) {
    return null;
  }

  const existingUser = await client.user.findUnique({ where: { email } });
  return existingUser ? null : email;
};

export const findOrCreateUserBySocialProfile = async (profile: OAuthProfile, clientId: string = "temis"): Promise<User> => {
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

  return prisma.$transaction(async (transaction) => {
    const userEmail = await nullableEmailForSeparateAccount(transaction, profile.email);
    const user = await transaction.user.create({
      data: {
        email: userEmail,
        emailVerified: profile.emailVerified ?? false,
        name: profile.name,
        profileUrl: profile.profileUrl,
        status: userStatuses.active,
        socialAccounts: {
          create: {
            provider: profile.provider,
            providerUserId: profile.providerUserId,
            providerEmail: profile.email
          }
        }
      }
    });

    await seedTemisRolesAndAssignDefaultRole(transaction, user.id, clientId);
    return user;
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

  return toCurrentUser(user);
};

export const getCurrentUserWithStatus = async (userId: string): Promise<CurrentUserWithStatus | null> => {
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
    ...toCurrentUser(user),
    status: user.status
  };
};

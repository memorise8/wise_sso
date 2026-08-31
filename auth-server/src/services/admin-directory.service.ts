import { PrismaClient } from "@prisma/client";
import type { Prisma } from "@prisma/client";
import { parseUserStatusValue, type UserStatusValue } from "./user-status.service.js";
import { HttpError } from "../utils/httpError.js";

const prisma = new PrismaClient();

type AdminRoleProfile = {
  readonly id: string;
  readonly serviceKey: string;
  readonly name: string;
};

export type AdminUserProfile = {
  readonly id: string;
  readonly email: string | null;
  readonly name: string | null;
  readonly status: UserStatusValue;
  readonly createdAt: string;
  readonly roles: readonly AdminRoleProfile[];
};

export type AdminUserListInput = {
  readonly page: number;
  readonly pageSize: number;
  readonly status?: UserStatusValue;
  readonly email?: string;
  readonly role?: string;
};

export type AdminUserPage = {
  readonly items: readonly AdminUserProfile[];
  readonly total: number;
  readonly page: number;
  readonly pageSize: number;
};

const roleFilter = (role: string): Prisma.RoleWhereInput => {
  const parts = role.split(":");
  if (parts.length > 2) {
    throw new HttpError(400, "INVALID_REQUEST", "Invalid request");
  }

  const serviceKey = parts[0];
  const name = parts[1];
  if (serviceKey === undefined) {
    throw new HttpError(400, "INVALID_REQUEST", "Invalid request");
  }

  if (name !== undefined) {
    if (serviceKey.trim() === "" || name.trim() === "") {
      throw new HttpError(400, "INVALID_REQUEST", "Invalid request");
    }
    return { serviceKey, name };
  }

  if (serviceKey.trim() === "") {
    throw new HttpError(400, "INVALID_REQUEST", "Invalid request");
  }
  return { name: serviceKey };
};

const userWhere = (input: AdminUserListInput): Prisma.UserWhereInput => ({
  ...(input.status ? { status: parseUserStatusValue(input.status) } : {}),
  ...(input.email ? { email: { contains: input.email.trim(), mode: "insensitive" } } : {}),
  ...(input.role ? { roles: { some: { role: roleFilter(input.role) } } } : {})
});

export const listAdminUsers = async (input: AdminUserListInput): Promise<AdminUserPage> => {
  const where = userWhere(input);
  const [items, total] = await prisma.$transaction([
    prisma.user.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: (input.page - 1) * input.pageSize,
      take: input.pageSize,
      select: {
        id: true,
        email: true,
        name: true,
        status: true,
        createdAt: true,
        roles: {
          include: {
            role: true
          }
        }
      }
    }),
    prisma.user.count({ where })
  ]);

  return {
    items: items.map((user) => ({
      id: user.id,
      email: user.email,
      name: user.name,
      status: user.status,
      createdAt: user.createdAt.toISOString(),
      roles: user.roles.map((userRole) => ({
        id: userRole.role.id,
        serviceKey: userRole.role.serviceKey,
        name: userRole.role.name
      }))
    })),
    total,
    page: input.page,
    pageSize: input.pageSize
  };
};

export const findAdminRoleById = async (roleId: string): Promise<AdminRoleProfile | null> =>
  prisma.role.findUnique({
    where: { id: roleId },
    select: {
      id: true,
      serviceKey: true,
      name: true
    }
  });

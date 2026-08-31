import { PrismaClient } from "@prisma/client";
import type { Prisma } from "@prisma/client";
import type { AuditLogListInput, AuditLogQueryStore, AuditLogStore } from "./audit.service.js";

const prisma = new PrismaClient();

const auditLogWhere = (input: AuditLogListInput): Prisma.AuditLogWhereInput => {
  const createdAt = input.createdAtFrom || input.createdAtTo
    ? {
      ...(input.createdAtFrom ? { gte: input.createdAtFrom } : {}),
      ...(input.createdAtTo ? { lte: input.createdAtTo } : {})
    }
    : undefined;

  return {
    ...(createdAt ? { createdAt } : {}),
    ...(input.eventType ? { eventType: input.eventType } : {}),
    ...(input.outcome ? { outcome: input.outcome } : {}),
    ...(input.userId ? { userId: input.userId } : {}),
    ...(input.actorUserId ? { actorUserId: input.actorUserId } : {}),
    ...(input.targetUserId ? { targetUserId: input.targetUserId } : {}),
    ...(input.reasonCode ? { reasonCode: input.reasonCode } : {})
  };
};

export const auditLogStore: AuditLogStore & AuditLogQueryStore = {
  create: async (event) => {
    await prisma.auditLog.create({
      data: {
        eventType: event.eventType,
        outcome: event.outcome,
        userId: event.userId,
        actorUserId: event.actorUserId ?? null,
        targetUserId: event.targetUserId ?? null,
        provider: event.provider ?? null,
        serviceKey: event.serviceKey ?? null,
        ipAddress: event.ipAddress ?? null,
        userAgent: event.userAgent ?? null,
        reasonCode: event.reasonCode ?? null,
        ...(event.detailsJson ? { detailsJson: event.detailsJson } : {})
      }
    });
  },
  queryAuditLogs: async (input) => {
    const where = auditLogWhere(input);
    const [items, total] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip: (input.page - 1) * input.pageSize,
        take: input.pageSize,
        select: {
          id: true,
          eventType: true,
          outcome: true,
          userId: true,
          actorUserId: true,
          targetUserId: true,
          reasonCode: true,
          detailsJson: true,
          createdAt: true
        }
      }),
      prisma.auditLog.count({ where })
    ]);
    return { items, total };
  },
  findUserIdByEmail: async (email) => {
    const user = await prisma.user.findUnique({
      where: { email: email.trim().toLowerCase() },
      select: { id: true }
    });
    return user?.id ?? null;
  },
  findUserIdByPasswordEmail: async (email) => {
    const credential = await prisma.passwordCredential.findUnique({
      where: { email: email.trim().toLowerCase() },
      select: { userId: true }
    });
    return credential?.userId ?? null;
  }
};

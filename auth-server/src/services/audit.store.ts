import { PrismaClient } from "@prisma/client";
import type { AuditLogStore } from "./audit.service.js";

const prisma = new PrismaClient();

export const auditLogStore: AuditLogStore = {
  create: async (event) => {
    await prisma.auditLog.create({
      data: {
        eventType: event.eventType,
        outcome: event.outcome,
        userId: event.userId,
        provider: event.provider ?? null,
        serviceKey: event.serviceKey ?? null,
        ipAddress: event.ipAddress ?? null,
        userAgent: event.userAgent ?? null,
        reasonCode: event.reasonCode ?? null
      }
    });
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

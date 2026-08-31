import type { PrismaClient } from "@prisma/client";

const millisecondsPerDay = 24 * 60 * 60 * 1000;
const defaultAuditRetentionDays = 180;

export type AuditRetentionCleanupStore = {
  readonly countAuditLogsOlderThan: (cutoff: Date) => Promise<number>;
  readonly deleteAuditLogsOlderThan: (cutoff: Date) => Promise<number>;
};

export type AuditRetentionCleanupOptions = {
  readonly execute?: boolean;
  readonly now?: Date;
  readonly retentionDays?: number;
};

export type AuditRetentionCleanupResult = {
  readonly cutoff: Date;
  readonly deletedCount: number;
  readonly dryRun: boolean;
  readonly retentionDays: number;
};

export class AuditRetentionCleanupConfigurationError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "AuditRetentionCleanupConfigurationError";
  }
}

const cutoffForRetention = (now: Date, retentionDays: number): Date =>
  new Date(now.getTime() - retentionDays * millisecondsPerDay);

const assertRetentionDays = (retentionDays: number): void => {
  if (!Number.isInteger(retentionDays) || retentionDays < 1) {
    throw new AuditRetentionCleanupConfigurationError("retentionDays must be a positive integer");
  }
};

export const createPrismaAuditRetentionCleanupStore = (prisma: PrismaClient): AuditRetentionCleanupStore => ({
  countAuditLogsOlderThan: async (cutoff) =>
    prisma.auditLog.count({ where: { createdAt: { lt: cutoff } } }),
  deleteAuditLogsOlderThan: async (cutoff) => {
    const result = await prisma.auditLog.deleteMany({ where: { createdAt: { lt: cutoff } } });
    return result.count;
  }
});

export const cleanupAuditLogs = async (
  store: AuditRetentionCleanupStore,
  options: AuditRetentionCleanupOptions = {}
): Promise<AuditRetentionCleanupResult> => {
  const retentionDays = options.retentionDays ?? defaultAuditRetentionDays;
  assertRetentionDays(retentionDays);
  const cutoff = cutoffForRetention(options.now ?? new Date(), retentionDays);
  const dryRun = options.execute !== true;
  const deletedCount = dryRun
    ? await store.countAuditLogsOlderThan(cutoff)
    : await store.deleteAuditLogsOlderThan(cutoff);

  return {
    cutoff,
    deletedCount,
    dryRun,
    retentionDays
  };
};

import type { Prisma, PrismaClient } from "@prisma/client";

const millisecondsPerDay = 24 * 60 * 60 * 1000;

export type RefreshTokenCleanupStore = {
  readonly countRefreshTokensEligibleForCleanup: (cutoff: Date) => Promise<number>;
  readonly deleteRefreshTokensEligibleForCleanup: (cutoff: Date) => Promise<number>;
};

export type RefreshTokenCleanupOptions = {
  readonly dryRun: boolean;
  readonly now?: Date;
  readonly retentionDays: number;
};

export type RefreshTokenCleanupResult = {
  readonly cutoff: Date;
  readonly deletedCount: number;
  readonly dryRun: boolean;
  readonly retentionDays: number;
};

export class RefreshTokenCleanupConfigurationError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "RefreshTokenCleanupConfigurationError";
  }
}

const refreshTokenCleanupWhere = (cutoff: Date): Prisma.RefreshTokenWhereInput => ({
  OR: [
    { expiresAt: { lt: cutoff } },
    { revokedAt: { lt: cutoff } }
  ]
});

const cutoffForRetention = (now: Date, retentionDays: number): Date =>
  new Date(now.getTime() - retentionDays * millisecondsPerDay);

const assertRetentionDays = (retentionDays: number): void => {
  if (!Number.isInteger(retentionDays) || retentionDays < 1) {
    throw new RefreshTokenCleanupConfigurationError("retentionDays must be a positive integer");
  }
};

export const createPrismaRefreshTokenCleanupStore = (prisma: PrismaClient): RefreshTokenCleanupStore => ({
  countRefreshTokensEligibleForCleanup: async (cutoff) =>
    prisma.refreshToken.count({ where: refreshTokenCleanupWhere(cutoff) }),
  deleteRefreshTokensEligibleForCleanup: async (cutoff) => {
    const result = await prisma.refreshToken.deleteMany({ where: refreshTokenCleanupWhere(cutoff) });
    return result.count;
  }
});

export const cleanupRefreshTokens = async (
  store: RefreshTokenCleanupStore,
  options: RefreshTokenCleanupOptions
): Promise<RefreshTokenCleanupResult> => {
  assertRetentionDays(options.retentionDays);
  const cutoff = cutoffForRetention(options.now ?? new Date(), options.retentionDays);
  const deletedCount = options.dryRun
    ? await store.countRefreshTokensEligibleForCleanup(cutoff)
    : await store.deleteRefreshTokensEligibleForCleanup(cutoff);

  return {
    cutoff,
    deletedCount,
    dryRun: options.dryRun,
    retentionDays: options.retentionDays
  };
};

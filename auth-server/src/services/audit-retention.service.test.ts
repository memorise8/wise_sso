import { describe, expect, it } from "vitest";
import { cleanupAuditLogs } from "./audit-retention.service.js";
import type { AuditRetentionCleanupStore } from "./audit-retention.service.js";

type StoredAuditLog = {
  readonly id: string;
  readonly createdAt: Date;
  readonly detailsJson: Record<string, string> | null;
};

type TestStore = AuditRetentionCleanupStore & {
  readonly logs: () => readonly StoredAuditLog[];
  readonly deletedCutoffs: () => readonly Date[];
};

const fixedNow = new Date("2026-07-23T00:00:00.000Z");
const oldDate = new Date("2026-01-01T00:00:00.000Z");
const cutoffDate = new Date("2026-01-24T00:00:00.000Z");
const recentDate = new Date("2026-07-01T00:00:00.000Z");

const createStore = (initialLogs: readonly StoredAuditLog[]): TestStore => {
  const logs = [...initialLogs];
  const deletedCutoffs: Date[] = [];

  return {
    logs: () => logs,
    deletedCutoffs: () => deletedCutoffs,
    countAuditLogsOlderThan: async (cutoff) =>
      logs.filter((log) => log.createdAt < cutoff).length,
    deleteAuditLogsOlderThan: async (cutoff) => {
      deletedCutoffs.push(cutoff);
      const deletedCount = logs.filter((log) => log.createdAt < cutoff).length;
      for (let index = logs.length - 1; index >= 0; index -= 1) {
        const log = logs[index];
        if (log && log.createdAt < cutoff) {
          logs.splice(index, 1);
        }
      }
      return deletedCount;
    }
  };
};

describe("audit retention cleanup service", () => {
  it("Given audit logs older than retention When cleanup runs in dry-run mode Then it reports the count without deleting rows", async () => {
    const store = createStore([
      { id: "old-audit", createdAt: oldDate, detailsJson: { accessToken: "raw-access-token" } },
      { id: "cutoff-audit", createdAt: cutoffDate, detailsJson: null },
      { id: "recent-audit", createdAt: recentDate, detailsJson: null }
    ]);

    const result = await cleanupAuditLogs(store, {
      now: fixedNow,
      retentionDays: 180
    });

    expect(result).toEqual({
      deletedCount: 1,
      dryRun: true,
      cutoff: cutoffDate,
      retentionDays: 180
    });
    expect(store.logs().map((log) => log.id)).toEqual(["old-audit", "cutoff-audit", "recent-audit"]);
    expect(store.deletedCutoffs()).toEqual([]);
  });

  it("Given audit logs older than retention When cleanup runs with execute Then it deletes only rows older than cutoff", async () => {
    const store = createStore([
      { id: "old-audit", createdAt: oldDate, detailsJson: { refreshToken: "raw-refresh-token" } },
      { id: "cutoff-audit", createdAt: cutoffDate, detailsJson: null },
      { id: "recent-audit", createdAt: recentDate, detailsJson: null }
    ]);

    const result = await cleanupAuditLogs(store, {
      execute: true,
      now: fixedNow,
      retentionDays: 180
    });

    expect(result.deletedCount).toBe(1);
    expect(result.dryRun).toBe(false);
    expect(result.cutoff).toEqual(cutoffDate);
    expect(store.logs().map((log) => log.id)).toEqual(["cutoff-audit", "recent-audit"]);
    expect(store.deletedCutoffs()).toEqual([cutoffDate]);
  });

  it("Given invalid retention input When audit cleanup is configured Then it rejects before deleting rows", async () => {
    const store = createStore([
      { id: "old-audit", createdAt: oldDate, detailsJson: { email: "person@example.test" } }
    ]);

    await expect(cleanupAuditLogs(store, {
      execute: true,
      now: fixedNow,
      retentionDays: 0
    })).rejects.toMatchObject({
      name: "AuditRetentionCleanupConfigurationError",
      message: "retentionDays must be a positive integer"
    });
    expect(store.logs().map((log) => log.id)).toEqual(["old-audit"]);
    expect(store.deletedCutoffs()).toEqual([]);
  });
});

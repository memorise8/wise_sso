import { PrismaClient } from "@prisma/client";
import dotenv from "dotenv";
import { z } from "zod";
import {
  AuditRetentionCleanupConfigurationError,
  cleanupAuditLogs,
  createPrismaAuditRetentionCleanupStore
} from "../services/audit-retention.service.js";

dotenv.config();

type CleanupCliOptions = {
  readonly execute: boolean;
  readonly retentionDays: number;
};

const cliOptionsSchema = z.object({
  execute: z.boolean(),
  retentionDays: z.coerce.number().int().positive().default(180)
});

const readRetentionDays = (value: string | undefined): number =>
  cliOptionsSchema.shape.retentionDays.parse(value ?? "180");

const parseArgs = (argv: readonly string[]): CleanupCliOptions => {
  let execute = false;
  let retentionDays = readRetentionDays(undefined);

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--execute") {
      execute = true;
      continue;
    }

    if (arg === "--retention-days") {
      const value = argv[index + 1];
      if (!value) {
        throw new AuditRetentionCleanupConfigurationError("--retention-days requires a value");
      }
      retentionDays = readRetentionDays(value);
      index += 1;
      continue;
    }

    if (arg?.startsWith("--retention-days=")) {
      retentionDays = readRetentionDays(arg.slice("--retention-days=".length));
      continue;
    }

    throw new AuditRetentionCleanupConfigurationError(`Unknown option: ${arg ?? ""}`);
  }

  return cliOptionsSchema.parse({ execute, retentionDays });
};

const main = async (): Promise<void> => {
  const options = parseArgs(process.argv.slice(2));
  const prisma = new PrismaClient();

  try {
    const result = await cleanupAuditLogs(createPrismaAuditRetentionCleanupStore(prisma), options);
    const action = result.dryRun ? "dry-run" : "deleted";
    console.log(`audit-log-cleanup ${action} count=${result.deletedCount} cutoff=${result.cutoff.toISOString()}`);
  } finally {
    await prisma.$disconnect();
  }
};

main().catch((error: unknown) => {
  if (error instanceof Error) {
    console.error(`audit-log-cleanup failed: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  console.error("audit-log-cleanup failed with an unknown error");
  process.exitCode = 1;
});

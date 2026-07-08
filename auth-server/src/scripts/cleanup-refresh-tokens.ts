import { PrismaClient } from "@prisma/client";
import dotenv from "dotenv";
import { z } from "zod";
import {
  cleanupRefreshTokens,
  createPrismaRefreshTokenCleanupStore,
  RefreshTokenCleanupConfigurationError
} from "../services/token-cleanup.service.js";

dotenv.config();

type CleanupCliOptions = {
  readonly dryRun: boolean;
  readonly retentionDays: number;
};

const cliOptionsSchema = z.object({
  dryRun: z.boolean(),
  retentionDays: z.coerce.number().int().positive()
});

const readRetentionDays = (value: string | undefined): number => cliOptionsSchema.shape.retentionDays.parse(value ?? "30");

const parseArgs = (argv: readonly string[], env: NodeJS.ProcessEnv): CleanupCliOptions => {
  let dryRun = false;
  let retentionDays = readRetentionDays(env["REFRESH_TOKEN_CLEANUP_RETENTION_DAYS"]);

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--dry-run") {
      dryRun = true;
      continue;
    }

    if (arg === "--retention-days") {
      const value = argv[index + 1];
      if (!value) {
        throw new RefreshTokenCleanupConfigurationError("--retention-days requires a value");
      }
      retentionDays = readRetentionDays(value);
      index += 1;
      continue;
    }

    if (arg?.startsWith("--retention-days=")) {
      retentionDays = readRetentionDays(arg.slice("--retention-days=".length));
      continue;
    }

    throw new RefreshTokenCleanupConfigurationError(`Unknown option: ${arg ?? ""}`);
  }

  return cliOptionsSchema.parse({ dryRun, retentionDays });
};

const main = async (): Promise<void> => {
  const options = parseArgs(process.argv.slice(2), process.env);
  const prisma = new PrismaClient();

  try {
    const result = await cleanupRefreshTokens(createPrismaRefreshTokenCleanupStore(prisma), options);
    const action = result.dryRun ? "would delete" : "deleted";
    console.log(
      `refresh-token-cleanup ${action} ${result.deletedCount} token rows older than ${result.cutoff.toISOString()} ` +
        `(retentionDays=${result.retentionDays})`
    );
  } finally {
    await prisma.$disconnect();
  }
};

main().catch((error: unknown) => {
  if (error instanceof Error) {
    console.error(`refresh-token-cleanup failed: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  console.error("refresh-token-cleanup failed with an unknown error");
  process.exitCode = 1;
});

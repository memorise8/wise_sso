import { PrismaClient, Prisma } from "@prisma/client";
import dotenv from "dotenv";
import { backfillRolelessUsersWithDefaultRole } from "../services/user.service.js";

dotenv.config();

class BackfillDefaultRolesCliError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "BackfillDefaultRolesCliError";
  }
}

const maxSerializationRetries = 3;

const assertNoArgs = (argv: readonly string[]): void => {
  if (argv.length > 0) {
    throw new BackfillDefaultRolesCliError("backfill-default-roles does not accept arguments");
  }
};

const isSerializationConflict = (error: unknown): boolean =>
  error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2034";

const runBackfill = async (prisma: PrismaClient) => {
  for (let attempt = 1; attempt <= maxSerializationRetries; attempt += 1) {
    try {
      return await prisma.$transaction(
        async (transaction) => backfillRolelessUsersWithDefaultRole(transaction),
        { isolationLevel: Prisma.TransactionIsolationLevel.Serializable }
      );
    } catch (error) {
      if (!isSerializationConflict(error) || attempt === maxSerializationRetries) {
        throw error;
      }
    }
  }

  throw new BackfillDefaultRolesCliError("backfill retry limit exceeded");
};

const main = async (): Promise<void> => {
  assertNoArgs(process.argv.slice(2));
  const prisma = new PrismaClient();

  try {
    const result = await runBackfill(prisma);
    console.log(
      `backfill-default-roles success defaultRole=${result.defaultRole.serviceKey}:${result.defaultRole.name} ` +
        `rolelessUserCount=${result.rolelessUserCount} assignedUserRoleCount=${result.assignedUserRoleCount}`
    );
  } finally {
    await prisma.$disconnect();
  }
};

main().catch((error: unknown) => {
  if (error instanceof Error) {
    console.error(`backfill-default-roles failed: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  console.error("backfill-default-roles failed with an unknown error");
  process.exitCode = 1;
});

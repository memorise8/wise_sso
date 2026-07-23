import { PrismaClient } from "@prisma/client";
import dotenv from "dotenv";
import { z } from "zod";
import { createPrismaAdminUserMutationStore } from "../services/admin-user.store.js";
import { grantFirstAdmin } from "../services/first-admin-provisioning.service.js";

dotenv.config();

type GrantAdminCliOptions = {
  readonly email: string;
};

class GrantAdminConfigurationError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "GrantAdminConfigurationError";
  }
}

const cliOptionsSchema = z.object({
  email: z.string().trim().email()
});

const parseArgs = (argv: readonly string[]): GrantAdminCliOptions => {
  let email: string | undefined;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--email") {
      const value = argv[index + 1];
      if (!value) {
        throw new GrantAdminConfigurationError("--email requires a value");
      }
      email = value;
      index += 1;
      continue;
    }

    if (arg?.startsWith("--email=")) {
      email = arg.slice("--email=".length);
      continue;
    }

    throw new GrantAdminConfigurationError(`Unknown option: ${arg ?? ""}`);
  }

  if (!email) {
    throw new GrantAdminConfigurationError("--email is required");
  }

  return cliOptionsSchema.parse({ email });
};

const main = async (): Promise<void> => {
  const options = parseArgs(process.argv.slice(2));
  const prisma = new PrismaClient();

  try {
    const result = await grantFirstAdmin(createPrismaAdminUserMutationStore(prisma), { email: options.email });
    console.log(
      `grant-admin success userId=${result.userId} roleAssigned=${result.roleAssigned} ` +
        `revokedRefreshTokenCount=${result.revokedRefreshTokenCount} reasonCode=OPS_BOOTSTRAP_ADMIN`
    );
  } finally {
    await prisma.$disconnect();
  }
};

main().catch((error: unknown) => {
  if (error instanceof Error) {
    console.error(`grant-admin failed: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  console.error("grant-admin failed with an unknown error");
  process.exitCode = 1;
});

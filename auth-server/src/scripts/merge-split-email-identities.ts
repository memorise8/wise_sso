import { randomUUID } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import dotenv from "dotenv";
import { z } from "zod";

dotenv.config();

type SplitAccountCandidate = {
  readonly email: string;
  readonly canonicalUserId: string;
  readonly passwordUserId: string;
  readonly provider: string;
  readonly providerUserId: string;
};

type CliOptions = {
  readonly apply: boolean;
  readonly email: string | null;
};

class MergeSplitIdentityCliError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "MergeSplitIdentityCliError";
  }
}

const cliOptionsSchema = z.object({
  apply: z.boolean(),
  email: z.string().trim().email().nullable()
});

const parseArgs = (argv: readonly string[]): CliOptions => {
  let apply = false;
  let email: string | null = null;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--apply") {
      apply = true;
      continue;
    }

    if (arg === "--email") {
      const value = argv[index + 1];
      if (!value) {
        throw new MergeSplitIdentityCliError("--email requires a value");
      }
      email = value.toLowerCase();
      index += 1;
      continue;
    }

    if (arg?.startsWith("--email=")) {
      email = arg.slice("--email=".length).toLowerCase();
      continue;
    }

    throw new MergeSplitIdentityCliError(`Unknown option: ${arg ?? ""}`);
  }

  return cliOptionsSchema.parse({ apply, email });
};

const findCandidates = async (prisma: PrismaClient, email: string | null): Promise<readonly SplitAccountCandidate[]> =>
  prisma.$queryRaw<SplitAccountCandidate[]>`
    SELECT
      lower(pc."email") AS "email",
      sa."userId" AS "canonicalUserId",
      pc."userId" AS "passwordUserId",
      sa."provider" AS "provider",
      sa."providerUserId" AS "providerUserId"
    FROM "PasswordCredential" pc
    JOIN "SocialAccount" sa ON lower(sa."providerEmail") = lower(pc."email")
    JOIN "User" canonical_user ON canonical_user."id" = sa."userId"
    JOIN "User" password_user ON password_user."id" = pc."userId"
    WHERE sa."provider" = 'google'
      AND sa."userId" <> pc."userId"
      AND canonical_user."status" = 'ACTIVE'
      AND canonical_user."emailVerified" = true
      AND password_user."emailVerified" = true
      AND NOT EXISTS (
        SELECT 1 FROM "PasswordCredential" existing_pc WHERE existing_pc."userId" = sa."userId"
      )
      AND (${email}::text IS NULL OR lower(pc."email") = lower(${email}::text))
    ORDER BY lower(pc."email")
  `;

const mergeCandidate = async (prisma: PrismaClient, candidate: SplitAccountCandidate): Promise<void> => {
  await prisma.$transaction(async (transaction) => {
    await transaction.user.update({
      where: { id: candidate.passwordUserId },
      data: { email: null }
    });
    await transaction.user.update({
      where: { id: candidate.canonicalUserId },
      data: {
        email: candidate.email,
        emailVerified: true
      }
    });
    await transaction.passwordCredential.update({
      where: { userId: candidate.passwordUserId },
      data: { userId: candidate.canonicalUserId }
    });
    await transaction.auditLog.create({
      data: {
        id: randomUUID(),
        eventType: "identity_merge",
        outcome: "success",
        provider: candidate.provider,
        userId: candidate.canonicalUserId,
        targetUserId: candidate.passwordUserId,
        reasonCode: "OPS_MERGE_SPLIT_EMAIL_IDENTITIES",
        detailsJson: {
          email: candidate.email,
          providerUserId: candidate.providerUserId,
          canonicalUserId: candidate.canonicalUserId,
          mergedPasswordUserId: candidate.passwordUserId
        }
      }
    });
    await transaction.user.delete({
      where: { id: candidate.passwordUserId }
    });
  });
};

const main = async (): Promise<void> => {
  const options = parseArgs(process.argv.slice(2));
  const prisma = new PrismaClient();

  try {
    const candidates = await findCandidates(prisma, options.email);
    if (!options.apply) {
      console.log(JSON.stringify({ mode: "dry-run", count: candidates.length, candidates }, null, 2));
      return;
    }

    for (const candidate of candidates) {
      await mergeCandidate(prisma, candidate);
    }
    console.log(JSON.stringify({ mode: "apply", mergedCount: candidates.length }, null, 2));
  } finally {
    await prisma.$disconnect();
  }
};

main().catch((error: unknown) => {
  if (error instanceof Error) {
    console.error(`merge-split-email-identities failed: ${error.message}`);
    process.exitCode = 1;
    return;
  }

  console.error("merge-split-email-identities failed with an unknown error");
  process.exitCode = 1;
});

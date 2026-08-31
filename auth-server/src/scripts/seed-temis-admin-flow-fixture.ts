import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PrismaClient } from "@prisma/client";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";

type FixtureUser = {
  readonly id: string;
  readonly email: string;
  readonly emailVerified: boolean;
  readonly name: string;
  readonly roles: readonly {
    readonly serviceKey: string;
    readonly name: string;
  }[];
};

class QaFixtureError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "QaFixtureError";
  }
}

const fixtureUsers = {
  admin: {
    id: "00000000-0000-4000-8000-000000000801",
    email: "qa-admin@temis.example.test",
    emailVerified: true,
    name: "QA Admin",
    roles: [{ serviceKey: "temis", name: "admin" }]
  },
  target: {
    id: "00000000-0000-4000-8000-000000000802",
    email: "qa-target@temis.example.test",
    emailVerified: true,
    name: "QA Target",
    roles: [{ serviceKey: "temis", name: "user" }]
  },
  nonAdmin: {
    id: "00000000-0000-4000-8000-000000000803",
    email: "qa-non-admin@temis.example.test",
    emailVerified: true,
    name: "QA Non Admin",
    roles: [{ serviceKey: "temis", name: "user" }]
  }
} as const;

const evidenceRelativePath = ".omo/evidence/temis-sso-p0-auth-hardening/qa-fixture.env";
const tokenExpiresAt = new Date("2027-07-22T00:00:00.000Z");
const targetRefreshTokenId = "00000000-0000-4000-8000-000000000804";

const hashToken = (token: string): string => createHash("sha256").update(token).digest("hex");

const redactToken = (label: string, token: string): string => {
  const proofPrefix = hashToken(token).slice(0, 12);
  return `REDACTED_${label}_SHA256_PREFIX_${proofPrefix}`;
};

const readRequiredEnv = (key: string): string => {
  const value = process.env[key];
  if (!value) {
    throw new QaFixtureError(`${key} is required`);
  }
  return value;
};

const readAccessAlgorithm = (): "RS256" => {
  const algorithm = readRequiredEnv("JWT_ACCESS_ALGORITHM");
  if (algorithm !== "RS256") {
    throw new QaFixtureError("JWT_ACCESS_ALGORITHM must be RS256");
  }
  return algorithm;
};

const readAccessPrivateKey = (): string => readRequiredEnv("JWT_ACCESS_PRIVATE_KEY").replace(/\\n/g, "\n");

const findRepoRoot = (startDirectory: string): string => {
  let directory = startDirectory;
  while (!existsSync(path.join(directory, ".git"))) {
    const parent = path.dirname(directory);
    if (parent === directory) {
      throw new QaFixtureError("Unable to find repository root");
    }
    directory = parent;
  }
  return directory;
};

export const createAccessToken = (user: FixtureUser): string => jwt.sign({
  sub: user.id,
  email: user.email,
  email_verified: user.emailVerified,
  name: user.name,
  roles: user.roles,
  type: "access",
  iss: readRequiredEnv("JWT_ISSUER"),
  aud: readRequiredEnv("JWT_AUDIENCE"),
  exp: Math.floor(tokenExpiresAt.getTime() / 1000)
}, readAccessPrivateKey(), {
  algorithm: readAccessAlgorithm(),
  keyid: readRequiredEnv("JWT_ACCESS_KEY_ID"),
  noTimestamp: true
});

const createTargetRefreshToken = (): string => jwt.sign({
  sub: fixtureUsers.target.id,
  type: "refresh",
  tokenId: targetRefreshTokenId,
  exp: Math.floor(tokenExpiresAt.getTime() / 1000)
}, readRequiredEnv("JWT_REFRESH_SECRET"), { noTimestamp: true });

const main = async (): Promise<void> => {
  dotenv.config();

  if (process.env["NODE_ENV"] === "production") {
    throw new QaFixtureError("qa fixture seeding is not allowed in production");
  }

  const prisma = new PrismaClient();
  const targetRefreshToken = createTargetRefreshToken();

  try {
    await prisma.$transaction(async (transaction) => {
      await transaction.user.deleteMany({
        where: {
          OR: [
            { id: { in: Object.values(fixtureUsers).map((user) => user.id) } },
            { email: { in: Object.values(fixtureUsers).map((user) => user.email) } }
          ]
        }
      });

      const adminRole = await transaction.role.upsert({
        where: { serviceKey_name: { serviceKey: "temis", name: "admin" } },
        create: { serviceKey: "temis", name: "admin" },
        update: {}
      });
      const userRole = await transaction.role.upsert({
        where: { serviceKey_name: { serviceKey: "temis", name: "user" } },
        create: { serviceKey: "temis", name: "user" },
        update: {}
      });

      await transaction.user.createMany({
        data: Object.values(fixtureUsers).map((user) => ({
          id: user.id,
          email: user.email,
          emailVerified: user.emailVerified,
          name: user.name,
          status: "ACTIVE"
        }))
      });
      await transaction.userRole.createMany({
        data: [
          { userId: fixtureUsers.admin.id, roleId: adminRole.id },
          { userId: fixtureUsers.target.id, roleId: userRole.id },
          { userId: fixtureUsers.nonAdmin.id, roleId: userRole.id }
        ]
      });
      await transaction.refreshToken.create({
        data: {
          id: targetRefreshTokenId,
          userId: fixtureUsers.target.id,
          tokenHash: hashToken(targetRefreshToken),
          expiresAt: tokenExpiresAt
        }
      });
    });

    const adminAccessToken = createAccessToken(fixtureUsers.admin);
    const targetAccessToken = createAccessToken(fixtureUsers.target);
    const nonAdminAccessToken = createAccessToken(fixtureUsers.nonAdmin);
    const fixtureEnv = [
      `ADMIN_ACCESS_TOKEN=${redactToken("ADMIN_ACCESS_TOKEN", adminAccessToken)}`,
      `TARGET_ACCESS_TOKEN=${redactToken("TARGET_ACCESS_TOKEN", targetAccessToken)}`,
      `TARGET_USER_ID=${fixtureUsers.target.id}`,
      `TARGET_REFRESH_TOKEN=${redactToken("TARGET_REFRESH_TOKEN", targetRefreshToken)}`,
      `NON_ADMIN_ACCESS_TOKEN=${redactToken("NON_ADMIN_ACCESS_TOKEN", nonAdminAccessToken)}`,
      "TOKEN_VALUES_REDACTED=true",
      `TARGET_REFRESH_TOKEN_ID=${targetRefreshTokenId}`,
      ""
    ].join("\n");
    const fixturePath = path.join(findRepoRoot(process.cwd()), evidenceRelativePath);
    await mkdir(path.dirname(fixturePath), { recursive: true });
    await writeFile(fixturePath, fixtureEnv, { mode: 0o600 });
    await chmod(fixturePath, 0o600);

    console.log(`qa-fixture wrote ${fixturePath}`);
    console.log(`ADMIN_ACCESS_TOKEN=${redactToken("ADMIN_ACCESS_TOKEN", adminAccessToken)}`);
    console.log(`TARGET_ACCESS_TOKEN=${redactToken("TARGET_ACCESS_TOKEN", targetAccessToken)}`);
    console.log(`TARGET_USER_ID=${fixtureUsers.target.id}`);
    console.log(`TARGET_REFRESH_TOKEN=${redactToken("TARGET_REFRESH_TOKEN", targetRefreshToken)}`);
    console.log(`NON_ADMIN_ACCESS_TOKEN=${redactToken("NON_ADMIN_ACCESS_TOKEN", nonAdminAccessToken)}`);
    console.log("TOKEN_VALUES_REDACTED=true");
  } finally {
    await prisma.$disconnect();
  }
};

const entrypoint = process.argv[1];
if (entrypoint !== undefined && import.meta.url === pathToFileURL(path.resolve(entrypoint)).href) {
  main().catch((error: unknown) => {
    if (error instanceof Error) {
      console.error(`qa-fixture failed: ${error.message}`);
      process.exitCode = 1;
      return;
    }

    console.error("qa-fixture failed with an unknown error");
    process.exitCode = 1;
  });
}

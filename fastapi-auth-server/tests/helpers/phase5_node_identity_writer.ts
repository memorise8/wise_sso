import { createHash } from "node:crypto";

type Profile = {
  readonly provider: "google" | "naver" | "kakao";
  readonly providerUserId: string;
  readonly email: string | null;
  readonly emailVerified: boolean;
  readonly name: string | null;
  readonly profileUrl: string | null;
};

type Input = {
  readonly profile: Profile;
  readonly clientId: string;
  readonly startAtEpochMs: number;
};

const sleep = async (milliseconds: number): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
};

const safeHash = (value: string): string => createHash("sha256").update(value).digest("hex");
const controlledPrismaCodes = new Set(["P2002", "P2028", "P2034"]);

const finish = (value: object, status: number = 0): never => {
  process.stdout.write(`${JSON.stringify(value)}\n`);
  process.exit(status);
};

const failRedacted = (error: unknown): never => {
  const code = typeof error === "object" && error !== null && "code" in error
    ? String(error.code)
    : "";
  if (controlledPrismaCodes.has(code)) {
    finish({ status: "controlled-conflict", code });
  }
  const type = error instanceof Error && /^[A-Za-z0-9_]{1,64}$/.test(error.name)
    ? error.name
    : "Error";
  finish({ status: "unexpected", type }, 1);
};

const main = async (): Promise<void> => {
  const databaseUrl = process.env.WISEACCT_PHASE5_NODE_DATABASE_URL ?? "";
  const parsedDatabase = new URL(databaseUrl);
  if (
    parsedDatabase.protocol !== "postgresql:"
    || parsedDatabase.hostname !== "127.0.0.1"
    || parsedDatabase.port !== "5433"
    || !parsedDatabase.pathname.includes("_test_")
  ) {
    throw new Error("Phase 5 Node writer requires a disposable localhost _test_ database");
  }
  process.env.DATABASE_URL = databaseUrl;
  process.env.NODE_ENV = "test";

  const input = JSON.parse(process.argv[2] ?? "null") as Input;
  if (!input || !Number.isSafeInteger(input.startAtEpochMs) || input.startAtEpochMs <= Date.now()) {
    throw new Error("Phase 5 Node writer requires a future synchronized start time");
  }
  const { findOrCreateUserBySocialProfile } = await import(
    "../../../auth-server/src/services/user.service.ts"
  );
  await sleep(Math.max(0, input.startAtEpochMs - Date.now()));
  const user = await findOrCreateUserBySocialProfile(input.profile, input.clientId);
  finish({ status: "ok", userIdSha256: safeHash(user.id) });
};

void main().catch(failRedacted);

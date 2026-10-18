const input = JSON.parse(process.argv[2] ?? "{}") as Record<string, unknown>;

const assertGuardedDatabase = (): void => {
  const runId = process.env.WISEACCT_PHASE6_RUN_ID ?? "";
  const rawUrl = process.env.DATABASE_URL ?? "";
  if (!/^[A-Za-z0-9_]+$/.test(runId)) {
    throw new Error("Phase 6 guard rejected the run identifier");
  }
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("Phase 6 guard rejected the database target");
  }
  const databaseName = decodeURIComponent(url.pathname.slice(1));
  const expectedDatabase = `fastapi_phase6_test_${runId}`;
  const expectedRole = `phase6_runtime_${runId}`;
  if (
    url.protocol !== "postgresql:" ||
    url.hostname !== "127.0.0.1" ||
    url.port !== "5433" ||
    decodeURIComponent(url.username) !== expectedRole ||
    decodeURIComponent(url.password) !== "synthetic-phase6-runtime-only" ||
    databaseName !== expectedDatabase ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new Error("Phase 6 guard rejected the database target");
  }
};

const main = async (): Promise<unknown> => {
  // Guard before importing any module that constructs a Prisma client.
  assertGuardedDatabase();
  const { createPrismaAdminUserMutationStore } = await import(
    "../../../auth-server/src/services/admin-user.store.ts"
  );
  const { createAdminUserService } = await import(
    "../../../auth-server/src/services/admin-user.service.ts"
  );
  const { listAdminUsers } = await import(
    "../../../auth-server/src/services/admin-directory.service.ts"
  );
  const { PrismaClient } = await import("../../../auth-server/node_modules/@prisma/client/default.js");
  const { z } = await import("../../../auth-server/node_modules/zod/index.js");
  const prisma = new PrismaClient();
  const service = createAdminUserService(createPrismaAdminUserMutationStore(prisma));
  const querySchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    pageSize: z.coerce.number().int().min(1).max(100).default(25),
    email: z.string().trim().min(1).optional(),
    createdAt: z.string().trim().min(1)
      .refine((value: string) => !Number.isNaN(Date.parse(value)))
      .transform((value: string) => new Date(value))
      .optional()
  });
  switch (input.command) {
    case "assign-role":
      return service.assignRole({
        actorUserId: String(input.actorUserId),
        targetUserId: String(input.targetUserId),
        serviceKey: String(input.serviceKey),
        name: String(input.name),
        reasonCode: String(input.reasonCode)
      });
    case "set-status":
      return service.setUserStatus({
        actorUserId: String(input.actorUserId),
        targetUserId: String(input.targetUserId),
        status: String(input.status),
        reasonCode: String(input.reasonCode)
      });
    case "remove-role":
      return service.removeRole({
        actorUserId: String(input.actorUserId),
        targetUserId: String(input.targetUserId),
        serviceKey: String(input.serviceKey),
        name: String(input.name),
        reasonCode: String(input.reasonCode)
      });
    case "revoke-sessions":
      return service.revokeSessions({
        actorUserId: String(input.actorUserId),
        targetUserId: String(input.targetUserId),
        reasonCode: String(input.reasonCode)
      });
    case "query-oracle": {
      const parsedResult = querySchema.safeParse(input.query);
      if (!parsedResult.success) {
        return { accepted: false };
      }
      const parsed = parsedResult.data;
      const page = await listAdminUsers({
        page: 1,
        pageSize: 100,
        ...(parsed.email ? { email: parsed.email } : {})
      });
      return {
        accepted: true,
        page: parsed.page,
        pageSize: parsed.pageSize,
        createdAt: parsed.createdAt?.toISOString() ?? null,
        emails: page.items.map((row) => row.email).sort()
      };
    }
    default:
      throw new Error("unsupported Phase 6 bridge command");
  }
};

void main().then((result) => {
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exit(0);
}).catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.name : "Error"}\n`);
  process.exit(1);
});

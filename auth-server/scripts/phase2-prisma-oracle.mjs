import { PrismaClient } from "@prisma/client";

const rawUrl = process.env.PHASE2_DATABASE_URL ?? "";
const url = new URL(rawUrl);
if (!["127.0.0.1", "localhost"].includes(url.hostname) || url.port !== "5433" || !url.pathname.includes("_test_")) {
  throw new Error("Phase 2 Prisma oracle requires a synthetic _test_ database on localhost:5433");
}

const prisma = new PrismaClient({ datasources: { db: { url: rawUrl } } });
const label = `phase2-prisma-${process.pid}`;
const email = `${label}@integration.invalid`;
const timestampFixture = new Date("2026-01-02T03:04:05.123Z");

try {
  const created = await prisma.user.create({ data: { email } });
  if (!/^[0-9a-f-]{36}$/.test(created.id)) throw new Error("Prisma UUID default mismatch");

  await new Promise((resolve) => setTimeout(resolve, 10));
  const updated = await prisma.user.update({ where: { id: created.id }, data: { name: label } });
  if (updated.updatedAt.getTime() <= created.updatedAt.getTime()) throw new Error("updatedAt did not advance on update");

  await new Promise((resolve) => setTimeout(resolve, 10));
  const updateMany = await prisma.user.updateMany({ where: { id: created.id }, data: { profileUrl: "phase2" } });
  if (updateMany.count !== 1) throw new Error("Prisma updateMany rowcount mismatch");
  const afterUpdateMany = await prisma.user.findUniqueOrThrow({ where: { id: created.id } });
  if (afterUpdateMany.updatedAt.getTime() <= updated.updatedAt.getTime()) {
    throw new Error("updatedAt did not advance on updateMany");
  }

  let notFound = false;
  try {
    await prisma.user.update({ where: { id: `${created.id}-missing` }, data: { name: "missing" } });
  } catch (error) {
    notFound = error?.code === "P2025";
  }
  if (!notFound) throw new Error("Prisma not-found semantics mismatch");

  await prisma.passwordCredential.create({
    data: { userId: created.id, email, passwordHash: "synthetic-phase2-only" }
  });
  await prisma.user.delete({ where: { id: created.id } });
  const cascaded = await prisma.passwordCredential.count({ where: { userId: created.id } });
  if (cascaded !== 0) throw new Error("Prisma cascade semantics mismatch");

  const timestampRow = await prisma.subjectReservation.create({
    data: {
      email: `${label}-timestamp@integration.invalid`,
      subjectId: `${label}-timestamp`,
      updatedAt: timestampFixture
    }
  });
  if (timestampRow.updatedAt.toISOString() !== timestampFixture.toISOString()) {
    throw new Error("Prisma TIMESTAMP(3) roundtrip mismatch");
  }

  process.stdout.write(JSON.stringify({
    provisional: true,
    uuidDefault: "pass",
    updatedAtCreateIso: created.updatedAt.toISOString(),
    updatedAtUpdateIso: updated.updatedAt.toISOString(),
    updatedAtUpdateManyIso: afterUpdateMany.updatedAt.toISOString(),
    updateManyRowcount: "pass",
    notFound: "P2025",
    cascade: "pass",
    timestamp3FixtureId: timestampRow.id,
    timestamp3Iso: timestampRow.updatedAt.toISOString(),
    timestamp3Milliseconds: timestampRow.updatedAt.getUTCMilliseconds()
  }) + "\n");
} finally {
  await prisma.user.deleteMany({ where: { email } }).catch(() => undefined);
  await prisma.$disconnect();
}

import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export type ReadinessCheck = () => Promise<boolean>;

export const checkPostgresReadiness: ReadinessCheck = async () => {
  const isReady = await prisma.$queryRaw`SELECT 1`.then(
    () => true,
    () => false
  );
  return isReady;
};

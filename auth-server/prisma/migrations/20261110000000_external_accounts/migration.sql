-- Additive: time-limited external accounts. No existing row changes.
ALTER TYPE "UserType" ADD VALUE IF NOT EXISTS 'EXTERNAL';
ALTER TABLE "User" ADD COLUMN "accountExpiresAt" TIMESTAMP(3);
CREATE INDEX "User_accountExpiresAt_idx" ON "User"("accountExpiresAt");

ALTER TABLE "EmployeeInvitation"
  ADD COLUMN "kind" TEXT NOT NULL DEFAULT 'EMPLOYEE' CHECK ("kind" IN ('EMPLOYEE','EXTERNAL')),
  ADD COLUMN "accountExpiresAt" TIMESTAMP(3),
  ADD CONSTRAINT "EmployeeInvitation_external_expiry_check"
    CHECK (("kind" = 'EXTERNAL') = ("accountExpiresAt" IS NOT NULL));

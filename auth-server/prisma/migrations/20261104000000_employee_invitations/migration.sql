CREATE TABLE "EmployeeInvitation" (
 "id" TEXT PRIMARY KEY,
 "email" TEXT NOT NULL,
 "name" TEXT NOT NULL,
 "roles" JSONB NOT NULL,
 "tokenHash" TEXT NOT NULL UNIQUE,
 "status" TEXT NOT NULL DEFAULT 'PENDING' CHECK ("status" IN ('PENDING','CANCELLED','ACCEPTED')),
 "expiresAt" TIMESTAMP(3) NOT NULL,
 "deliveredAt" TIMESTAMP(3),
 "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
 "updatedAt" TIMESTAMP(3) NOT NULL
);
CREATE INDEX "EmployeeInvitation_email_idx" ON "EmployeeInvitation"("email");
CREATE INDEX "EmployeeInvitation_status_expiresAt_idx" ON "EmployeeInvitation"("status","expiresAt");

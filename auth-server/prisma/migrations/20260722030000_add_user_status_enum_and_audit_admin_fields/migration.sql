CREATE TYPE "UserStatus" AS ENUM (
    'PENDING_EMAIL_VERIFICATION',
    'ACTIVE',
    'SUSPENDED',
    'DELETED'
);

ALTER TABLE "User" ALTER COLUMN "status" DROP DEFAULT;

ALTER TABLE "User"
ALTER COLUMN "status" TYPE "UserStatus"
USING (
    CASE "status"
        WHEN 'pending_verification' THEN 'PENDING_EMAIL_VERIFICATION'
        WHEN 'active' THEN 'ACTIVE'
        WHEN 'suspended' THEN 'SUSPENDED'
        WHEN 'deleted' THEN 'DELETED'
        ELSE "status"
    END::"UserStatus"
);

ALTER TABLE "User" ALTER COLUMN "status" SET DEFAULT 'ACTIVE';

ALTER TABLE "AuditLog" ADD COLUMN "actorUserId" TEXT;
ALTER TABLE "AuditLog" ADD COLUMN "targetUserId" TEXT;
ALTER TABLE "AuditLog" ADD COLUMN "detailsJson" JSONB;

CREATE INDEX "AuditLog_actorUserId_idx" ON "AuditLog"("actorUserId");
CREATE INDEX "AuditLog_targetUserId_idx" ON "AuditLog"("targetUserId");

ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_actorUserId_fkey" FOREIGN KEY ("actorUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_targetUserId_fkey" FOREIGN KEY ("targetUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

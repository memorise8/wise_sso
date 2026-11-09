-- Operator-only backfill. Do not run automatically or from deployment migrations.
BEGIN;
LOCK TABLE "User", "UserRole", "Role" IN SHARE ROW EXCLUSIVE MODE;
WITH changed AS (
 UPDATE "User" u SET "userType"=(CASE WHEN EXISTS (
  SELECT 1 FROM "UserRole" ur JOIN "Role" r ON r.id=ur."roleId"
  WHERE ur."userId"=u.id AND (
   r."serviceKey" IN ('gitlab','agent-hub','lab-staff','sso') OR
   (r."serviceKey"='temis' AND r.name='admin')
  )
 ) THEN 'EMPLOYEE' ELSE 'CUSTOMER' END)::"UserType",
 "updatedAt"=CURRENT_TIMESTAMP,"ssoSessionVersion"="ssoSessionVersion"+1
 WHERE u."userType" IS NULL RETURNING id,"userType"
), revoked AS (
 UPDATE "RefreshToken" t SET "revokedAt"=CURRENT_TIMESTAMP
 WHERE t."userId" IN (SELECT id FROM changed) AND t."revokedAt" IS NULL
)
INSERT INTO "AuditLog" (id,"eventType",outcome,"userId","targetUserId","reasonCode","detailsJson","createdAt")
SELECT gen_random_uuid()::text,'admin_user_type_changed','success',NULL,id,'OPERATOR_USER_TYPE_BACKFILL',
 jsonb_build_object('previousUserType',NULL,'userType',"userType"),CURRENT_TIMESTAMP FROM changed;
COMMIT;

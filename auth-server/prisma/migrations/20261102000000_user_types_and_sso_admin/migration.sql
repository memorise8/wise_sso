-- Additive schema change, with an atomic, audited additive administrator grant.
BEGIN;
CREATE TYPE "UserType" AS ENUM ('EMPLOYEE', 'CUSTOMER');
ALTER TABLE "User" ADD COLUMN "userType" "UserType";
CREATE INDEX "User_userType_idx" ON "User"("userType");

-- Never infer employee status from email or the public temis:user role.
WITH employees AS (
  UPDATE "User" u SET "userType"='EMPLOYEE', "updatedAt"=CURRENT_TIMESTAMP
  WHERE EXISTS (
    SELECT 1 FROM "UserRole" ur JOIN "Role" r ON r.id=ur."roleId"
    WHERE ur."userId"=u.id AND (
      (r."serviceKey"='temis' AND r.name='admin') OR
      (r."serviceKey" IN ('gitlab','agent-hub','lab-staff') AND r.name='user')
    )
  ) RETURNING id
)
INSERT INTO "AuditLog" (id,"eventType",outcome,"userId","targetUserId","reasonCode","detailsJson","createdAt")
SELECT gen_random_uuid()::text,'admin_user_type_changed','success',NULL,id,'POLICY_MIGRATION',
       '{"previousUserType":null,"userType":"EMPLOYEE"}'::jsonb,CURRENT_TIMESTAMP FROM employees;

INSERT INTO "Role" (id,"serviceKey",name)
VALUES ('d548b2a9-65b3-416d-971b-9140a02404fe','sso','admin')
ON CONFLICT ("serviceKey",name) DO NOTHING;
WITH old_admins AS (
 SELECT DISTINCT ur."userId" FROM "UserRole" ur JOIN "Role" r ON r.id=ur."roleId"
 WHERE r."serviceKey"='temis' AND r.name='admin'
), migrated AS (
 INSERT INTO "UserRole" (id,"userId","roleId")
 SELECT gen_random_uuid()::text,a."userId",r.id FROM old_admins a,"Role" r
 WHERE r."serviceKey"='sso' AND r.name='admin'
 ON CONFLICT ("userId","roleId") DO NOTHING RETURNING "userId"
)
INSERT INTO "AuditLog" (id,"eventType",outcome,"userId","targetUserId","reasonCode","detailsJson","createdAt")
SELECT gen_random_uuid()::text,'admin_user_role_assigned','success',NULL,"userId",'POLICY_MIGRATION',
       '{"serviceKey":"sso","roleName":"admin"}'::jsonb,CURRENT_TIMESTAMP FROM migrated;

COMMIT;

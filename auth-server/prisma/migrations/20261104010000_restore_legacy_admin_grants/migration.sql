-- Compatibility for local databases which applied the earlier, destructive draft.
-- Only restore grants explicitly removed by that POLICY_MIGRATION audit trail.
WITH restored AS (
 INSERT INTO "UserRole" (id,"userId","roleId")
 SELECT gen_random_uuid()::text,u.id,r.id FROM "User" u
 JOIN "AuditLog" a ON a."targetUserId"=u.id
 CROSS JOIN "Role" r
 WHERE a."eventType"='admin_user_role_removed' AND a.outcome='success'
 AND a."reasonCode"='POLICY_MIGRATION'
 AND a."detailsJson"->>'serviceKey'='temis' AND a."detailsJson"->>'roleName'='admin'
 AND r."serviceKey"='temis' AND r.name='admin'
 ON CONFLICT ("userId","roleId") DO NOTHING RETURNING "userId"
)
INSERT INTO "AuditLog" (id,"eventType",outcome,"userId","targetUserId","reasonCode","detailsJson","createdAt")
SELECT gen_random_uuid()::text,'admin_user_role_assigned','success',NULL,"userId",'RESTORE_LEGACY_MIGRATION_GRANT',
 '{"serviceKey":"temis","roleName":"admin"}'::jsonb,CURRENT_TIMESTAMP FROM restored;

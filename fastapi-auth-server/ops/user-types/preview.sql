-- Read-only preview. No UPDATE/INSERT/DELETE, email addresses or raw user IDs.
BEGIN TRANSACTION READ ONLY;
SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='User' AND column_name='userType') AS has_user_type_column;
-- to_jsonb also supports the pre-migration production schema: absent userType means unclassified.
WITH candidates AS (
 SELECT u.id,u.status,CASE WHEN EXISTS (
  SELECT 1 FROM "UserRole" ur JOIN "Role" r ON r.id=ur."roleId"
  WHERE ur."userId"=u.id AND (
   r."serviceKey" IN ('gitlab','agent-hub','lab-staff','sso') OR
   (r."serviceKey"='temis' AND r.name='admin')
  )
 ) THEN 'EMPLOYEE' ELSE 'CUSTOMER' END AS proposed_type
 FROM "User" u WHERE to_jsonb(u)->>'userType' IS NULL
)
SELECT proposed_type,status,COUNT(*) FROM candidates GROUP BY proposed_type,status ORDER BY proposed_type,status;
WITH candidates AS (
 SELECT u.id,u.status,CASE WHEN EXISTS (
  SELECT 1 FROM "UserRole" ur JOIN "Role" r ON r.id=ur."roleId"
  WHERE ur."userId"=u.id AND (
   r."serviceKey" IN ('gitlab','agent-hub','lab-staff','sso') OR
   (r."serviceKey"='temis' AND r.name='admin')
  )
 ) THEN 'EMPLOYEE' ELSE 'CUSTOMER' END AS proposed_type
 FROM "User" u WHERE to_jsonb(u)->>'userType' IS NULL
), ranked AS (
 SELECT *,ROW_NUMBER() OVER (PARTITION BY proposed_type ORDER BY id) AS n FROM candidates
)
SELECT LEFT(MD5(id),12) AS sample_key,status,proposed_type FROM ranked WHERE n<=10 ORDER BY proposed_type,n;
ROLLBACK;

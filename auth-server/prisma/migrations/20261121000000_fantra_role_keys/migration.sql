-- Fantra 역할 이름 전환: temis:* 는 fantra:* 의 옛 이름입니다.
-- fantra 역할을 만들고, temis:pending·user·admin 을 가진 사용자에게 같은 이름의 fantra 역할을 함께 줍니다.
-- temis 역할은 지우지 않습니다(전환 기간에는 둘 다 유지). 여러 번 실행해도 결과가 같습니다.
INSERT INTO "Role" (id, "serviceKey", name)
VALUES
  (gen_random_uuid()::text, 'fantra', 'pending'),
  (gen_random_uuid()::text, 'fantra', 'user'),
  (gen_random_uuid()::text, 'fantra', 'admin')
ON CONFLICT ("serviceKey", name) DO NOTHING;

INSERT INTO "UserRole" (id, "userId", "roleId")
SELECT concat('fantra-role-', md5(ur."userId" || fantra.id)), ur."userId", fantra.id
FROM "UserRole" ur
JOIN "Role" temis ON temis.id = ur."roleId" AND temis."serviceKey" = 'temis'
JOIN "Role" fantra ON fantra."serviceKey" = 'fantra' AND fantra.name = temis.name
WHERE temis.name IN ('pending', 'user', 'admin')
ON CONFLICT ("userId", "roleId") DO NOTHING;

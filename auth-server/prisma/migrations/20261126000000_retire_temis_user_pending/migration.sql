-- temis:user, temis:pending 정리: temis 는 fantra 의 옛 이름입니다(20261121000000_fantra_role_keys).
-- FANTRA 백엔드(운영·개발)는 temis 와 fantra 를 모두 받아 하나로 합치므로 fantra 쪽만 남깁니다.
-- 1) 혹시 fantra 짝이 빠진 사용자가 있으면 먼저 채웁니다(권한을 잃는 사람이 없게).
-- 2) 그다음 temis:user, temis:pending 할당과 역할 자체를 지웁니다.
-- temis:admin 은 건드리지 않습니다. 여러 번 실행해도 결과가 같습니다.
-- 이 코드(fantra 만 쓰는 판)를 배포한 뒤에 실행해야 합니다. 옛 코드는 가입 때 temis 역할을 다시 만듭니다.
INSERT INTO "Role" (id, "serviceKey", name)
VALUES
  (gen_random_uuid()::text, 'fantra', 'pending'),
  (gen_random_uuid()::text, 'fantra', 'user')
ON CONFLICT ("serviceKey", name) DO NOTHING;

INSERT INTO "UserRole" (id, "userId", "roleId")
SELECT concat('fantra-role-', md5(ur."userId" || fantra.id)), ur."userId", fantra.id
FROM "UserRole" ur
JOIN "Role" temis ON temis.id = ur."roleId" AND temis."serviceKey" = 'temis'
JOIN "Role" fantra ON fantra."serviceKey" = 'fantra' AND fantra.name = temis.name
WHERE temis.name IN ('pending', 'user')
ON CONFLICT ("userId", "roleId") DO NOTHING;

DELETE FROM "UserRole"
WHERE "roleId" IN (
  SELECT id FROM "Role" WHERE "serviceKey" = 'temis' AND name IN ('pending', 'user')
);

DELETE FROM "Role" WHERE "serviceKey" = 'temis' AND name IN ('pending', 'user');

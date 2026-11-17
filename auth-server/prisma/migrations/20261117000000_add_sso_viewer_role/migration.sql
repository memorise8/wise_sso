-- 읽기 전용 역할만 등록합니다. 사용자 권한은 자동 부여하지 않습니다.
INSERT INTO "Role" (id, "serviceKey", name)
VALUES ('d5d58d1e-0ee5-4ec2-a65f-b8671b62f175', 'sso', 'viewer')
ON CONFLICT ("serviceKey", name) DO NOTHING;

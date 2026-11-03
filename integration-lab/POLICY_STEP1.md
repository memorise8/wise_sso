# 사용자 유형 · 중앙 관리자 분리: 로컬 검증 1단계

이 변경은 로컬 개발용이다. 운영 서버 배포와 Git commit/push는 수행하지 않는다.

## 구현 범위

- `User.userType`: EMPLOYEE / CUSTOMER, null은 미분류. 공개 가입은 CUSTOMER.
- 이전 시 temis:admin, gitlab:user, agent-hub:user, lab-staff:user 보유자를 EMPLOYEE로 분류한다. 이메일 도메인은 사용하지 않는다. temis:user만 있는 사용자는 미분류로 둔다.
- 중앙 관리 권한을 sso:admin으로 이전한다. 관리자 API는 활성 EMPLOYEE + sso:admin을 DB에서 확인한다.
- OIDC client의 `allowedUserTypes`와 `requiredRoles`를 함께 검사한다. 허용 유형을 생략하면 EMPLOYEE만 허용한다.
- 고객 더미는 EMPLOYEE/CUSTOMER/미분류 + 고객 역할, 직원 더미는 EMPLOYEE + 직원 역할을 요구한다.
- 사용자 유형 조회/필터/단건 변경 API와 관리 화면을 추가한다. 변경은 감사 로그를 기록하고 Refresh Token을 폐기한다.
- 고객/미분류에 사내 서비스 역할을 주는 관리자 API 요청을 거부한다. 공개 서비스 키는 현재 temis, fantra, lab-customer이며 그 외 서비스는 직원 분류를 요구한다.
- 마지막 활성 중앙 관리자 정지·삭제·권한 회수·유형 강등을 거부한다. 중앙 관리자 역할을 가진 사용자의 유형을 변경하려면 먼저 역할을 회수해야 한다. 관리자 변경은 공통 DB 행 잠금으로 직렬화하고 잠금 이후 행위자 권한을 재확인한다.
- 같은 검증 이메일만으로 기존 계정에 소셜 계정을 자동 연결하거나 대기 계정을 삭제하지 않는다. 이메일 충돌 시 별도 CUSTOMER 계정을 만들고 기본 이메일은 null로 둔다. 기존 SocialAccount 연결은 유지한다.

## 적용 순서

아래 명령은 wise_sso 저장소 루트에서 실행한다. .env와 integration-lab/.local을 삭제하거나 교체하지 않는다.

### 1. 백업과 앱 중지

```bash
umask 077
docker compose -f docker-compose.oauth-local.yml exec -T postgres \
  pg_dump -U fastapi_dev -d fastapi_sso_dev > ../wise-sso-before-policy.sql
docker compose -f docker-compose.oauth-local.yml stop app
```

파일 적용은 배포 ZIP의 apply.py를 사용한다. 파일별 원본을 확인하고 저장소 밖에 소스 백업을 만든다. 기존 3개 소셜 로그인 변경 파일은 이 패키지에 포함하지 않는다.

### 2. DB 마이그레이션

```bash
docker run --rm \
  --network wiseacct-sso-wiseacct-oauth_oauth-network \
  --mount "type=bind,source=$PWD/auth-server/prisma,target=/schema,readonly" \
  -e DATABASE_URL='postgresql://fastapi_dev:synthetic-fastapi-db-only@postgres:5432/fastapi_sso_dev' \
  -w /tmp \
  node:22-bookworm \
  npx --yes prisma@6.19.3 migrate deploy --schema=/schema/schema.prisma
```

마이그레이션 오류 시 앱을 시작하지 말고 오류를 확인한다. 기존 마이그레이션 8개와 신규 1개가 있는 것이 정상이다. DB 변경 후에는 구버전 Express 관리자 기능을 사용하지 않는다.

### 3. 설정 재생성과 이미지 재빌드

```bash
bash integration-lab/lab.sh setup
bash integration-lab/lab.sh config
docker compose -f docker-compose.oauth-local.yml build app
bash integration-lab/lab.sh up
bash integration-lab/lab.sh seed
bash integration-lab/lab.sh policy-setup
bash integration-lab/lab.sh policy-check
```

setup은 기존 material.json을 재사용하므로 테스트 비밀번호와 client secret을 유지한다. policy-setup은 로컬 전용 DB/issuer와 고정 UUID·이메일을 검사한 뒤 테스트 계정 4개만 명시적으로 분류하고 employee 테스트 계정에 sso:admin을 부여한다. 운영용 초기 관리자 분류 도구가 아니다.

policy-check는 토큰을 출력하지 않고 관리자 API로 고객의 직원 역할 및 중앙 관리자 역할 부여가 차단되는지, 관리자 유형 강등이 보호되는지 확인한다. 테스트 후 로그인 Refresh Token은 로그아웃으로 폐기한다. 오류 시 응답 상태만 출력한다.

### 4. DB와 브라우저 확인

```bash
docker compose -f docker-compose.oauth-local.yml exec -T postgres \
  psql -U fastapi_dev -d fastapi_sso_dev \
  -c 'SELECT email, "userType", status FROM "User" WHERE email LIKE '\''%@wise-lab.invalid'\'' ORDER BY email;'
```

| 계정 | 유형 | 고객 더미 | 직원 더미 |
| --- | --- | --- | --- |
| customer@wise-lab.invalid | CUSTOMER | 허용 | 거부 |
| employee@wise-lab.invalid | EMPLOYEE | 허용 | 허용 |
| unapproved@wise-lab.invalid | EMPLOYEE, 역할 없음 | 거부 | 거부 |
| suspended@wise-lab.invalid | EMPLOYEE, SUSPENDED | 거부 | 거부 |

- https://localhost:4445/ 고객용, https://localhost:4446/ 직원용에서 다시 확인한다.
- 기존 더미 세션에서는 먼저 로그아웃한 뒤 새 로그인으로 검증한다.
- 고객에게 직원 역할을 실수로 DB에서 부여한 상황도 단위 테스트에서 재현한다. 역할이 있어도 CUSTOMER/미분류는 인가 코드 교환과 userinfo에서 차단된다.
- UI는 유형 표시·단건 변경·미분류 필터를 확인한다. 관리자 토큰은 외부에 공유하지 않는다.

## 검증 증거와 한계

- FastAPI 단위 테스트 + 관리자 HTTP 테스트: 592개 통과, 12개 skip, Express Node oracle 1개 제외. userinfo 유형 변경 테스트를 포함한다.
- 더미 테스트 12개 통과, Python 소스 mypy 통과, 변경 소스 Ruff 및 JS 문법 검사 통과.
- 임베디드 PostgreSQL(PGlite)에서 기존 8개와 신규 마이그레이션 실행, 직원 분류/고객 미분류 유지/중앙 관리자 이전/감사 로그 확인.
- 성능 collector 테스트는 이 작업 사본의 기존 frozen manifest 해시/줄바꿈 문제로 제외했다. Express Node oracle은 이 실행 환경의 IPC 권한 오류로 제외했다. 전체 테스트가 모두 통과했다고 주장하지 않는다.
- 실제 Docker PostgreSQL16·Redis·브라우저 검증은 사용자 로컬에서 위 순서로 수행해야 한다.

## 남은 작업

중앙 SSO 세션, 서비스 간 무재로그인 이동, 통합 로그아웃, client DB/관리 화면, 명시적 소셜 계정 연결 UI, 사용자 유형 일괄 변경, 서비스 관리자 위임, MFA, Fantra JWT 역할 최소화는 별도 단계다. 직원으로 신규 분류되더라도 사내 역할은 별도로 승인해야 한다.

운영 CORS와 실제 Fantra/dashboard 연동은 운영 설정·하위 서비스 정보가 확보된 뒤 검증한다. 현재 운영 설정을 변경하지 않는다. 이 단계만으로 운영 완료를 선언하지 않는다.

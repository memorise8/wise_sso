# wise_sso / TEMIS SSO Auth Server 작업 인계 요약

## 현재 위치

작업 디렉터리:

```bash
/home/ruci/repo/wiseacct_sso
```

주요 프로젝트:

```bash
auth-server/
```

현재 계획 파일:

```bash
.omo/plans/temis-sso-p0-auth-hardening.md
```

현재 상태:

- `temis-sso-p0-auth-hardening` 계획의 todo `1~12`, `F1~F4` 모두 완료
- `.omo/boulder.json`에서 `temis-sso-p0-auth-hardening`은 `completed`
- 커밋은 아직 하지 않음
- `auth-server/.env`는 로컬 비밀 설정으로 ignored 상태이며 읽거나 이동하지 않았음
- `auth-server/.auth-server.pid`는 없음, `.gitignore`에 추가됨

최종 검증 결과:

```bash
cd auth-server
npm test -- --reporter=verbose
# 31 files / 174 tests passed

npm run build
# passed

npx prisma validate --schema prisma/schema.prisma
# passed

node scripts/qa-portal-storage.mjs
# passed

git diff --check
# passed
```

## 지금까지 구현 완료된 핵심 기능

### Auth Server 기본/운영

- `/healthz`
- `/readyz`
- PostgreSQL readiness check
- Redis 기반 OAuth state / handoff code 저장
- Docker Compose Postgres/Redis 기본 loopback binding
- `.env.example` host 실행 기준 Redis URL:
  - `redis://127.0.0.1:6379`
- Compose 내부 app 실행 시:
  - `redis://redis:6379`
- `auth-server/.auth-server.pid` ignored 처리

### A서버/B서버 구조

정책:

```text
B서버 = Auth Server
A서버 = TEMIS 등 실제 서비스 서버
```

Auth Server DB에는 인증 최소 정보만 저장:

- User
- SocialAccount
- PasswordCredential
- EmailVerificationToken
- PasswordResetToken
- RefreshToken
- Role
- UserRole
- AuditLog

서비스 데이터는 TEMIS DB에 저장해야 함.

### 회원가입/로그인

Auth Server가 담당:

- 이메일 회원가입
- 이메일 인증
- 비밀번호 로그인
- 비밀번호 재설정
- Google OAuth
- Naver/Kakao provider disabled 응답 처리
- 소셜 계정과 내부 user id 분리
- 같은 email 자동 병합 금지

사용자 상태:

```ts
PENDING_EMAIL_VERIFICATION
ACTIVE
SUSPENDED
DELETED
```

상태 정책:

- `SUSPENDED`, `DELETED`는 로그인, code exchange, token refresh 차단
- Auth Server DB-backed `/users/me`도 현재 DB 상태 재검증

### TEMIS client policy

`AUTH_CLIENTS_JSON` 기반 정적 relying-client 정책 구현.

기본 TEMIS client:

```json
{
  "clientId": "temis",
  "audience": "temis",
  "allowedRedirectUris": ["https://financenow.kr/auth/callback"],
  "allowedOrigins": ["https://financenow.kr"],
  "defaultRole": {
    "serviceKey": "temis",
    "name": "pending"
  }
}
```

보안 정책:

- `allowedRedirectUris`는 인증 보안 경계
- `allowedOrigins`는 CORS 용도
- 둘을 섞지 않음
- redirect URI는 정확히 일치해야 함
- CORS 허용이 redirect 허용을 의미하지 않음
- unknown key strict reject
- duplicate client id reject
- default role은 least privilege 검증
- `admin` default role 금지

### Role / Approval

기본 신규 사용자 role:

```json
{ "serviceKey": "temis", "name": "pending" }
```

정책:

- 신규 가입자: `temis:pending`
- 승인 사용자: `temis:user`
- 운영자: `temis:admin`

구현됨:

- OAuth 신규 사용자 default role assignment
- 이메일 인증 완료 시 default role assignment
- roleless user backfill script
- `ops:grant-admin` 첫 admin 부여 CLI
- QA fixture seed script

관련 scripts:

```bash
npm run ops:grant-admin -- --email <email>
npm run qa:seed-temis-admin-flow
```

주의:

- `qa-fixture.env`에는 raw JWT/refresh token을 남기지 않고 redacted proof만 남기도록 변경됨

### Admin API

구현됨:

```http
GET    /admin/users
PATCH  /admin/users/:id/status
POST   /admin/users/:id/roles
DELETE /admin/users/:id/roles/:roleId
POST   /admin/users/:id/revoke-sessions
```

정책:

- DB-backed `ACTIVE` + `temis:admin` 필요
- stale JWT role만으로는 관리자 권한 인정하지 않음
- self suspend/delete 차단
- self admin role removal 차단
- self session revoke 차단
- status change / role removal / explicit session revoke는 refresh token revocation + audit와 transaction 처리

### OAuth / Handoff Code / PKCE

구현됨:

- OAuth start는 `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method=S256` 필요
- PKCE S256 필수
- missing PKCE는 provider redirect 전에 400
- callback은 TEMIS redirect URI로 `code`와 `state`만 전달
- Access Token / Refresh Token은 URL query/fragment로 전달하지 않음
- `/auth/exchange` body는 camelCase only:

```json
{
  "clientId": "temis",
  "redirectUri": "https://financenow.kr/auth/callback",
  "code": "<handoff_code>",
  "codeVerifier": "<pkce_verifier>"
}
```

handoff code 보안:

- Redis 저장
- raw code를 Redis key로 쓰지 않음
- SHA-256 keyed storage
- token pair를 handoff value에 저장하지 않음
- metadata bound:
  - `clientId`
  - `redirectUri`
  - `userId`
  - provider/login method
  - `codeChallenge`
  - `codeChallengeMethod=S256`
  - `state`
  - `audience`
- successful exchange만 atomic consume
- wrong client/redirect/verifier 시 code를 태우지 않음
- successful replay는 실패
- expired/malformed metadata는 cleanup 가능

중요하게 마지막 글로벌 리뷰에서 발견되어 수정된 내용:

- 이전에는 wrong verifier/client/redirect 시 handoff code가 소비됐음
- 수정 후 failed binding/PKCE attempt는 code를 소비하지 않음
- valid retry 가능
- success만 atomic consume

### Token / Refresh Token

구현됨:

- Access Token
- Refresh Token hash 저장
- Refresh Token rotation
- Refresh Token revocation
- Refresh Token audience column/migration 추가
- relying-client audience propagation
- refresh rotation 시 audience 유지
- invalid audience refresh 차단
- token issue/refresh는 active-row lock과 transaction 기반 상태 확인
- role removal / session revoke / password reset 시 target User row lock 후 refresh revocation
- refresh revocation vs rotation race 보강

마지막 글로벌 보안 리뷰에서 수정된 내용:

- relying-client audience가 실제 token issuance/refresh에 적용되지 않던 문제 수정
- refresh revocation과 refresh rotation race 보강
- role removal, session revoke, password reset race tests 추가

### Audit

구현됨:

- login_success
- login_failure
- register
- email_verify
- token_refresh
- logout
- rate_limited
- handoff exchange success/failure
- admin status change
- admin role assignment/removal
- admin session revoke
- admin authorization failure

AuditLog fields:

- `actorUserId`
- `targetUserId`
- `detailsJson`

정책:

- raw OAuth code, handoff code, access token, refresh token, SMTP/JWT secret 저장 금지
- detailsJson bounded/sanitized
- PII overlogging 방지

주의:

- 감사 로그 조회 API는 아직 명시적으로 별도 구현되지 않은 것으로 보임. 다음 요청에서 필요하면 추가 개발 대상.

### Portal

Auth Portal 구현/보강됨:

- `/login`
- `/signup`
- callback handling
- Refresh Token browser localStorage/sessionStorage 저장 금지
- legacy `wise_sso_refresh_token`은 removeItem만 수행
- production에서는 browser direct `/auth/exchange` 호출하지 않음
- dev callback은 Refresh Token을 저장하지 않으며, 개발용 단기 access state만 저장 가능
- URL에서 code/state 처리 후 token query/fragment leak 없음

검증:

```bash
node scripts/qa-portal-storage.mjs
```

통과.

### Docs / Runbook

수정됨:

- `auth-server/README.md`
- `auth-server/ops/README.md`
- `.env.example`

문서화된 내용:

- A/B 서버 경계
- Auth DB 저장 범위
- TEMIS DB 저장 범위
- `AUTH_CLIENTS_JSON`
- `/healthz` vs `/readyz`
- redirect URI vs CORS origin
- PKCE/code exchange
- user statuses
- `temis:pending` approval flow
- admin APIs
- audit fields
- refresh-token revocation
- first-admin CLI
- Docker/Postgres/Redis setup
- Google internal/external app 주의
- Naver/Kakao disabled provider
- Refresh Token은 TEMIS browser에 저장하지 않음
- TEMIS는 Auth DB 직접 조회하지 않음

## 주요 신규/변경 파일

대표 파일:

```bash
auth-server/src/routes/admin.routes.ts
auth-server/src/routes/admin.routes.test.ts
auth-server/src/routes/admin.routes.test-support.ts

auth-server/src/services/admin-directory.service.ts
auth-server/src/services/admin-directory.service.test.ts

auth-server/src/services/admin-user.service.ts
auth-server/src/services/admin-user.service.test.ts
auth-server/src/services/admin-user.store.ts
auth-server/src/services/admin-user.service.test-support.ts

auth-server/src/services/auth-control.store.ts
auth-server/src/services/auth-handoff.store.ts
auth-server/src/services/auth-handoff.store.test.ts
auth-server/src/services/client-policy.service.ts
auth-server/src/services/first-admin-provisioning.service.ts
auth-server/src/services/first-admin-provisioning.service.test.ts
auth-server/src/services/redis.client.ts
auth-server/src/services/redis.client.test.ts
auth-server/src/services/session-revocation.service.ts
auth-server/src/services/session-revocation.service.test.ts
auth-server/src/services/token.audience.service.test.ts
auth-server/src/services/user-status.service.ts
auth-server/src/services/user.service.test.ts

auth-server/src/scripts/backfill-default-roles.ts
auth-server/src/scripts/grant-admin.ts
auth-server/src/scripts/seed-temis-admin-flow-fixture.ts

auth-server/public/auth-portal.html
auth-server/public/assets/auth.js
auth-server/scripts/qa-portal-storage.mjs

auth-server/prisma/migrations/20260722030000_add_user_status_enum_and_audit_admin_fields/
auth-server/prisma/migrations/20260723090000_add_refresh_token_audience/
```

## 현재 git 상태 관련 주의

변경 파일이 매우 많고 커밋은 아직 없음.

확인 명령:

```bash
git status --short
```

`auth-server/.env`는 ignored 상태:

```bash
git status --short --ignored auth-server/.env
# !! auth-server/.env
```

주의:

- `.env`는 로컬 비밀 파일이라 읽거나 출력하지 말 것
- `.auth-server.pid`는 없어야 하며 `.gitignore`에 추가됨
- Postgres/Redis 컨테이너는 일부 QA에서 intentionally left running일 수 있음

## 최종 글로벌 리뷰 상태

5개 글로벌 리뷰 레인 PASS:

- Goal/constraint review: PASS
- QA review: PASS
- Code quality review: PASS/WATCH
- Security review: PASS/WATCH
- Context/scope review: PASS

최종 검증 명령 결과:

```bash
cd auth-server

npm test -- --reporter=verbose
# 31 files / 174 tests passed

npm run build
# passed

npx prisma validate --schema prisma/schema.prisma
# passed

node scripts/qa-portal-storage.mjs
# passed

git diff --check
# passed
```

## 남은 요청 / 다음 개발 후보

사용자가 다음으로 요청한 TEMIS 추가 요구사항:

```text
1. 회원가입 진입 경로 제공
2. TEMIS 역할 및 승인 정책
3. JWT 공개키 검증 지원
4. Access Token 사용자 정보 계약
5. code exchange 보안 확인
6. Refresh Token 역할 분담 확정
7. 운영 편의
```

현재 답변 기준:

- 1번: 구현됨. 공식 signup URL은 `https://auth.financenow.kr/signup`.
- 2번: 구현됨.
- 3번: 구현됨.
  - Access Token은 RS256 public key/JWKS 검증 계약.
  - `/.well-known/jwks.json` 제공.
  - JWT `kid` 제공.
  - `/.well-known/openid-configuration` 제공.
- 4번: 구현됨.
  - Access Token required claims: `iss`, `aud`, `sub`, `exp`, `roles`, `type=access`.
  - AuthUser contract includes `email_verified`.
  - `/users/me`는 있음. 반환 필드 확인 필요.
- 5번: 구현됨.
- 6번: 구현됨.
  - TEMIS browser에는 Refresh Token 저장 금지.
  - TEMIS BFF가 필요할 때만 Refresh Token을 server-side session store 또는 secret store에 저장.
- 7번: 대부분 구현됨.
  - `/healthz` 있음.
  - audit event 저장 있음.
  - Naver/Kakao disabled response 있음.
  - 감사 로그 조회 API/보관 정책은 추가 개발 필요.

## 다음 세션에서 바로 이어 할 일

추천 다음 목표:

```text
남은 운영 편의 항목을 확정한다. JWKS/OIDC Discovery, Access Token claims, Refresh Token BFF 계약 문서화는 구현됨.
```

다음 세션 첫 작업 제안:

1. 현재 코드 확인

   ```bash
   cd /home/ruci/repo/wiseacct_sso
   git status --short
   cd auth-server
   npm test -- --reporter=verbose
   npm run build
   ```

2. 감사 로그 조회 API 개발 여부 결정

   - admin only
   - pagination/filter
   - PII redaction
   - retention policy docs

3. 운영 key rotation runbook 작성 여부 결정

   - JWKS cache TTL
   - 새 `kid` 배포 순서
   - 이전 public key 제거 시점

## TEMIS에 현재 전달 가능한 연동 계약

```md
Auth Server:
- https://auth.financenow.kr

TEMIS client:
- client_id: temis
- audience: temis
- redirect_uri: https://financenow.kr/auth/callback

회원가입:
- 공식 signup URL: https://auth.financenow.kr/signup
- 가입/이메일 인증/비밀번호 재설정은 Auth Server가 담당

로그인 시작:
GET /auth/google?client_id=temis&redirect_uri=https%3A%2F%2Ffinancenow.kr%2Fauth%2Fcallback&state=<state>&code_challenge=<challenge>&code_challenge_method=S256

Callback:
- Auth Server -> TEMIS redirect_uri
- query: code, state only
- Access/Refresh Token URL 전달 금지

Exchange:
POST /auth/exchange
{
  "clientId": "temis",
  "redirectUri": "https://financenow.kr/auth/callback",
  "code": "<handoff_code>",
  "codeVerifier": "<pkce_verifier>"
}
- body는 camelCase only. `client_id`, `redirect_uri`, `code_verifier` 또는 unknown field는 거부.

JWKS / Discovery:
- GET https://auth.financenow.kr/.well-known/jwks.json
- GET https://auth.financenow.kr/.well-known/openid-configuration
- Access Token verifier는 JWKS/public key로 `RS256`만 허용하고 HS256 token을 거부.
- required claims: `iss`, `aud`, `exp`, `sub`, `roles`, `type=access`.
- AuthUser contract includes `email_verified`.
- Refresh Token처럼 `type=refresh`인 token은 TEMIS API Access Token으로 사용 금지.

TEMIS 책임:
- Access Token 검증
- iss/aud/exp/signature/sub/roles/type=access/email_verified 확인
- sub를 authUserId로 사용
- Auth DB 직접 조회 금지
- TEMIS browser는 Refresh Token 저장 금지
- TEMIS BFF는 필요할 때만 Refresh Token을 server-side 저장소에 보관
- OAuth provider secret 보관 금지
```

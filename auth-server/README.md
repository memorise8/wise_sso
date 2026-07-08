# Auth Server

Google, Naver, Kakao OAuth와 회사 이메일/비밀번호 로그인을 하나의 Express 기반 B서버(SSO/Auth/Login 서버)에서 처리하고, 여러 A서버(실제 서비스 서버)가 같은 SSO를 공유하도록 구성한 Node.js/TypeScript 프로젝트입니다.

## 핵심 경계

운영에서 가장 중요한 원칙은 인증 데이터와 서비스 데이터를 분리하는 것입니다.

- A/B 서버는 DB를 공유하지 않습니다.
- A서버는 auth DB를 읽지 않습니다.
- B서버는 로그인, OAuth callback, 이메일 인증, 비밀번호 재설정, Access Token 발급, Refresh Token 저장/회전/폐기만 담당합니다.
- A서버는 Access Token만 검증하고 Refresh Token을 저장하거나 처리하지 않습니다.
- `authUserId`는 서비스 데이터와 인증 사용자를 연결하는 link key입니다.
- 서비스 데이터는 A서버 DB에만 저장합니다.

## A서버와 B서버 역할

B서버(Auth Server)는 identity provider입니다. 사용자가 Google/Naver/Kakao 또는 이메일/비밀번호로 로그인하면 B서버가 JWT Access Token과 Refresh Token을 발급합니다. Refresh Token은 B서버 DB에 hash로만 저장되고, 재발급과 로그아웃도 B서버에서만 처리합니다.

A서버(Service Server)는 실제 제품 기능과 업무 데이터를 소유합니다. A서버는 요청의 `Authorization: Bearer <accessToken>` 값을 검증한 뒤 JWT `sub` claim을 `authUserId`로 사용합니다. A서버는 B서버의 `users`, `refresh_tokens`, `password_credentials`, `audit_logs` 같은 auth DB table을 조회하지 않습니다.

## B서버 DB 저장 범위

B서버 DB에는 인증을 운영하기 위한 최소 auth-only data만 저장합니다.

```text
users: id, email, name, profileUrl, status, createdAt, updatedAt
password_credentials: userId, email, passwordHash, failedLoginCount, lockedUntil, passwordUpdatedAt
social_accounts: userId, provider, providerUserId, providerEmail
refresh_tokens: userId, tokenHash, expiresAt, revokedAt, createdAt
email_verification_tokens: userId, tokenHash, expiresAt, usedAt, createdAt
password_reset_tokens: userId, tokenHash, expiresAt, usedAt, createdAt
audit_logs: userId, eventType, outcome, provider, serviceKey, ipAddress, userAgent, reasonCode, createdAt
roles: serviceKey, name
user_roles: userId, roleId
```

B서버 DB에 저장하지 않는 데이터:

```text
프로젝트, 문서, 채팅/질문/답변, 결제 상세, 고객사 업무 데이터,
서비스별 세부 설정, 서비스 이용 내역, A서버 내부 권한 상세
```

## A서버 DB 저장 범위

A서버 DB는 서비스 데이터를 저장하고, B서버의 `users.id`를 외부 식별자 `authUserId`로만 참조합니다. `authUserId`는 link key일 뿐이고, A서버가 auth DB를 join하거나 직접 조회한다는 뜻이 아닙니다.

```text
service_users: id, authUserId, companyId, plan, serviceStatus, createdAt, updatedAt
projects: id, serviceUserId, title, createdAt
chat_sessions: id, serviceUserId, title, createdAt
documents: id, serviceUserId, fileName, storageKey, createdAt
service_permissions: serviceUserId, resourceId, permission
```

서비스 내부의 프로젝트 owner/editor/viewer 같은 세부 권한은 A서버 DB에서 관리합니다. B서버 role은 `temis:user`, `temis:admin`처럼 서비스 접근을 위한 큰 단위 권한에만 사용합니다.

## 설치

```bash
cd auth-server
npm install
cp .env.example .env
npm run prisma:generate
```

`.env`는 운영 환경마다 별도로 관리하고 저장소에 커밋하지 않습니다.

## 환경변수 설정

운영자가 제공해야 하는 값:

```text
DATABASE_URL
PORT
JWT_ACCESS_SECRET
JWT_REFRESH_SECRET
JWT_ISSUER
JWT_AUDIENCE
ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN_DAYS
PASSWORD_MIN_LENGTH
COMPANY_ALLOWED_EMAIL_DOMAIN
CORS_ALLOWED_ORIGINS
AUTH_RATE_LIMIT_WINDOW_SECONDS
AUTH_RATE_LIMIT_MAX_REQUESTS
FRONTEND_REDIRECT_URL
MAIL_PROVIDER
MAIL_FROM
SMTP_HOST
SMTP_PORT
SMTP_USERNAME
SMTP_PASSWORD
GOOGLE_CLIENT_ID
GOOGLE_CLIENT_SECRET
GOOGLE_REDIRECT_URI
NAVER_CLIENT_ID
NAVER_CLIENT_SECRET
NAVER_REDIRECT_URI
KAKAO_CLIENT_ID
KAKAO_CLIENT_SECRET
KAKAO_REDIRECT_URI
```

운영자는 secret 값을 password manager, CI/CD secret store, systemd environment file, Kubernetes Secret 같은 비공개 저장소로 주입합니다. README와 `.env.example`에는 실제 secret을 넣지 않습니다.

코드가 처리하는 값:

- JWT signature, issuer, audience, expiration 검증
- Refresh Token hash 저장, rotation, logout 폐기
- 이메일 인증 token hash 저장과 만료/재사용 차단
- password reset token hash 저장과 만료/재사용 차단
- login/register/verification/reset/refresh/logout audit log 기록
- CORS allowlist 적용
- auth-sensitive endpoint rate limit 적용

## PostgreSQL 배포

MVP에서는 현재 SSO 서버에 PostgreSQL을 함께 둘 수 있습니다. 장기적으로는 auth DB를 별도 DB 서버나 managed PostgreSQL로 분리하는 것을 권장합니다.

최소 운영 원칙:

- `auth_db`는 B서버 전용 DB입니다.
- A서버 계정에는 `auth_db` 접속 권한을 부여하지 않습니다.
- `auth_user`는 필요한 schema/table 권한만 받는 least-privilege 계정이어야 합니다.
- DB port는 B서버 또는 내부 관리망에서만 접근되도록 firewall/security group으로 제한합니다.
- migration은 배포 시 `npm run prisma:migrate:deploy` 또는 동일한 Prisma deploy 명령으로 적용합니다.

예시 절차:

```bash
createdb auth_db
createuser auth_user
psql auth_db -c "GRANT CONNECT ON DATABASE auth_db TO auth_user;"
cd auth-server
npm run prisma:migrate:deploy
```

위 명령의 사용자명, host, password는 운영 환경의 secret 관리 방식에 맞게 바꿉니다.

## Backup / Restore

Auth DB backup은 refresh token hash, email, audit metadata를 포함하므로 암호화된 저장소에 보관합니다. backup 파일 접근 권한은 DB 운영자와 보안 담당자로 제한합니다.

Backup 예시:

```bash
export DATABASE_URL="postgresql://auth_user:<password>@<host>:5432/auth_db"
npm run ops:backup -- "backups/auth_db-$(date +%Y%m%d%H%M%S).dump"
```

Restore test 예시:

```bash
createdb auth_db_restore_test
export AUTH_RESTORE_TEST_DATABASE_URL="postgresql://auth_user:<password>@<host>:5432/auth_db_restore_test"
npm run ops:restore-test -- backups/auth_db-YYYYMMDDHHMMSS.dump
```

운영 기준:

- backup 주기와 보관 기간을 서비스 RPO/RTO에 맞게 정합니다.
- 최소 월 1회 restore test를 수행합니다.
- restore test DB는 검증 후 삭제합니다.
- backup과 restore log에는 DB password, JWT secret, SMTP password를 남기지 않습니다.

## OAuth Redirect URIs

개발 환경에서 각 provider console에 등록할 redirect URI:

```text
Google: http://localhost:4000/auth/google/callback
Naver:  http://localhost:4000/auth/naver/callback
Kakao:  http://localhost:4000/auth/kakao/callback
```

운영 환경에서는 HTTPS Auth Server 도메인을 사용합니다.

```text
Google: https://auth.example.com/auth/google/callback
Naver:  https://auth.example.com/auth/naver/callback
Kakao:  https://auth.example.com/auth/kakao/callback
```

Provider console의 redirect URI와 `.env`의 `GOOGLE_REDIRECT_URI`, `NAVER_REDIRECT_URI`, `KAKAO_REDIRECT_URI`가 정확히 같아야 합니다. `FRONTEND_REDIRECT_URL`은 OAuth 성공 후 브라우저가 돌아갈 A서비스 프론트엔드 callback URL입니다.

OAuth callback은 raw Access Token이나 Refresh Token을 redirect URL query/fragment에 넣지 않습니다. B서버는 짧게 만료되는 one-time handoff code만 `FRONTEND_REDIRECT_URL?code=<code>`로 전달하고, 프론트엔드는 즉시 `POST /auth/exchange`로 token pair를 교환합니다.

## Google Login Setup

Google 로그인은 Google Cloud Console의 OAuth client로 연동합니다.

Google Cloud Console에서 설정한 항목:

```text
Google Auth Platform
-> 클라이언트
-> 클라이언트 만들기
```

클라이언트 설정:

```text
애플리케이션 유형: 웹 애플리케이션
이름: wise-sso-auth-server
승인된 JavaScript 원본: 비워둠
승인된 리디렉션 URI:
  http://localhost:4000/auth/google/callback
  https://auth.financenow.kr/auth/google/callback
```

`승인된 JavaScript 원본`은 프론트엔드가 Google SDK로 직접 token을 받는 구조에서 필요합니다. 이 프로젝트는 B서버가 OAuth callback과 token exchange를 처리하므로 redirect URI만 등록합니다.

Google Cloud Console에서 발급된 값을 `.env`에 넣습니다. secret 원문은 README나 Git에 기록하지 않습니다.

로컬 개발:

```env
GOOGLE_CLIENT_ID="<google-client-id>"
GOOGLE_CLIENT_SECRET="<google-client-secret>"
GOOGLE_REDIRECT_URI="http://localhost:4000/auth/google/callback"
```

운영 또는 Cloudflare 연결 후:

```env
GOOGLE_CLIENT_ID="<google-client-id>"
GOOGLE_CLIENT_SECRET="<google-client-secret>"
GOOGLE_REDIRECT_URI="https://auth.financenow.kr/auth/google/callback"
JWT_ISSUER="https://auth.financenow.kr"
```

테스트 흐름:

```text
GET /auth/google
-> Google 로그인/동의 화면
-> GET /auth/google/callback
-> FRONTEND_REDIRECT_URL?code=<one-time-code>
-> POST /auth/exchange
-> Access Token / Refresh Token 발급
```

문제가 발생하면 먼저 아래를 확인합니다.

- Google Console의 redirect URI와 `.env`의 `GOOGLE_REDIRECT_URI`가 완전히 같은지 확인합니다.
- `http`/`https`, host, port, path가 하나라도 다르면 `redirect_uri_mismatch`가 발생합니다.
- 내부 앱으로 만든 경우 Google Workspace 조직 내부 사용자만 로그인할 수 있습니다.
- 운영 도메인 적용 직후에는 Google 설정 반영에 시간이 걸릴 수 있습니다.

## SMTP Setup

개발 환경에서는 `MAIL_PROVIDER=dev`를 사용해 실제 SMTP 발송 없이 verification/reset link를 테스트합니다.

운영 환경에서는 `MAIL_PROVIDER=smtp`와 SMTP 값을 채웁니다. `smtp` mode는 설정된 SMTP transport로 email verification과 password reset 메일을 발송합니다.

SMTP 계정 인증을 사용하는 일반 SMTP 서버:

```text
MAIL_PROVIDER=smtp
MAIL_FROM=Auth <no-reply@example.com>
SMTP_HOST=<smtp-host>
SMTP_PORT=587
SMTP_USERNAME=<smtp-username>
SMTP_PASSWORD=<smtp-password>
```

Google Workspace SMTP Relay처럼 서버 공인 IP 기반 릴레이를 사용하는 경우:

```text
MAIL_PROVIDER=smtp
MAIL_FROM=Auth <no-reply@company.com>
SMTP_HOST=smtp-relay.gmail.com
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
```

이 경우 Google Admin Console의 SMTP relay service에서 SSO 서버 공인 IP를 허용하고, TLS 암호화를 요구하며, SMTP 인증 요구는 끕니다. `MAIL_FROM`은 Google Workspace에 등록된 회사 도메인 주소여야 합니다.

SMTP 운영자가 결정할 것:

- 발송 도메인과 sender 주소
- SPF/DKIM/DMARC 설정
- SMTP credential 또는 허용된 서버 공인 IP 관리 방식
- 이메일 인증 link와 password reset link의 public frontend URL 정책
- bounce/complaint 처리 방식

메일 본문과 log에는 raw password, raw refresh token, provider access token을 넣지 않습니다.

## API

OAuth 로그인 시작:

```http
GET /auth/google
GET /auth/naver
GET /auth/kakao
```

OAuth handoff code 교환:

```http
POST /auth/exchange
Content-Type: application/json

{
  "code": "<one-time-handoff-code>"
}
```

성공 시 `{ "accessToken": "...", "refreshToken": "..." }`를 반환합니다. 누락, 만료, 유효하지 않은 code와 재사용된 code는 모두 generic `400`으로 거부합니다.

회사 계정 가입:

```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "minimum-12-chars",
  "name": "User Name"
}
```

가입 요청은 계정 존재 여부를 노출하지 않는 generic response를 사용합니다. 이메일/비밀번호 계정은 email verification을 완료한 뒤 로그인 정책에 따라 사용할 수 있습니다.

이메일 인증 요청:

```http
POST /auth/email-verification/request
Content-Type: application/json

{
  "email": "user@example.com"
}
```

이메일 인증 확인:

```http
POST /auth/email-verification/confirm
Content-Type: application/json

{
  "token": "<verification-token-from-email>"
}
```

회사 계정 로그인:

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "minimum-12-chars"
}
```

Password reset 요청:

```http
POST /auth/password-reset/request
Content-Type: application/json

{
  "email": "user@example.com"
}
```

Password reset 확인:

```http
POST /auth/password-reset/confirm
Content-Type: application/json

{
  "token": "<reset-token-from-email>",
  "password": "new-minimum-12-chars"
}
```

토큰 재발급:

```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "<refresh-token>"
}
```

로그아웃:

```http
POST /auth/logout
Content-Type: application/json

{
  "refreshToken": "<refresh-token>"
}
```

현재 사용자:

```http
GET /users/me
Authorization: Bearer <accessToken>
```

## Access Token 검증 흐름

각 A서버는 Auth Server와 동일한 `JWT_ACCESS_SECRET`, `JWT_ISSUER`, `JWT_AUDIENCE`를 안전하게 주입받아 Access Token을 검증합니다. 공유 secret 방식에서 public key 방식으로 바꾸는 경우에도 A서버 책임은 동일합니다. A서버는 token 검증만 하고 auth DB를 읽지 않습니다.

Access Token payload 기준:

```json
{
  "sub": "auth_user_id",
  "email": "user@example.com",
  "name": "User Name",
  "roles": [
    {
      "serviceKey": "temis",
      "name": "user"
    }
  ],
  "iss": "https://auth.example.com",
  "aud": "temis",
  "iat": 1234567890,
  "exp": 1234569999
}
```

A서버 검증 규칙:

- JWT signature가 유효해야 합니다.
- `exp`가 지나지 않아야 합니다.
- `iss`가 A서버가 신뢰하는 Auth Server 값이어야 합니다.
- `aud`가 해당 서비스의 audience 값이어야 합니다.
- `sub` claim을 A서버의 `authUserId`로 사용합니다.

요청 처리 흐름:

1. 사용자가 B서버에서 로그인합니다.
2. B서버가 Access Token과 Refresh Token을 발급합니다.
3. 사용자가 A서버 API를 호출할 때 Access Token을 전달합니다.
4. A서버가 signature, `exp`, `iss`, `aud`를 검증합니다.
5. A서버가 JWT `sub`를 `authUserId`로 사용합니다.
6. A서버가 `authUserId` 기준으로 `service_users`를 조회하거나 최초 접근 시 생성합니다.
7. A서버가 자체 DB의 service data와 service permission으로 업무 요청을 처리합니다.

## A서버가 Refresh Token을 다루지 않는 이유

Refresh Token은 장기 인증 권한입니다. 저장, rotation, 폐기 책임을 B서버로 한정해야 사고 대응과 강제 로그아웃 범위를 통제할 수 있습니다.

A서버가 Refresh Token을 저장하거나 처리하면 서비스별 DB마다 장기 인증 권한이 분산됩니다. 그러면 한 서비스 DB 유출이 전체 SSO session 탈취로 이어질 수 있고, 비밀번호 재설정이나 보안 사고 시 전체 refresh token 폐기를 일관되게 적용하기 어렵습니다.

A서버는 짧은 수명의 Access Token만 검증합니다. Access Token이 만료되면 클라이언트가 B서버의 `/auth/refresh`를 호출해 새 token pair를 받습니다.

## 여러 서비스가 하나의 SSO를 공유하는 구조

```text
Browser -> B서버 /auth/google -> OAuth provider -> B서버 callback
Browser <- B서버 Access Token + Refresh Token
Browser -> A서버 temis API Authorization: Bearer <accessToken>
A서버 -> aud=temis, iss=https://auth.example.com 검증
A서버 -> service_users.authUserId = JWT sub 로 서비스 사용자 조회/생성
```

각 서비스는 같은 B서버를 신뢰하지만 자체 서비스 DB를 유지합니다. 예를 들어 `temis`, `review`, `billing` A서버가 같은 SSO를 쓰더라도 각 서비스의 프로젝트, 문서, 결제 상세, 고객사 업무 데이터는 각 A서버 DB에 남습니다.

## CORS

`CORS_ALLOWED_ORIGINS`에는 브라우저에서 Auth Server API를 호출할 수 있는 frontend origin만 쉼표로 등록합니다. Auth Server는 `FRONTEND_REDIRECT_URL`의 origin도 allowlist에 포함합니다.

```text
CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
```

운영에서는 wildcard origin을 사용하지 않고 localhost origin도 자동으로 허용하지 않습니다. Localhost origin은 development/test 환경에서만 자동 추가되며, 운영에서 필요하면 `CORS_ALLOWED_ORIGINS`에 명시해야 합니다. OAuth provider, A서버의 server-to-server token verification, DB 접속은 CORS 대상이 아닙니다. CORS는 브라우저 보안 정책이므로 A서버 backend가 JWT를 검증하는 흐름을 막지 않습니다.

## Rate Limits

`AUTH_RATE_LIMIT_WINDOW_SECONDS`와 `AUTH_RATE_LIMIT_MAX_REQUESTS`는 login/register/email verification/password reset 같은 auth-sensitive endpoint에 적용됩니다.

운영자가 결정할 것:

- 사용자 경험을 해치지 않는 최대 요청 수
- 프록시 뒤에서 실제 client IP를 식별하는 방식
- 과도한 실패가 발생할 때 alert을 보낼 기준
- password reset과 email verification 요청의 별도 제한이 필요한지 여부

기본 정책은 brute-force와 email abuse를 줄이는 것이며, 없는 계정과 있는 계정의 응답 형태는 가능한 같게 유지합니다.

## Audit Log Retention

`audit_logs`는 register/login failure/login success/lockout/email verification/password reset/refresh/logout/security failure 같은 인증 보안 이벤트를 기록합니다.

보관 정책 권장값:

- 운영 online DB: 90일에서 180일
- 장기 보관 archive: 내부 보안/감사 기준에 따라 1년 이상 여부 결정
- 삭제 또는 archive 작업은 정기 batch로 수행

Audit log에 저장하지 않는 값:

```text
비밀번호 원문, refresh token 원문, access token 원문, provider access token,
verification token 원문, password reset token 원문, OAuth authorization code
```

보안 조사에 필요한 최소 metadata만 저장하고, 개인정보 보관 기간은 회사 정책과 법무 기준에 맞춥니다.

## A서버 통합

`examples/service-server`에는 A서버에서 사용할 수 있는 Express 예시가 포함되어 있습니다.

- `src/middlewares/verifyAccessToken.ts`: Bearer token 파싱, signature/issuer/audience/expiration 검증, `req.authUser` 주입
- `src/middlewares/requireRole.ts`: JWT roles에서 필요한 `serviceKey:name` 권한 확인
- `src/routes/me.routes.ts`: JWT payload 기준 `/me` 응답 예시

A서버 통합 체크리스트:

- B서버와 같은 `JWT_ACCESS_SECRET` 또는 공개키 검증 설정을 주입합니다. 예시 A서버의 `AUTH_JWT_ACCESS_SECRET`은 누락되거나 `replace-access-secret` placeholder이면 시작 시 실패합니다.
- `JWT_ISSUER`와 `JWT_AUDIENCE`를 서비스별로 고정합니다.
- JWT `sub`를 `authUserId`로 저장합니다.
- 최초 접근 시 A서버 DB에 `service_users.authUserId` row를 생성합니다.
- 서비스 데이터는 `serviceUserId`나 A서버 내부 key로 연결합니다.
- Refresh Token endpoint는 프론트엔드가 B서버로 호출하게 두고 A서버 API에서는 받지 않습니다.
- A서버 운영자에게 auth DB credential을 배포하지 않습니다.

## 운영 배포 체크리스트

- HTTPS만 사용하고 OAuth redirect URI도 HTTPS로 등록합니다.
- `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `SMTP_PASSWORD`, OAuth client secret은 secret store로 주입합니다.
- Access Token 만료시간은 짧게 유지합니다. 기본 예시는 `15m`입니다.
- Refresh Token 원문은 DB에 저장하지 않고 hash만 저장합니다.
- 비밀번호 원문은 저장하지 않고 Argon2id hash만 저장합니다.
- Email verification과 password reset token은 hash로만 저장합니다.
- CORS는 운영 프론트엔드 도메인으로 제한합니다.
- Rate limit 값은 프록시/IP 정책과 함께 점검합니다.
- Audit log retention과 backup retention을 문서화합니다.
- Backup restore test를 정기적으로 수행합니다.
- 로그에 provider access token, refresh token, authorization code, password reset token을 남기지 않습니다.
- `helmet`을 기본 적용하지만, 프록시와 쿠키 정책을 사용하는 경우 추가 보안 헤더를 점검합니다.
- `User.email`은 nullable이며, 같은 email이어도 provider가 다르면 자동 병합하지 않습니다. 이미 존재하는 email이면 새 사용자의 email은 `null`로 저장하고 `SocialAccount.providerEmail`에는 provider email을 보존합니다.
- Refresh Token rotation이 적용되어 `/auth/refresh` 호출 시 기존 refresh token은 폐기되고 새 refresh token이 발급됩니다.

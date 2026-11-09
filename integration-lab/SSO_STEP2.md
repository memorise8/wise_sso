# 중앙 SSO 세션: 로컬 검증 2단계

작성일: 2026-11-02. 전제: POLICY_STEP1 마이그레이션과 브라우저 검증 완료.
대상은 로컬 개발 브랜치이며 commit/push/운영 배포는 하지 않는다.

## 변경 내용

- OIDC 로그인 성공 시 Redis 중앙 세션을 생성한다. 브라우저에는 256비트 난수 쿠키 `__Host-wise_sso`만 전달한다. 쿠키는 Secure, HttpOnly, SameSite=Lax, Path=/, Domain 없음이며 Redis 키에는 쿠키 값의 SHA-256만 사용한다. 세션 TTL은 절대 8시간이고 서비스 이동으로 연장되지 않는다.
- 대상 client의 redirect URI, scope, PKCE를 먼저 검증하고 중앙 세션이 유효하면 인가 코드를 발급한다. 사용자 상태·유형·역할은 매번 DB에서 확인한다. 다른 서비스의 역할을 복사하지 않는다.
- `prompt=none`: 유효 세션이면 UI 없이 처리하고, 인증이 필요하면 검증된 callback으로 `login_required`와 원래 state를 반환한다. 서비스 권한 부족은 `access_denied`다.
- `prompt=login`, `prompt=select_account`, `max_age=0`은 입력 화면으로 보낸다. 양수 max_age는 마지막 실제 인증 시각으로 판단한다. 새 ID Token의 auth_time은 원래 인증 시각을 유지한다.
- 새로 입력해 로그인할 때 중앙 세션 ID를 교체하고 이전 브라우저 세션을 폐기한다. 감사 로그 실패 등 완료 실패 시 준비한 인가 코드와 중앙 세션을 폐기한다.
- `User.ssoSessionVersion`을 추가한다. 관리자 전체 세션 폐기/정지/역할 회수/유형 변경, 비밀번호 재설정, 관리자 bootstrap에서 증가시킨다. 버전이 다른 중앙 세션·새 OIDC 코드·새 OIDC UserInfo 토큰은 재사용하지 않는다. 버전 증가는 DB 변경/감사 로그와 같은 트랜잭션에서 수행된다.
- `/oauth2/session`에서 중앙 세션 종료를 확인한다. 종료는 같은 Origin의 POST + CSRF 검증을 요구한다. GET이나 외부 redirect 파라미터로 세션을 종료하지 않는다. 비밀 토큰을 URL에 넣지 않는다.
- 더미 화면에 중앙 세션 관리 및 다른 계정으로 재인증 링크를 추가한다. 프록시가 재생성된 upstream의 IP를 사용하도록 lab up 후 nginx 설정을 다시 읽는다.

참고 규격: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest 의 prompt/max_age, ID Token의 auth_time.

## 적용

ZIP의 apply.py로 소스를 적용한 다음 아래 명령을 저장소 루트에서 수행한다.
.env, integration-lab/.local, 기존 소셜 로그인 변경 3개 파일은 교체하지 않는다.

### 1. 로컬 DB 백업 및 앱 중지

```bash
umask 077
docker compose -f docker-compose.oauth-local.yml exec -T postgres \
  pg_dump -U fastapi_dev -d fastapi_sso_dev > ../wise-sso-before-sso-session.sql
ls -lh ../wise-sso-before-sso-session.sql
docker compose -f docker-compose.oauth-local.yml stop app
```

백업 명령 실패 시 진행하지 않는다. PostgreSQL/Redis/볼륨은 삭제하지 않는다.

### 2. 신규 마이그레이션

```bash
docker run --rm \
  --network wiseacct-sso-wiseacct-oauth_oauth-network \
  --mount "type=bind,source=$PWD/auth-server/prisma,target=/schema,readonly" \
  -e DATABASE_URL='postgresql://fastapi_dev:synthetic-fastapi-db-only@postgres:5432/fastapi_sso_dev' \
  -w /tmp \
  node:22-bookworm \
  npx --yes prisma@6.19.3 migrate deploy --schema=/schema/schema.prisma
```

10 migrations 중 `20261102010000_central_sso_sessions`만 새로 적용되는 것이 정상이다.
이 컬럼이 없으면 새 앱을 시작하지 않는다. 실패 시 강제 resolve나 migration 기록 삭제를 하지 않는다.

### 3. 앱과 더미 재빌드 및 실행

```bash
docker compose -f docker-compose.oauth-local.yml build app
bash integration-lab/lab.sh build
bash integration-lab/lab.sh up
bash integration-lab/lab.sh ps
bash integration-lab/lab.sh policy-check
bash integration-lab/lab.sh sso-check
```

기존 fixture와 client 설정을 유지한다. setup/seed/policy-setup 재실행은 필요하지 않다.
`sso-check`는 container loopback의 실제 앱/DB/Redis를 검사한다. HTTPS URL을 쿠키 판정에 사용하고 HTTP 요청만 컨테이너 내부 loopback으로 전달하며 TLS 검증을 전역 비활성화하지 않는다. 프록시 TLS 자체를 검증하는 도구는 아니므로 아래 브라우저 검사도 수행한다.

기대 출력은 PASS 6개다:

1. 세션 없는 prompt=none → login_required
2. 직원 로그인 후 직원 서비스에서 중앙 세션 재사용
3. max_age=0 → 재인증 화면
4. 중앙 세션 종료 → 재사용 불가
5. 고객 중앙 세션 → 직원 서비스 거부
6. 관리자 세션 폐기 → 고객 중앙 세션 무효

테스트는 토큰/인가 코드/비밀번호를 출력하지 않는다. 테스트용 고객 계정의 세션 폐기를 실제로 실행하고 감사 로그를 남긴다. 기존 고객 테스트 브라우저 세션도 다음 검증 시 재로그인해야 할 수 있다. 오류는 마지막 PASS 위치와 앱 로그로 확인한다. 기존 rate limit 때문에 반복 실행 시 429가 발생하면 1분 뒤 다시 실행한다.

## 브라우저 검증

기존 계정/세션과 혼동하지 않도록 새 시크릿 창에서 시작한다. 세 HTTPS 주소의 로컬 인증서 경고는 이전처럼 해당 localhost만 예외 처리한다.

| 순서 | 작업 | 기대 결과 |
| --- | --- | --- |
| 1 | https://localhost:4445 에서 employee 계정으로 로그인 | 첫 인증은 이메일/비밀번호 입력 |
| 2 | 직원용 링크 https://localhost:4446 → wise-sso로 로그인 버튼 | 입력 화면 없이 직원용 로그인 성공 |
| 3 | https://localhost:4446/login?prompt=login | 중앙 세션이 있어도 로그인 입력 화면 |
| 4 | https://localhost:4446/login?max_age=0 | 로그인 입력 화면 |
| 5 | https://localhost:4444/oauth2/session 에서 중앙 세션 종료 | 종료 완료 안내 |
| 6 | https://localhost:4446/login?prompt=none | 인증 필요로 실패, 입력 화면 자동 표시 없음 |
| 7 | 새 계정 검증 전에 모든 시크릿 창을 닫고 새로 열기 | 기존 더미/중앙 쿠키와 분리 |
| 8 | 고객용에서 customer 로그인 후 직원용 로그인 버튼 | 입력 생략 후 직원용 접근 거부 |

종료된 거래의 뒤로 가기/새로고침 대신 각 서비스의 새 로그인 링크로 시작한다.
더미 홈은 로그인 버튼을 표시할 수 있다. 버튼을 누른 뒤 자격증명 재입력이 생략되는 것이 이번 SSO 검증 기준이다.

## 세션 종류와 제한

- 중앙 SSO 세션: 앞으로 다른 client에서 재인증을 생략할 수 있는 인증 상태.
- 서비스 세션: 더미가 자체 보관하는 로그인. 더미는 홈마다 userinfo를 다시 확인하고 불투명 토큰은 5분 동안 유효하다. 중앙 세션이 살아 있으면 새 로그인으로 입력을 생략할 수 있다.
- 중앙 세션 종료는 해당 브라우저 중앙 세션만 종료한다. 이미 발급된 서비스 세션/ID Token을 모든 서비스에서 즉시 없애는 통합 로그아웃은 아직 아니다. 표준 end_session/back-channel logout은 후속 작업이다.
- 계정 전환도 다른 서비스의 기존 자체 세션을 바꾸지 않는다. 다른 사용자 테스트에서는 더미 자체 로그아웃/새 시크릿 환경을 사용한다.
- 관리자 전체 세션 폐기는 버전을 올리므로 이 변경 이후 발급된 OIDC userinfo 토큰도 다음 조회부터 거부된다. ID Token만 로컬 검증하며 자체 세션을 유지하는 실제 하위 서비스는 별도 폐기 연동이 필요하다.
- 배포 직전 구버전 코드(최대 60초)와 userinfo 토큰(최대 5분)은 버전 필드 없이 남아 있을 수 있다. 기존 레거시 JWT의 폐기/역할 최소화 정책은 이번에 변경하지 않았다.
- 중앙 세션은 `/oauth2`의 비밀번호/등록된 소셜 인증 완료 경로에서 발급한다. 레거시 `4003/auth/.../callback` 로그인은 아직 중앙 세션 발급과 통합하지 않았다. 로컬 검증은 비밀번호 OIDC 경로를 사용한다.
- 쿠키는 포트가 아니라 호스트 단위다. 로컬 더미 4444/4445/4446은 같은 localhost를 공유하는 신뢰된 실험실이다. 운영에서는 인증 서버와 서비스에 분리된 호스트를 사용해야 한다.

## 검증 기록과 남은 작업

개발 환경에서 실제 코드의 HTTP 경로 + Redis 저장소 fake + DB identity fake로 세션 재사용/만료/버전 폐기/CSRF/권한 거부/오류 정리/서명 auth_time을 검증했다. 기존 단위/관리자 HTTP/dispatch 회귀 검사는 638개 통과(12개 skip, Node oracle 1개 제외), 더미 테스트는 20개 통과했다. Python 소스·테스트 136개 파일의 mypy와 변경 소스 Ruff도 통과했다. embedded PostgreSQL에서 전체 10개 마이그레이션과 버전 기본값/증가도 확인했다.

실제 Docker PostgreSQL16/Redis/nginx/브라우저 결과는 위 로컬 검증 후 기록한다. Node Express IPC oracle과 기존 성능 collector frozen manifest 문제는 이전 단계와 동일하게 별도다.

남은 항목은 실제 하위 서비스 연동, 통합 로그아웃, client DB 관리, 관리자 MFA, 명시적 계정 연결, Fantra 토큰 역할 최소화다. 이 단계가 운영 배포 완료를 의미하지 않는다.

# 2026-11-04 브랜치 피드백 반영·로컬 확인

대상: feat/local-auth-policy. 원격 원본 커밋 2b65126. 최신 main 7fc3a19 위에 작업 사본을 rebase했다. 원격 브랜치나 운영 환경은 이 작업으로 변경하지 않았다. 기존 고객 가입 패키지는 계속 미적용·보류다.

## 정책 수정

- 모든 OIDC client에 allowedUserTypes를 명시해야 한다. 누락하면 설정 검증 실패다. 예시·preview 설정·회귀 fixture도 수정했다.
- ssoAutoLogin은 client별 boolean이고 기본 true다. false면 유효한 중앙 세션이 있어도 대화형 로그인을 요구하고 prompt=none에는 login_required를 돌려준다. 인증 이후 사용자 유형/역할 검사는 계속 적용한다.
- 초기 정책 마이그레이션은 temis:admin을 회수하지 않고 sso:admin만 추가한다. 마이그레이션 신규 감사 기록의 userId/actorUserId는 NULL이다. FastAPI는 새 temis:admin 부여를 거부한다.
- 자신 또는 마지막 활성 중앙 관리자를 ACTIVE 이외의 어떤 상태로도 바꾸지 못한다. 비활성 상태 전환은 Refresh Token과 중앙 세션 버전도 회수한다.
- 일괄 유형 변경의 reasonCode는 생략할 수 없다. 클라이언트/검사 스크립트도 이를 보낸다.
- Naver/Kakao 버튼은 해당 provider 활성화와 ID·secret 설정이 모두 있을 때만 서버가 표시한다. 키 값은 HTML/JS에 전달하지 않는다. FastAPI와 auth-server/public의 auth-portal.html 원본은 동일하게 맞췄다.
- XSS oracle의 DOM setAttribute를 보완했다. 기존 XSS 검증은 유지한다.

## 서비스 정책과 client ID 충돌

| 서비스 | OIDC client ID 예시 | 유형 | 필요 역할 |
| --- | --- | --- | --- |
| GitLab | gitlab-temis | EMPLOYEE | gitlab:user |
| 업무 대시보드 | agent-hub-dash | EMPLOYEE | agent-hub:user |
| Fantra | fantra-oidc | CUSTOMER, EMPLOYEE | temis:user |

**temis는 기존 AUTH_CLIENTS_JSON의 legacy client ID/audience다.** 기존 Settings는 OIDC와 legacy ID/audience 중복을 차단한다. 그 보안 경계는 제거하지 않았다. 신규 OIDC 예시만 fantra-oidc라는 구분된 ID를 사용한다. 실제 Fantra가 legacy temis 흐름을 유지할지 신규 OIDC를 붙일지는 실제 설정 확인 후 결정해야 한다. 기존 temis/Fantra client, callback, audience는 이 작업으로 임의 변경하지 않는다.

ops/deployment/oidc-clients.production.example.json과 production.env.example은 템플릿이다. 실제 callback과 비밀값을 채우기 전에는 사용할 수 없다. 운영 env를 내보내거나 안전한 파일 경로로 검사한다. 전체 env/출력을 공유하지 않는다.

```bash
cd fastapi-auth-server
bash ops/check-prod-env.sh --env-file /private/path/production.env
```

운영 DB 연결·메일 발송·환경 수정은 이 검사가 수행하지 않는다. 현재 preflight의 Fantra OIDC 예시는 fantra-oidc를 요구하므로 legacy 유지 운영에는 그대로 적용하지 말고 연결 계약을 확정한다.

## 직원 초대

HTTPS 관리자 화면에 이메일·이름·서비스 역할 입력과 초대 목록/재발송/취소를 제공한다. 역할은 `gitlab:user,agent-hub:user`처럼 입력한다. sso:admin을 부여하면 중앙 관리자 권한까지 생기므로 승인 범위를 검토한다. temis:admin은 초대에서도 금지한다.

- 계정은 초대 생성 시 만들지 않는다. 수락 시 신규 EMPLOYEE·ACTIVE·이메일 인증 계정과 비밀번호 hash, 지정 역할을 한 트랜잭션으로 생성한다.
- 이메일이 이미 존재하면 초대/수락을 거부한다. 기존 고객을 이메일만으로 직원으로 승격하거나 소셜 계정을 자동 연결하지 않는다.
- 토큰은 32바이트 난수이며 DB에는 SHA-256 hash만 저장한다. 72시간 만료·일회용이다. 수락 시 행 잠금으로 재검사한다. 재발송은 token과 만료 시각을 교체한다. 취소·사용·만료 토큰은 거부한다.
- 초대 링크는 #token fragment를 사용한다. 수락 화면 JS가 URL에서 즉시 제거하고 POST 본문으로 보낸다. 관리자 API·목록·감사 로그에 원문 token이나 비밀번호를 돌려주지 않는다.
- 변경 요청은 기존 관리자 쿠키 인증·Origin·CSRF를 적용한다. 공개 수락도 Origin과 HttpOnly cookie에 묶인 CSRF를 검사한다.
- 생성·재발송·취소·수락·메일 실패를 감사 기록에 남긴다. 메일 실패 시 초대를 목록에서 찾아 재발송한다. DevMail은 링크를 로그로 노출하지 않고 발송 실패로 처리한다. 실제 운영은 SMTP/Resend가 필요하다.
- 일반 공개 가입은 계속 CUSTOMER다. 직원 초대가 공개 가입에 직원 선택지를 추가하지 않는다.

## 로컬 마이그레이션과 실행

먼저 기존 로컬 DB를 백업하고 app을 중지한다. 운영 DB에 실행하는 명령이 아니다.

```bash
umask 077
docker compose -f docker-compose.oauth-local.yml exec -T postgres \
  pg_dump -U fastapi_dev -d fastapi_sso_dev > ../wise-sso-before-review.sql
docker compose -f docker-compose.oauth-local.yml stop app

docker run --rm \
  --network wiseacct-sso-wiseacct-oauth_oauth-network \
  --mount "type=bind,source=$PWD/auth-server/prisma,target=/schema,readonly" \
  -e DATABASE_URL='postgresql://fastapi_dev:synthetic-fastapi-db-only@postgres:5432/fastapi_sso_dev' \
  -w /tmp node:22-bookworm \
  npx --yes prisma@6.19.3 migrate deploy --schema=/schema/schema.prisma
```

새 마이그레이션은 EmployeeInvitation 테이블과 이전 초안에서 회수한 legacy 역할 복구다. 복구는 기존 POLICY_MIGRATION의 temis:admin 회수 감사 기록이 있는 사용자에게만 적용한다. 신규 DB에는 해당 회수 기록이 없으므로 복구 작업은 없다.

이미 적용한 초기 정책 SQL을 수정했으므로 기존 로컬 DB에서 Prisma의 migration modified 경고가 나올 수 있다. checksum을 강제로 덮어쓰거나 migrate reset으로 데이터를 지우지 않는다. Prisma 6 migrate deploy는 수정 경고 후 대기 중 마이그레이션을 적용할 수 있다. 경고를 숨기지 말고 배포 전에 이력을 검토한다. 기존 역사적 감사 로그는 재작성하지 않는다.

로컬 초대 메일 검증은 별도의 opt-in Mailpit overlay다. 미적용 고객 가입 패키지를 적용하는 것이 아니다. 새 SMTP 인증서를 생성하면서 기존 .env, fixture 비밀번호, 브라우저 TLS, client secret은 유지한다.

```bash
bash integration-lab/lab.sh build
bash integration-lab/lab.sh setup
docker compose -f docker-compose.oauth-local.yml build app
bash integration-lab/lab.sh invitation-mail-up
bash integration-lab/lab.sh invitation-check
bash integration-lab/lab.sh admin-login-check
bash integration-lab/lab.sh bulk-check
bash integration-lab/lab.sh policy-check
bash integration-lab/lab.sh sso-check
```

invitation-check 기대 출력은 PASS 6개다. 실제 로컬 앱/DB/SMTP에서 생성·재발송·이전 링크 차단·수락·재사용 차단·직원 로그인·취소·감사를 검사한다. 임의 합성 이메일과 무작위 비밀번호를 사용하고 token/비밀번호는 출력하지 않는다. 검사용 직원 계정과 감사 기록은 남고 중앙 세션은 종료한다.

수동 확인: https://localhost:4444/oauth2/admin/dashboard 에 employee 관리자 로그인 → 새 `staff-review-01@wise-lab.invalid` 주소와 이름·lab-staff:user 역할로 초대 → http://127.0.0.1:8025 로컬 메일에서 링크 열기 → 직원 창에서 직접 비밀번호 설정 → https://localhost:4446/login 로그인. 재발송한 이전 링크와 취소 링크도 거부되는지 확인한다. 초대 URL이나 입력한 비밀번호를 기록/공유하지 않는다.

Mailpit UI는 127.0.0.1:8025에만 공개하고 SMTP 포트는 외부에 열지 않는다. @wise-lab.invalid 수신만 허용하며 외부로 전달하지 않는다. TLS 검증은 유지하고 기존 공개 CA와 로컬 SMTP 인증서를 묶은 파일을 app에만 마운트한다. enable marker가 있으면 이후 lab.sh up/config도 mail overlay를 포함한다. 원래 메일 구성으로 복원하려면 실험실 mailpit을 중지하고 .local/invitation-mail.enabled만 제거한 뒤 lab.sh up을 실행한다.

## 기존 사용자 분류: 실행 권한은 운영자에게

ops/user-types/preview.sql은 BEGIN TRANSACTION READ ONLY로 건수와 최대 10개씩의 익명 샘플을 조회하고 ROLLBACK한다. userType 컬럼이 아직 없는 운영 schema도 미분류로 취급하여 조회할 수 있다. 이메일·원문 ID 대신 ID의 짧은 hash를 출력한다.

사내 역할 판정은 gitlab/agent-hub/lab-staff/sso 서비스의 역할 또는 legacy temis:admin이다. 이 목록 외에 사내 서비스 역할이 있는지는 운영자가 먼저 확인한다. temis:user만 있는 사용자와 역할이 없는 사용자는 CUSTOMER 대상이다. 기존에 분류된 사용자는 변경하지 않는다.

운영 접속 정보가 제공되지 않아 **실제 운영 건수/샘플은 조회하지 않았다.** PR에는 미조회로 명시한다. 운영자가 read-only PostgreSQL service 설정을 마련한 경우 다음처럼 조회할 수 있다.

```bash
psql 'service=wise_sso_readonly' -X -v ON_ERROR_STOP=1 \
  -f fastapi-auth-server/ops/user-types/preview.sql \
  > ../wise-sso-user-type-preview.txt
```

ops/user-types/apply.sql은 운영자가 검토 후 별도로 실행할 쓰기 SQL이다. 배포/검사 스크립트에서 자동 실행하지 않는다. userType 컬럼 마이그레이션 이후에만 적용한다. 미분류 계정만 분류하고 세션 버전·Refresh Token을 회수하며 system actor로 감사 기록을 남긴다. 재실행은 변경 0건이다.

## 검증 증거와 남은 확인

- 단위/관리자 HTTP/OIDC dispatch: 727 passed, 12 skipped, Node Express IPC oracle 1개 제외. 테스트 제외/권한 제약은 전체 통과로 포장하지 않는다.
- 정적 자산/정책/초대 HTTP 묶음: 14 passed + 109 subtests passed.
- 보안 번들 관련 security_gate/downstream: 원본 2b65126과 수정본 모두 81 passed. 피드백의 보안 번들 실패는 현재 환경에서 재현하지 못했다. 정확한 테스트 이름과 실패 traceback이 필요하며 미확인으로 남긴다. 검증 기준이나 보안 gate를 완화하지 않았다.
- mypy: 145개 소스 파일 통과. 변경 Python Ruff, JS/bash 문법 검사 통과. Prisma 6.19.3 validate 통과.
- PGlite 임시 WASM PostgreSQL에서 새 마이그레이션·이전 초안 복구·읽기 전용 preview·분류 멱등성을 검사했다. 직원 초대 서비스가 생성한 SQL도 replay하여 EMPLOYEE·ACTIVE·역할/FK를 확인했다. 실제 운영 조회 결과가 아니다.
- 실제 로컬 Docker/PostgreSQL/SMTP에서 마이그레이션과 자동 검사 27개를 통과했고, 직원 초대 브라우저 수동 검증도 완료했다. 운영 환경·실제 서비스 확인은 아직이며 운영 배포나 원격 PR 게시는 수행하지 않았다.

참고: https://docs.prisma.io/docs/orm/v6/prisma-migrate/workflows/development-and-production


## 임시 PostgreSQL 검증 재현 (개발자용)

운영 DB에 연결하지 않는 선택적 검사다. FastAPI dev 가상환경에서 저장소 루트 기준으로 실행한다. PGlite는 앱 런타임 의존성에 추가하지 않는다.

```bash
npm install --prefix /tmp/wise-review-pglite --no-audit --no-fund @electric-sql/pglite@0.3.14
PYTHONPATH=fastapi-auth-server/src python integration-lab/tests/export-invitation-statements.py
PGLITE_MODULE_PATH=/tmp/wise-review-pglite/node_modules/@electric-sql/pglite/dist/index.js \
INVITATION_SQL_PATH=/tmp/invitation-statements.json \
node integration-lab/tests/review-migrations.mjs
```

합성 SQL export에는 실제 비밀번호/원문 초대 token이 없고 가짜 hash와 합성 계정만 있다. 기존 초안 비교를 위해 Git의 2b65126 커밋이 필요하다. 실제 SMTP·Docker·동시성 검증을 대체하지 않는다.


## 2026-11-05 로컬 검증 완료

사용자 로컬에서 직원 초대 테이블 및 이전 초안의 legacy 역할 복구 마이그레이션 2개를 적용했다. 실제 Docker·PostgreSQL·Redis·로컬 SMTP 환경의 자동 검사 27개가 통과했다.

| 검사 | 통과 |
| --- | ---: |
| 직원 초대 | 6 |
| 관리자 브라우저 로그인 | 7 |
| 사용자 유형 일괄 변경 | 5 |
| 사용자 유형·관리자 정책 | 3 |
| 중앙 SSO 세션 | 6 |
| 합계 | 27 |

관리자 화면의 신규 직원 초대 → 로컬 메일함 수신 → 초대 링크에서 직원이 직접 비밀번호 설정 → 직원 더미 로그인까지 브라우저에서 확인했다. 재발송·이전 링크 거부·일회용 수락·취소·감사 기록은 자동 검사로 확인했다. 72시간 만료 경계는 개발 회귀 검사로 확인했으며 실제 72시간을 기다린 검사는 아니다.

운영 DB 사용자 분류 건수·샘플은 미조회다. 보안 번들 실패 traceback과 실제 Fantra/GitLab/업무 대시보드 연동은 미확인이다. 고객 가입 패키지는 계속 미적용·보류다. 이 로컬 검증을 운영 배포 완료로 취급하지 않는다.

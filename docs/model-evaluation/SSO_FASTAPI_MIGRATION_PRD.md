# Reference SSO FastAPI Migration PRD

## 1. 문서 정보

- 목적: 여러 언어 모델 또는 코딩 에이전트가 기존 Express SSO를 Python/FastAPI로 얼마나 정확하고 안전하게 이식하는지 평가한다.
- 문서 성격: 모델 입력용 비식별화 PRD다.
- 기준 구현: 제공되는 Express/TypeScript 서버가 현재 동작의 oracle이자 rollback 기준이다.
- 후보 구현: Python/FastAPI 기반의 독립 서버다.
- 운영 원칙: 별도 승인 전까지 Express만 운영하며 후보 서버는 운영 traffic, 운영 DB, 운영 Redis에 접근하지 않는다.
- 기본 readiness 판정: 모든 검증이 끝나기 전에는 `NOT_READY`다.

이 문서는 실제 credential, 운영 주소, 사용자 정보, container 식별자, 현재 FastAPI 해답과 구현 이력을 포함하지 않는다.

## 2. 배경과 문제

현재 SSO는 Express/TypeScript, PostgreSQL, Redis를 사용하며 비밀번호 인증, JWT, OAuth, PKCE handoff, 관리자 기능과 감사 로그를 제공한다. 조직의 Python 통합 요구에 따라 이를 FastAPI로 이식하려 한다.

이 작업은 신규 인증 제품을 설계하는 프로젝트가 아니다. 후보 서버는 기존 사용자가 가진 계정, password hash, refresh session, OAuth identity, 역할과 relying-party 연동을 변환 없이 처리해야 한다. 후보 구현의 편의보다 기존 외부 계약과 상태 전이 호환성이 우선한다.

## 3. 비즈니스 목표

1. SSO 서버의 주 개발 언어를 Python으로 통합한다.
2. relying-party와 사용자가 교체를 인지하지 않도록 외부 계약을 보존한다.
3. 기존 PostgreSQL schema와 Redis namespace를 그대로 사용할 수 있게 한다.
4. Express와 후보 서버가 같은 상태를 읽고 쓰는 전환 구간에서도 데이터 무결성을 보장한다.
5. 실패 시 schema downgrade나 데이터 변환 없이 Express로 복귀할 수 있게 한다.
6. 구현 완료, 검증 완료, 운영 교체 가능 판정을 명확히 분리한다.

## 4. 비목표

- relying-party의 업무 권한 체계를 SSO로 통합하지 않는다.
- PostgreSQL schema migration ownership을 즉시 Python으로 넘기지 않는다.
- OAuth provider, 메일 provider 또는 ingress를 교체하지 않는다.
- 기존의 의도치 않은 동작을 근거 없이 보안 개선으로 변경하지 않는다.
- 이 개발 과정에서 production canary, credential rotation 또는 routing 변경을 실행하지 않는다.

## 5. 사용자와 시스템 역할

- 일반 사용자: 이메일과 비밀번호로 가입, 인증, 로그인한다.
- 소셜 로그인 사용자: Google, Naver 또는 Kakao identity로 로그인한다.
- Relying-party/BFF: 일회용 handoff code를 token pair로 교환한다.
- Relying-party API: Access Token을 검증하고 SSO DB나 Refresh Token을 직접 처리하지 않는다.
- 관리자: 사용자 상태, 역할, session을 관리하고 감사 로그를 조회한다.
- 운영자: 최초 관리자 부여, token 정리, 감사 retention, 배포와 복구를 담당한다.
- 외부 의존성: PostgreSQL, Redis, OAuth provider, SMTP 또는 메일 provider다.

## 6. 시스템 소유 경계

SSO가 소유하는 데이터:

- 사용자 인증 identity와 상태
- password credential과 pending credential
- 소셜 계정 연결
- refresh token hash와 폐기 상태
- verification/reset token hash
- OAuth state와 auth handoff
- 서비스 단위 역할
- 인증 및 관리자 감사 로그

SSO가 소유하지 않는 데이터:

- 프로젝트, 문서, 결제, 고객사 업무 데이터
- 각 relying-party 내부의 세부 업무 권한

Relying-party는 JWT `sub`를 외부 연결 키로 사용하며 SSO DB를 직접 조회하지 않는다.

## 7. 공통 호환 원칙

- Express source와 실행 결과를 읽고 검증할 수 있어야 한다.
- method, path, status, body, header, redirect, validation 순서와 error envelope를 보존한다.
- 시간, UUID, token처럼 매번 달라지는 값은 의미를 훼손하지 않는 방식으로 비교한다.
- PostgreSQL row 변화, Redis key/value/TTL/consume 결과와 audit delta를 HTTP 응답과 함께 비교한다.
- 기능별 transaction, lock, commit, 외부 side effect 순서를 하나의 일반 추상화로 임의 통합하지 않는다.
- 보안 개선 때문에 의도적으로 parity를 깨야 한다면 양 구현을 함께 변경하고 기준을 다시 동결해야 한다.

## 8. 기능 요구사항

### 8.1 시스템 및 공개 HTTP 표면

- process liveness와 PostgreSQL readiness endpoint를 분리한다.
- 공개 JWKS와 OpenID discovery metadata를 제공한다.
- 기존 portal, callback, 관리자 dashboard와 static asset 경로를 유지한다.
- static cache, CORS, security header, HEAD/OPTIONS 동작을 유지한다.
- 알 수 없는 경로와 모든 오류는 기존 `{ "error": { "code": "...", "message": "..." } }` 형식으로 반환한다.
- 프레임워크 기본 validation payload를 외부로 노출하지 않는다.
- 기존 전역 JSON parser의 content type, charset, 압축, 크기 제한과 오류 우선순위를 호환한다.

### 8.2 가입 및 비밀번호 로그인

- 이메일 normalization과 선택적 회사 domain 정책을 유지한다.
- 최소 비밀번호 길이를 설정으로 제어한다.
- 가입과 복구 요청은 계정 존재 여부를 노출하지 않는다.
- 가입 사용자는 이메일 인증 전 상태로 생성되며 인증 전 token을 받을 수 없다.
- 기존 Argon2id hash를 검증하고 새 hash를 Express가 검증할 수 있어야 한다.
- 없는 계정에도 dummy password verification을 수행한다.
- 실패 횟수와 lockout을 동시 요청에서도 정확히 적용한다.
- 성공 로그인은 실패 횟수와 잠금 상태를 초기화한다.

### 8.3 이메일 인증

- request endpoint는 generic accepted 응답을 사용한다.
- raw token은 메일로만 전달하고 DB에는 SHA-256 hash만 저장한다.
- token은 기존 TTL과 single-use 규칙을 따른다.
- 성공 시 신규 사용자를 활성화하거나 기존 계정에 pending password credential을 연결한다.
- 요청에 handoff metadata가 포함되면 인증 완료 후 일회용 handoff를 생성한다.
- 같은 token의 동시 confirm은 정확히 한 번만 성공한다.
- token consume 이후 발생하는 실패의 commit/rollback 경계를 Express와 맞춘다.

### 8.4 비밀번호 재설정

- request endpoint는 계정 존재 여부를 노출하지 않는다.
- raw reset token을 DB에 저장하지 않는다.
- token은 기존 TTL과 single-use 규칙을 따른다.
- 성공 시 password hash와 관련 timestamp, 실패 횟수와 lock 상태를 갱신한다.
- 성공 시 해당 사용자의 모든 active refresh token을 폐기한다.
- 동일 token의 concurrent confirm은 정확히 한 번만 성공한다.

### 8.5 Access Token과 Refresh Token

- Access Token은 비대칭 서명과 고정 허용 algorithm을 사용한다.
- issuer, audience, expiry와 token type을 검증한다.
- `kid` 선택·불일치 동작은 현재 Express oracle을 우선하며, 양 runtime의 동시 hardening 또는 명시적 위험 수용을 refreeze 전에 결정한다.
- Access Token은 최소 사용자 identity, 이메일 인증 상태, 역할, 발급·만료 정보와 audience를 담는다.
- JWKS로 Express와 후보 서버의 Access Token을 교차 검증한다.
- Refresh Token은 현재 Express와 호환되는 HMAC algorithm과 claim 계약을 사용한다.
- 다른 HMAC algorithm, `none`, access/refresh type confusion을 거부한다.
- raw Refresh Token은 DB에 저장하지 않고 SHA-256 hash만 저장한다.
- rotation은 기존 token 폐기와 replacement 발급을 안전한 상태 전이로 처리한다.
- 같은 Refresh Token의 concurrent refresh는 한 요청만 성공한다.
- client audience가 다른 곳에서 Refresh Token을 재사용하지 못한다.
- suspended/deleted 사용자는 신규 token 발급과 refresh가 불가능하다.
- logout은 기존 HTTP 및 audit 계약에 따라 Refresh Token을 폐기한다.

### 8.6 Handoff 및 PKCE

- browser redirect에 Access Token이나 Refresh Token을 포함하지 않는다.
- password, verification, OAuth 성공은 허용된 client에 짧은 수명의 일회용 handoff를 만들 수 있다.
- handoff는 client, audience, exact redirect URI, state, PKCE S256 challenge에 결합된다.
- exchange body는 기존 camelCase field만 허용하고 extra field를 거부한다.
- invalid, expired, replayed code와 binding/verifier mismatch는 정보 노출이 적은 오류로 처리한다.
- 잘못된 binding 시도가 올바른 consumer의 code를 불필요하게 소비해서는 안 된다.
- token 발급 실패 후 이미 소비된 handoff가 재생돼서는 안 된다.

### 8.7 OAuth

- Google, Naver, Kakao start와 callback을 지원한다.
- 활성 provider와 필수 설정을 시작 전에 검증한다.
- OAuth state는 opaque하고 provider/client/request metadata에 결합되며 짧은 TTL과 single-use 규칙을 가진다.
- provider callback 오류, timeout, TLS, non-2xx, malformed JSON과 invalid schema를 기존 상태 코드로 구분한다.
- provider redirect URI, relying-client redirect URI, CORS origin을 서로 다른 경계로 관리한다.
- 동일 provider identity concurrent callback은 canonical 사용자와 identity link 하나로 수렴한다.
- verified-email attach, pending identity replacement, subject reservation과 default role 규칙을 유지한다.
- callback redirect에는 handoff code와 caller state만 포함한다.
- 실제 provider는 합성 테스트에서 호출하지 않고 TLS가 적용된 local stub을 사용한다.

### 8.8 현재 사용자

- `/users/me`는 Bearer Access Token을 요구한다.
- token과 현재 DB 사용자 상태를 검증한다.
- 응답 shape와 인증 실패의 status/code/message를 유지한다.

### 8.9 사용자 상태와 역할

지원 상태:

- `PENDING_EMAIL_VERIFICATION`
- `ACTIVE`
- `SUSPENDED`
- `DELETED`

`ACTIVE` 사용자만 token 발급, refresh와 보호 API 사용이 가능하다.

역할은 `serviceKey:name` 단위다. 기본 사용자는 client policy의 default role을 받으며 관리자 역할은 공개 가입 경로로 부여하지 않는다.

### 8.10 관리자 기능

기존 관리자 prefix와 호환 alias를 모두 제공한다.

- 사용자 목록, pagination, 상태·이메일·역할 filter
- 감사 로그 목록과 날짜·event·outcome·사용자·actor·target·reason filter
- 사용자 상태 변경
- 역할 부여와 제거
- 사용자 session 강제 폐기

관리자 권한 요구:

- 유효한 Access Token
- 현재 DB 상태가 `ACTIVE`
- 현재 DB role에 관리자 권한 존재
- 오래된 JWT role claim만으로 권한을 인정하지 않음
- DB 기반 권한 거부를 감사 이벤트로 기록
- 자기 suspend/delete, 자기 관리자 역할 제거, 자기 session 강제 폐기 금지
- 상태·역할·session 변경과 필수 audit은 Express와 같은 원자성 정책을 사용

### 8.11 감사

최소 다음을 감사한다.

- 가입, 로그인 성공·실패, lockout
- refresh, logout
- verification, reset
- OAuth, handoff, exchange
- rate limit
- 관리자 권한 거부와 모든 관리자 mutation

감사 metadata는 bounded 값만 허용한다.

- 관련 user, actor, target ID
- event type, outcome, provider, service key
- reason code
- 정책에 따른 client IP와 user agent
- 제한된 details와 timestamp

password, Authorization 원문, access/refresh token, verification/reset token, OAuth code/state, provider token과 secret은 저장하거나 log에 출력하지 않는다. 조회 시 details를 다시 redaction하며 retention cleanup은 strict cutoff와 dry-run을 지원한다.

### 8.12 Rate limit, CORS 및 proxy

- 인증 민감 endpoint는 Redis 기반 global rate limit을 사용한다.
- count 증가와 최초 TTL 설정은 원자적이어야 한다.
- Express와 후보 서버가 같은 namespace를 쓰면 요청 수가 합산된다.
- Redis 장애 시 protection을 우회하거나 command를 나중에 재생하지 않고 fail closed한다.
- trusted proxy 정책에 따라 client IP를 일관되게 산출한다.
- production CORS는 명시적 allowlist만 사용한다.
- redirect allowlist와 CORS allowlist를 혼용하지 않는다.

### 8.13 메일

- 개발 fake, 일반 SMTP, 운영 메일 provider 경계를 지원한다.
- verification/reset 제목, 본문과 동적 link 의미를 유지한다.
- SMTP는 TLS를 필수로 사용하며 평문으로 downgrade하지 않는다.
- 발송 실패와 timeout의 public/audit 결과를 유지한다.
- 합성 테스트에서 외부 메일을 발송하지 않는다.

### 8.14 운영 명령

최소 다음 기능을 후보 구현으로 제공하되 전환 전 production owner는 Express로 유지한다.

- 최초 관리자 권한 부여
- 만료·폐기 Refresh Token 정리
- 감사 로그 retention cleanup
- 나머지 maintenance script의 전환 필요성 inventory

운영 명령은 secret을 출력하지 않으며 schema owner와 runtime DML role을 분리한다. 혼합 운영 중 background writer는 한 runtime에서만 실행한다.

## 9. 데이터 계약

- 현재 Prisma schema가 전환 전 유일한 schema source다.
- 후보 구현은 table/column 대소문자, nullability, enum, default, unique, index, FK, cascade와 JSONB 동작을 그대로 사용한다.
- 후보 ORM은 자동 create/drop/migrate를 실행하지 않는다.
- UUID, timestamp precision/timezone, 자동 update timestamp, row count와 unique-conflict 결과를 기존 client와 호환한다.
- 부분 성공으로 사용자만 생성되고 credential, role 또는 identity가 누락되는 상태를 허용하지 않는다.
- transaction callback 안에는 재시도해도 안전한 DB effect만 포함한다.

## 10. Redis 계약

- NX와 TTL을 결합한 저장
- 원자적 count 증가와 TTL 설정
- 일회용 consume
- 조회한 raw value와 일치할 때만 삭제하는 compare-and-consume
- 기존 key namespace, TTL, camelCase JSON serialization 호환
- state/handoff/limiter concurrency에서 정의된 성공 수 보장
- 장애 시 fail closed
- offline queue 또는 reconnect 후 silent mutation replay 금지

## 11. 비기능 요구사항

### 11.1 보안

- JWT algorithm/type/issuer/audience/expiry confusion을 차단한다. `kid` 불일치 정책은 동결된 oracle 또는 승인된 양쪽 hardening 결정을 따른다.
- enumeration과 timing 차이를 최소화한다.
- OAuth state replay, provider swap, PKCE mismatch, open redirect를 차단한다.
- 관리자 수평·수직 권한 상승과 자기보호 우회를 차단한다.
- SQL injection, mass assignment, oversized/encoded body와 content-type edge를 검증한다.
- dependency, source, image, secret scan에서 미승인 high/critical finding이 없어야 한다.
- container는 non-root와 제한된 filesystem 권한으로 실행한다.

### 11.2 신뢰성

- 설정, DB, Redis 요구조건을 startup에서 fail-fast 검증한다.
- graceful shutdown에서 새 요청을 받지 않고 connection을 정리한다.
- process, DB, Redis 장애와 복구 중 mutation이 중복 또는 지연 재생되지 않는다.
- deadlock과 serialization failure의 retry는 제한되고 재현 가능해야 한다.

### 11.3 관측성

- request ID로 request, audit, provider failure를 연결한다.
- normalized route별 count, status, latency, login outcome, refresh rejection, provider error, rate limit과 dependency health를 측정한다.
- email, 사용자 ID, token, query 원문을 metric label로 사용하지 않는다.
- structured log schema와 redaction을 자동 검증한다.

### 11.4 성능

동일 fixture, image resource, concurrency와 load shape에서 비교한다.

- 각 핵심 flow는 runtime별 1,000건 이상 실행한다.
- 적용 가능한 success/failure outcome은 각각 100건 이상 확보한다.
- unexpected 5xx와 aborted flow는 0이어야 한다.
- 후보 p95는 동결된 Express baseline 대비 승인 threshold 안에 있어야 한다.
- 표본이 부족하면 `PASS` 대신 `INSUFFICIENT_EVIDENCE`로 판정한다.

성능 threshold는 실험 시작 전에 evaluator가 고정하며 run 결과를 본 뒤 바꾸지 않는다.

## 12. 운영 및 개발 안전 제약

- 별도 Git worktree와 branch에서 개발한다.
- Express source, 운영 process, PostgreSQL, Redis, routing을 변경하지 않는다.
- 합성 credential, 폐기 가능한 DB, 격리 Redis와 run 전용 container만 사용한다.
- production URL, 기존 volume, 실제 credential이 감지되면 즉시 중단한다.
- 실제 `.env`를 복사하거나 commit하지 않는다.
- backup/restore는 암호화된 합성 artifact와 새 `_test_` DB만 사용한다.
- production canary, routing, credential rotation, restore, cutover는 모델이 실행할 수 없다.
- 모든 run 종료 후 생성한 container, network, volume, DB, role, Redis key, process와 temp secret이 0인지 확인한다.

## 13. 전달 원칙

모델은 안전한 순서를 스스로 설계하되 다음 전달 원칙을 지켜야 한다.

- 운영과 완전히 격리된 foundation을 먼저 만든다.
- 상태 저장소와 외부 계약을 작은 수직 기능 단위로 이식한다.
- 각 단위는 구현, targeted test, 전체 회귀와 재현 가능한 evidence가 있어야 닫힌다.
- 독립 differential이 통과하기 전 mixed-runtime, 성능 또는 chaos 결과를 승격하지 않는다.
- 합성 qualification이 완료돼도 운영 승인 전에는 cutover를 실행하지 않는다.
- schema, background writer와 운영 명령 ownership은 명시적으로 한 runtime에만 둔다.

## 14. 최종 인수 기준

- 공개 HTTP status/body/header/redirect mismatch 0
- PostgreSQL schema 및 client semantic mismatch 0
- Node/Python Argon2id 양방향 호환 100%
- JWT/JWKS와 Refresh Token 교차 호환, wrong-alg 허용 0
- password/email/OAuth handoff E→F 및 F→E 성공
- state/handoff/verification/reset/refresh replay 성공 0
- 20-way refresh 경쟁의 성공 1개와 active replacement 1개
- OAuth identity 경쟁의 canonical user/link 각각 1개
- mixed limiter count와 요청 합계 일치, TTL 없는 key 0
- 관리자 권한·자기보호·audit mismatch 0
- secret·token·PII log/evidence 노출 0
- Redis 장애 중 queued mutation 0
- 미승인 high/critical security finding 0
- 동결된 성능 threshold 충족
- encrypted backup/restore와 local rollback rehearsal 성공
- 전환 직전 모든 DB/Redis writer와 in-flight 상태가 0임을 증명
- 운영 승인 없는 routing 변경 0
- rollback window 전 Express 삭제 0

## 15. 모델 제출물

- 실행 가능한 FastAPI source와 dependency lock
- 합성 환경용 container 구성
- unit, integration, E2E, contract, security와 concurrency test
- Express↔FastAPI machine-readable differential report
- shared synthetic PostgreSQL/Redis report
- SBOM, dependency/source/image/secret scan
- 성능, 장애복구, backup/restore 결과
- drain, cutover, rollback runbook
- 알려진 mismatch, waiver, 미검증 항목
- 구현 상태: `COMPLETE` 또는 `INCOMPLETE`
- readiness 상태: `NOT_READY`, `PROVISIONAL_READY_FOR_REVIEW`, `READY_FOR_APPROVAL` 중 하나
- 두 상태의 근거와 다음 필수 gate

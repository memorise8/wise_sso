# Express 인증 서버 기준 동작 명세 (FastAPI 전환 대조용)

작성: 2026-10-16. 대상 소스: `auth-server/src` (Express, 마지막 소스 커밋 6a4fd73).
방법: **코드 정적 읽기**로 작성. 실제 요청으로 확인한 것이 아니며 운영 서버에는 요청을 보내지 않았다.
FastAPI 비교 대상: `wiseacct_sso_fastapi_oidc` / `feat/fastapi-oidc-gitlab` (정적 대조).

## 배경
- Express 테스트는 파일 33개·케이스 약 223개이나 커버리지 측정이 없고, `/auth/logout`을 호출하는 테스트가 0개다.
  `/auth/refresh`, `/auth/register`는 1개 파일에서만 다룬다. 따라서 기존 테스트만으로는 기준 동작이 고정돼 있지 않다.
- 이 문서는 Express 코드에서 읽은 기대 동작을 명세로 고정해, FastAPI와의 차분 시나리오 입력으로 쓰기 위한 것이다.

## 1. POST /auth/logout
Express:
- 본문 `{refreshToken: string(min 1)}`. 없거나 비면 400 `INVALID_REQUEST`.
- 토큰 서명·만료를 검증하지 않는다. SHA-256 해시로 DB 조회, `revokedAt`이 빈 행만 폐기.
- 모르는 토큰/이미 폐기된 토큰이어도 **항상 204**.
- 감사 로그 logout/success. 알려진 토큰이면 userId, 아니면 null.
- 레이트리밋 대상.
FastAPI 대조: `services.logout`의 `DomainError`가 `_raise_public`으로 오류가 될 수 있음 → 모르는 토큰에서 204인지 시험 필요.

## 2. POST /auth/refresh
Express:
- HS256 + `JWT_REFRESH_SECRET` 검증. 위조/만료 → 401 `INVALID_REFRESH_TOKEN`.
- payload `type != "refresh"` 또는 `sub`가 문자열 아님 → 401.
- 토큰 해시로 DB 조회, 저장 audience ≠ 토큰 audience → 401.
- 사용자 행 `FOR UPDATE` 잠금 후 활성 확인(비활성 → 401).
- 기존 토큰을 한 번만 폐기(`revokedAt=null` and `expiresAt>now`, 갱신 행 수 1이 아니면 401). 한 트랜잭션.
- 새 refresh(tokenId = 랜덤 32바이트 hex, 만료 30일) + 새 access(RS256, kid, 15분) 발급.
- access 클레임: sub, email, name, email_verified, type=access, roles[{serviceKey,name}]; iss, aud, iat, exp.
- 실패 시 감사 로그 `REFRESH_FAILED`.
FastAPI 대조: 기본 만료값(900초/30일) 동일. 재사용 토큰 즉시 거부, 동시 요청 레이스, tokenId 형식(64자리 hex)은 시험 필요.

## 3. 레이트리밋 (429)
Express:
- 대상: `/auth/*`의 `authRateLimit`을 붙인 모든 라우트(소셜 시작/콜백 포함).
- Redis 키 `wiseacct:rate-limit:{ip}:{baseUrl}{path}` → IP×경로 조합별 카운트.
- 창 60초, 최대 20회(env `AUTH_RATE_LIMIT_WINDOW_SECONDS`/`AUTH_RATE_LIMIT_MAX_REQUESTS`).
- 초과: 429, `Retry-After: 60`, `{error:{code:"RATE_LIMITED",message:"Too many authentication requests"}}`, 감사 로그 `RATE_LIMITED`.
- IP: `app.set("trust proxy", 1)` 기준 `request.ip`.
FastAPI 대조: 키 접두사·기본값·429 본문 동일. **위험**: `TRUSTED_PROXY_IPS`가 비면 전달 헤더를 믿지 않아
모든 요청이 cloudflared 호스트(192.168.0.7)로 보여 **전 사용자가 한 버킷(분당 20회)을 공유**한다.
→ 전환 시 `TRUSTED_PROXY_IPS=192.168.0.7`(정확한 주소, 서브넷 금지) 필수.
감사 로그 IP는 FastAPI가 `X-Forwarded-For` 첫 값을 사용(위조 가능). Express의 `auditContextFromRequest`와 동일한지 미확인.

## 4. 에러 본문 형식
| 상황 | 상태 | 본문 |
|---|---|---|
| HttpError | 해당 코드 | `{error:{code,message}}` |
| zod 검증 실패 | 400 | `INVALID_REQUEST` / `Invalid request` |
| 없는 경로 | 404 | `NOT_FOUND` / `Route not found` |
| 그 외 예외 | 500 | `INTERNAL_SERVER_ERROR` / `Internal server error` |
대표 코드: INVALID_REFRESH_TOKEN, INVALID_TOKEN, UNAUTHORIZED(401), INVALID_CLIENT_REDIRECT_URI(400), RATE_LIMITED(429).
FastAPI 대조: 이름·상태 매핑 동일. 깨진 JSON, 405 등에서 422가 새는 경로가 없는지 확인 필요.

## 차분 시나리오 후보
1. logout: 정상 / 모르는 토큰 / 이미 폐기 / 본문 없음 / 빈 문자열
2. refresh: 정상 회전 / 재사용 / 위조 / alg:none / 만료 / audience 불일치 / 비활성 사용자 / 동시 요청
3. 429: 같은 IP 21번째 / 다른 경로는 별도 카운트 / Retry-After
4. 에러: 잘못된 JSON / 없는 경로 / 허용 안 된 메서드 / 필드 누락
5. 교차: Express 발급 refresh를 FastAPI에서 회전, 그 반대

## 전환 관련 메모
- Ingress: `auth.financenow.kr` → .7(192.168.0.7)의 cloudflared(`/etc/cloudflared/config.yml`) → `http://192.168.0.4:4000`.
- 후보 compose 기본 바인딩은 `127.0.0.1:4002`라 .7의 cloudflared가 닿지 못함 → 전환 시 `192.168.0.4:4002` 바인딩 필요.
- Phase 7(정식 7게이트)은 NOT_READY. 간이 합격 기준 적용 여부는 소유자 결정 사항.

# FastAPI fixture 차분 검증 — 2026-10-14

## 결과

**기본 저장소의 `contracts/scenarios/fixtures.json` 8개 시나리오 PASS.**
`contracts/bin/differential.py` 종료 코드 0. 이 결과는 격리된 복제 실행본의
해당 시나리오에 한정되며 운영 전환 승인이나 전체 READY 판정이 아니다.

## 어댑터 위치와 수정

- FastAPI 마이그레이션 작업 폴더에는 확장된 어댑터가 이미 있었다. TEMIS가
  사용한 기본 저장소에는 없었으므로 기본 저장소의 구 버전 프로토콜에 맞는
  [fastapi_fixture.py](../adapters/fastapi_fixture.py)를 추가했다.
- 같은 폴더의 Express 어댑터 구현을 공유해 7개 fixture와 5개 probe의 상태
  투영을 동일하게 유지한다. `setup/snapshot/teardown/preflight`를 지원한다.
- `CONTRACT_FASTAPI_RUNTIME=1`을 추가로 요구하며 loopback, DB명 경계의
  test/contract/fixture, `auth_db` 금지, Redis 0 금지 규칙을 그대로 적용한다.
- 모든 CLI 동작 전에 공유 preflight와 8개 Prisma 테이블 존재 검사를 수행한다.
  테이블 존재 검사는 모든 컬럼/인덱스의 동등성을 증명하는 것은 아니다.

## 실제 실행 대상과 격리

기존 미리보기 `:4001`은 운영과 다른 네트워크·PostgreSQL 볼륨·Redis 컨테이너를
사용한다. 개발 PostgreSQL 볼륨은 `wiseacct-sso-fastapi-dev-postgres-data`, 운영
볼륨은 `auth-server_auth-postgres-data`다. 하지만 미리보기 DB명은
`fastapi_sso_dev`이고 Redis는 0번이므로 fixture 대상으로 직접 사용하지 않았다.

기존 개발용 저장소 컨테이너 안에 다음 임시 자원만 생성했다.

| 구분 | Express 복제 실행본 | FastAPI 복제 실행본 |
| --- | --- | --- |
| HTTP | `127.0.0.1:4410` | `127.0.0.1:4411` |
| PostgreSQL | `127.0.0.1:5433/phase7_express_test_temis_<run>` | `127.0.0.1:5433/phase7_fastapi_test_temis_<run>` |
| Redis | 개발 Redis `127.0.0.1:6380/13` | 개발 Redis `127.0.0.1:6380/14` |
| DB 권한 | 실행별 DML 전용 역할 | 실행별 DML 전용 역할 |

운영 `:4000`, 운영 PostgreSQL `:5432`, 운영 Redis `:6379`에는 fixture 요청이나
SQL을 보내지 않았다. 운영 `.env`와 컨테이너 비밀 설정은 읽지 않았다.
이미 저장소에 공개된 synthetic `.env.example`과 새 임시 난수만 사용했다.
임시 설정은 저장소 밖 mode-0700 디렉터리의 mode-0600 파일로 전달하고 삭제했다.

Express 소스는 기본 저장소의 `auth-server/src`와 같은 마이그레이션 작업 폴더의
소스를 새로 빌드했다. 실제 운영 컨테이너 바이너리의 동일성까지 검증한 것은 아니다.
FastAPI 소스 기준은 `1e4fea6`이며 앱 변경은 `cfa970b`에 포함되어 있다.

## 동일하게 설정한 계약

- issuer: `https://auth.financenow.kr`
- audience: `temis`
- 키: 두 실행본에 같은 **synthetic** RS256 signer/JWK/kid 제공; 운영 키 사용 안 함
- fixture 전용 client ID: `contract-fixture`; 해당 클라이언트 정책의 audience도 `temis`
- redirect: fixture 전용 loopback 주소; 운영 TEMIS redirect 등록은 변경하지 않음
- 메일: `dev`; 실제 SMTP·소셜 로그인은 비활성

따라서 기존 `:4001` 미리보기의 issuer/kid와 운영 서버의 차이를 무시한 것이 아니다.
비교용 실행본끼리 같은 비밀 아닌 테스트 조건을 구성했고 미리보기 설정은 유지했다.

## 실행 결과

```text
express preflight ok
fastapi preflight ok
PASS security.refresh-none-algorithm
PASS security.refresh-hs256-rotation
PASS security.refresh-hs384-algorithm
PASS security.refresh-hs512-algorithm
PASS auth.login-issues-verifiable-token
PASS recovery.password-reset-request
PASS recovery.email-verification-request
PASS admin.status-mutation
All 8 contract scenario(s) passed
```

로그인 시나리오는 PKCE 로그인 → handoff 발급 → `/auth/exchange` → 토큰 검증과
Redis handoff/refresh ledger 변화를 확인한다. JWKS의 kid에 대응하는 RSA 키로
서명을 검증하며 `iss`, `aud=temis`, `email_verified`, `roles[{serviceKey,name}]`
등을 비교한다. HS256 시나리오는 실제 refresh 회전과 ledger 변경을 확인한다.
`/auth/logout`의 상태 기반 시나리오는 이 8개 corpus에 포함되어 있지 않다.

## 초기 실패와 수정 이력

1. 최초 실행은 7 PASS / 1 FAIL. 기존 Express fixture의 `tokenId`가
   `contract-hs256-token-id` 형태였고 FastAPI는 실제 발급 형식인 64자리 hex를
   요구해 401을 반환했다. 실제 Express는 `randomBytes(32).toString("hex")`로
   발급하므로 fixture ID를 결정론적 SHA-256 hex로 맞췄다. 앱 검증을 완화하거나
   시나리오 기대값을 바꾸지 않았다. 비표준 tokenId 입력을 허용하는지는 두
   구현 간 차이로 남으며, 이번 통과가 모든 비정상 입력의 동등성을 뜻하지 않는다.
2. `aud=temis`로 추가 실행 시 fixture 클라이언트 정책이 `contract-fixture`
   audience를 유지해 로그인 시나리오가 실패했다. 양쪽 임시 설정에서 클라이언트
   정책도 `temis`로 일치시킨 후 8개 전부 통과했다. 운영 정책은 변경하지 않았다.

## 회귀 검사와 정리

- 기본 저장소 `python -m unittest discover -s contracts/tests -v`: 34 tests, OK.
- 새 어댑터의 opt-in 누락, 운영형 DB명, Redis 0, 비-loopback 거부 확인.
- `git diff --check` 통과.
- 두 임시 HTTP 프로세스 종료; 4410/4411 리스너 없음.
- 임시 DB 2개와 역할 2개 삭제; 해당 이름의 잔여 DB/역할 0.
- 실행 전 비어 있던 개발 Redis 13/14를 정리했고 최종 DBSIZE 각각 0.
- 운영 Express·PostgreSQL·Redis 및 미리보기 앱의 컨테이너 ID, 시작 시각,
  재시작 횟수, 실행 상태는 실행 전후 동일했다. 기존 `:4001`은 계속 실행 중이다.

## 재실행 계약

새 격리 DB/역할/Redis와 동일 설정의 두 복제 실행본을 준비하고, 실제 운영 설정이
아닌 private adapter config 두 개로 각각 preflight를 통과시킨 뒤 실행한다.
아래의 config 파일 경로는 별도로 준비해야 하며 이번 실행의 임시 파일은 삭제했다.

```sh
python3 contracts/bin/differential.py \
  --baseline http://127.0.0.1:4410 \
  --candidate http://127.0.0.1:4411 \
  --scenarios contracts/scenarios/fixtures.json \
  --baseline-adapter contracts/adapters/express_fixture.py \
  --candidate-adapter contracts/adapters/fastapi_fixture.py \
  --baseline-adapter-config /private/express-adapter.json \
  --candidate-adapter-config /private/fastapi-adapter.json
```

재현용 synthetic 설정 생성의 기존 구현은 마이그레이션 작업 폴더의
`fastapi-auth-server/ops/phase7/runtime_material.py`다. 그 기본 audience는
`contract-fixture`이므로 TEMIS audience 검증 시 runtime 기본값, adapter 값,
fixture 클라이언트 정책의 audience 세 곳을 함께 맞춰야 한다.

## 입력 식별

```text
fixtures.json SHA256:
251e473cab9e3fa833d3bb235551e0629a04b1d860ce5af3fe8772015764f6af
differential.py SHA256:
5dd35a860202f73ab4c6dd2b6f0140af20e1e2d7a662f891b356434844f05af3
express_fixture.py SHA256:
484c958230c4459edfb946c42c22255329af65d23703360247ccfbd995e88529
fastapi_fixture.py SHA256:
410886ac59babb0974ea540adfe953fd935b73a762053e1b4199019015315fc5
```

이 문서는 실행 관찰을 요약한 개발 증거이며 서명된 Phase 7 qualification 증거가 아니다.

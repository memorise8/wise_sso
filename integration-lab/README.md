# wise-sso 하위 서비스 연동 실험실

외부 고객용·직원용 더미를 표준 OIDC client로 연결한다. 업무 기능은 없고,
실제 Fantra 또는 대시보드의 코드를 가정하지 않는다. **로컬 단일 프로세스 전용**이다.

## 이번에 구현한 범위

- 고객용 더미 `https://localhost:4445`, 직원용 더미 `https://localhost:4446`
- wise-sso OIDC 진입점 `https://localhost:4444` (기존 앱을 TLS로 프록시)
- Authorization Code + PKCE S256, state/브라우저 바인딩, nonce 검증
- confidential client의 Basic 인증, RS256/JWKS·issuer·audience·만료 검증
- 토큰은 더미 서버 메모리, 브라우저에는 Secure/HttpOnly 세션 ID만 저장
- 서비스별로 다른 쿠키 이름, 사용자/역할 표시, 사용자 정보는 HTML escape
- 매 페이지 접근 시 userinfo 재검증. 만료/권한 회수 시 더미 세션 폐기
- CSRF 검증이 있는 POST 로컬 로그아웃. 다른 서비스 또는 중앙 세션 로그아웃 아님
- nginx access log와 더미 HTTP access log를 끄고 callback code 기록 방지

## 아직 구현하지 않은 정책

현재 wise-sso는 사용자 유형 필드가 없다. `customer`/`employee`는 이 실험실의
테스트 계정 이름과 역할 구성을 의미하며 보안상 사용자 유형 검사를 의미하지 않는다.
**고객에게 lab-staff:user 역할을 잘못 부여하면 지금은 직원용 더미에 들어갈 수 있다.**
이 차단은 다음 정책 개발의 실패 재현/수정 대상이다.
중앙 sso:admin 분리, 사용자 유형 관리, 중앙 SSO 세션, 통합 로그아웃, 실제
Fantra/대시보드 연동은 완료되지 않았다. 서비스 이동 시 다시 로그인하는 것이 현재 동작이다.

## 기존 환경 보존

파일은 integration-lab/만 추가한다. 기존 소스, .env.oauth-local, 소셜 callback,
DB 스키마와 기존 계정·역할은 바꾸지 않는다. Git commit/push는 하지 않는다.
실행 시 overlay가 앱을 재생성하여 OIDC를 켜고 JWT_ISSUER를 로컬 HTTPS로 바꾼다.
따라서 이전 로컬 앱 토큰은 재로그인이 필요하다. 운영에는 적용하지 않는다.
OIDC_CLIENTS_JSON은 실험실 client 두 개로 대체된다. 기존 운영 client를 혼합하지 않는다.

기존 docker-compose.oauth-local.yml은 저장소 최상위에 있어야 하며,
app build.context는 ./fastapi-auth-server, env_file은
./fastapi-auth-server/.env.oauth-local이어야 한다. postgres/redis가 healthy이고,
Prisma 마이그레이션이 적용된 로컬 fastapi_sso_dev DB를 사용한다.

## 실행 (WSL, wise_sso 저장소 최상위)

```bash
bash integration-lab/lab.sh build
bash integration-lab/lab.sh setup
bash integration-lab/lab.sh config
bash integration-lab/lab.sh up
bash integration-lab/lab.sh ps
```

setup은 소셜 키를 읽거나 변경하지 않는다. 새 client secret, Argon2id hash,
자체 서명 localhost 인증서(30일), 테스트 계정 비밀번호를 .local/에 생성한다.
.local/은 Git 제외 대상이며 공개/업로드하지 않는다. Docker inspect/config 전체
출력에도 client secret이 포함될 수 있다. config 명령은 검증 결과만 출력한다.
기존 생성 정보를 재사용하므로 setup 재실행으로 비밀번호를 덮어쓰지 않는다.
인증서 만료 후에는 로컬 tls.crt/tls.key만 제거하고 setup으로 재생성한다.

앱이 실행되면 테스트 계정을 명시적으로 만든다:

```bash
bash integration-lab/lab.sh seed
```

seed는 로컬 전용 DB/설정을 검사하고 아래 예약 이메일의 계정만 새로 만든다.
이미 있는 fixture는 비밀번호/상태/역할을 덮어쓰지 않는다. DB 테이블 생성/삭제,
실제 사용자 수정, 관리자 권한 부여는 하지 않는다.

비밀번호는 에디터에서 integration-lab/.local/fixtures.json을 열어 로컬에서 확인한다.

| 계정 | 상태/역할 | 고객용 예상 | 직원용 예상 |
|---|---|---|---|
| customer@wise-lab.invalid | ACTIVE, lab-customer:user | 허용 | 거부 |
| employee@wise-lab.invalid | ACTIVE, 고객용+직원용 역할 | 허용 | 허용 |
| unapproved@wise-lab.invalid | ACTIVE, 역할 없음 | 거부 | 거부 |
| suspended@wise-lab.invalid | SUSPENDED | 거부 | 거부 |

세 HTTPS 주소를 각각 열어 자체 서명 인증서 경고를 확인한다. 이 실험실의
localhost에 한해서만 인증서를 신뢰/예외 처리한다. 전역 TLS 검증을 끄지 않는다.
인증서 경고를 처리하기 전에는 로그인 redirect가 중단될 수 있다.

1. 고객용 더미 → wise-sso 로그인 → customer 계정 → 사용자/역할 표시 확인
2. 직원용 더미 → 같은 customer 계정 → 거부 확인
3. 두 더미에 employee 계정 → 허용 및 서비스별 역할만 표시 확인
4. unapproved/suspended 계정 → 거부 확인
5. 로그인 유지·새로고침·로컬 로그아웃 확인

이 단계의 OIDC는 **테스트 계정의 이메일/비밀번호 로그인**을 사용한다.
기존 네이버/카카오 `127.0.0.1:4003/auth/.../callback`과 client를 재사용하지 않는다.
OIDC 소셜 로그인은 별도의 /oauth2/providers/... callback 등록이 필요하므로 아직 켜지 않는다.

## 테스트

```bash
python -m pip install -r integration-lab/requirements.txt pytest
python -m pytest --noconftest integration-lab/tests -q
```

더미 검증은 mock OIDC HTTP를 사용한다. 실제 Docker/Postgres/브라우저 통합 검증은
사용자 로컬 환경에서 위 체크리스트로 진행해야 한다. 실패 시:

```bash
bash integration-lab/lab.sh logs
```

## 중지/원복

더미만 중지:

```bash
bash integration-lab/lab.sh stop
```

OIDC overlay까지 제거하고 원래 4003 앱 설정으로 돌아가려면:

```bash
docker compose -f docker-compose.oauth-local.yml up -d --no-deps --force-recreate --wait app
```

DB와 생성한 테스트 계정은 남는다. down -v 또는 볼륨 삭제를 실행하지 않는다.

## 로그인 제출 시 invalid request / Origin null 수정

프록시에서 Referrer-Policy를 추가하지 않는다. wise-sso는 /oauth2/login에
same-origin 정책을 적용한다. 여기에 no-referrer 헤더를 추가하면 브라우저의
HTML POST Origin이 null이 되어 원본 Origin 검사에 실패할 수 있다.
프록시는 upstream의 헤더를 그대로 유지한다. Origin/CSRF 검증을 끄지 않는다.
수정 후 프록시를 재시작하고 기존 폼이 아닌 더미 /login에서 새로 시작한다.

## 사용자 유형 정책 적용

사용자 유형·sso:admin 분리 적용 후에는 [POLICY_STEP1.md](POLICY_STEP1.md)의 마이그레이션과 `policy-setup`/`policy-check` 순서로 검증한다. 위 기존 로그인 표에 사용자 유형 검사도 함께 적용된다.

## 중앙 SSO 세션 적용

중앙 세션 추가 후의 설치·검증은 [SSO_STEP2.md](SSO_STEP2.md)를 따른다. 중앙 세션이 유효하면 로그인 정보를 다시 입력하지 않고 대상 서비스의 유형·역할을 다시 검사한다. 더미 로그아웃과 중앙 세션 종료는 별도다.

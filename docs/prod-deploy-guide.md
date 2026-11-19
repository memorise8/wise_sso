# 운영 SSO 배포 가이드

기준: 2026-11-19, main `d53b42f`

운영 SSO(`wiseacct-sso-fastapi-prod`)를 배포하고 주소를 옮길 때 쓰는 기준 문서다.
운영 DB, 운영 env, 컨테이너 교체, Cloudflare 설정 변경은 모두 ruci 승인 후 진행한다.

## 주소 계획 (wiseaccounting.co.kr)

| 새 주소 | 지금 주소 | 용도 | Cloudflare Access |
| --- | --- | --- | --- |
| `auth` | `auth.financenow.kr` | SSO 로그인 서버 | 없음 |
| `auth-lab` | `auth.wiseaccounting.co.kr` | 실습 SSO | 있음 |
| `git` | `git.temis.me` | 회사 GitLab | 없음 |
| `office` | `dash.temis.me` 안 | 도트오피스 (직원, 손님) | 없음 |
| `dash` | `dash.temis.me` | 직원용 대시보드 | 있음 (팀만) |
| `dev` | - | 대시보드 시험용 | 있음 |
| `share` | `share.temis.me` | 공유 페이지 | 없음 (페이지별 비밀번호) |

- Access는 직원만 쓰는 화면에만 건다. SSO에 걸면 서비스 서버의 토큰 요청이 막히고, GitLab에 걸면 git·CI·API 토큰 호출이 막힌다.
- 진행 순서: Cloudflare 틀 → SSO(auth) 끝까지 → GitLab → 도트오피스·대시보드 분리 → 공유 페이지.
- 서비스마다 (서비스 주소 설정 변경 + 터널 연결 + 확인)을 한 번에 한다. 준비가 안 된 서비스 주소는 터널에 미리 연결하지 않는다.

## 운영 구성

| 항목 | 값 |
| --- | --- |
| 서버 | 4번 서버 |
| 컨테이너 | `wiseacct-sso-fastapi-prod` (내부 4001 → `192.168.0.4:4002`) |
| 배포 키트 | 4번 서버 `~/cutover` |
| 운영 env | `/home/ruci/secure/prod-fastapi.env` (비밀값 포함, 내용 공유 금지) |
| DB | 컨테이너 `auth-server-postgres-1`, DB `auth_db`, 앱 계정 `auth_fastapi_app`, 표 소유자 `auth_user` |
| 외부 계정 만료 정리 | cron 10분마다, 로그 `~/cutover/logs/expire-external-accounts.log` |

운영 컨테이너는 `192.168.0.4:4002`에만 열려 있다. `127.0.0.1:4002`로는 접속되지 않는다.
터널 연결 대상은 항상 `http://192.168.0.4:4002`로 쓴다.

```
사용자 → Cloudflare → (터널) → cloudflared → 192.168.0.4:4002 → SSO 컨테이너
```

- `cloudflared`가 서버에서 Cloudflare 쪽으로 먼저 연결을 여는 방식이라 외부 포트는 열지 않는다.
- 확인: `docker port wiseacct-sso-fastapi-prod`, `curl http://192.168.0.4:4002/healthz`

## 0. Cloudflare 정리 (사용자 영향 없음)

### 운영 전용 터널

- wiseaccounting Cloudflare 계정에 운영 전용 터널을 만든다.
- 4번 서버에 이 터널용 cloudflared를 별도 systemd 서비스로 띄운다. 토큰 파일은 root 소유 0600.
- 기존 `cloudflared-wise-sso-test` 터널은 실습용으로 둔다.

### 실습 환경 이전 (`auth` → `auth-lab`)

- `auth-lab.wiseaccounting.co.kr` Access 정책을 먼저 만든다.
- test 터널에 `auth-lab.wiseaccounting.co.kr` → `http://127.0.0.1:4003` 추가
- 실습 SSO(`wiseacct-sso-wiseacct-oauth-app-1`)의 `JWT_ISSUER`, `OIDC_PUBLIC_ORIGIN`, 콜백 주소를 새 실습 주소로 바꾸고 다시 띄운다. 실습 더미 서비스의 SSO 주소도 바꾼다.
- 실습 로그인 확인 후 test 터널에서 `auth.wiseaccounting.co.kr` 항목을 지우고, 이 주소의 Access 정책을 해제한다.

### Access 정책 미리 만들기

- `dash`, `dev`에 팀 전용 Access 정책을 만든다. 터널 연결은 하지 않는다.
- Access를 거는 주소는 항상 Access를 먼저 만들고 그다음 터널에 연결한다.

## 1. 기능 릴리즈 (주소 그대로)

### 1-1. 준비

- 새 env 키가 있으면 `~/cutover/envcheck.py` 허용 목록에 먼저 추가한다. 빠뜨리면 검사에서 멈춘다.
  - `d53b42f` 기준 새 키: `PORTAL_ENTRY_URL`
- 이미지를 만든다.
  ```sh
  cd ~/cutover && ./build-candidate.sh <commit>
  # → wiseacct-sso-fastapi:cutover-<commit>
  ```
- 운영 env 백업 후 수정한다.
  ```sh
  cp -p /home/ruci/secure/prod-fastapi.env /home/ruci/secure/prod-fastapi.env.before-release-$(date +%Y%m%d-%H%M%S)
  ```

### 1-2. DB 마이그레이션

- 운영 DB를 먼저 백업한다. (`pg_dump`, 파일 권한 0600)
- 운영 DB에 적용된 마지막 마이그레이션과 `prisma/migrations` 목록을 비교해 새로 적용할 것을 고른다.
- 운영 서버에는 Prisma 도구가 없어 psql로 직접 적용한다.
  ```sql
  -- postgres 컨테이너, auth_db
  SET ROLE auth_user;
  \i migration.sql   -- 날짜 순서대로
  -- _prisma_migrations 에 기록 추가 (checksum = migration.sql 의 sha256)
  ```
- 새 표를 만드는 마이그레이션은 앱 계정 권한을 추가한다.
  ```sql
  GRANT SELECT, INSERT, UPDATE, DELETE ON "<새 표>" TO auth_fastapi_app;
  ```
- 마이그레이션은 컨테이너 교체 전에 적용한다. 열·행 추가만 있는 경우 이전 버전도 그대로 동작한다.

`d53b42f` 기준 미적용 마이그레이션 (운영 마지막: `20261111000000_invitation_return_to`):

| 마이그레이션 | 내용 | GRANT |
| --- | --- | --- |
| `20261114000000_external_account_metadata` | User 외부 계정 열 3개, EmployeeInvitation 열 1개 (NULL 허용) | 불필요 |
| `20261117000000_add_sso_viewer_role` | Role `sso:viewer` 추가 | 불필요 |

### 1-3. 검사와 교체

```sh
cd ~/cutover
IMG=wiseacct-sso-fastapi:cutover-<commit> ./check-prod-env.sh /home/ruci/secure/prod-fastapi.env
ALLOW_ENV_CHANGE=1 ./swap-prod.sh wiseacct-sso-fastapi:cutover-<commit> /home/ruci/secure/prod-fastapi.env
./post-cutover-check.sh
```

- 검사 결과가 `ALL CHECKS PASSED`가 아니면 멈춘다.
- `ALLOW_ENV_CHANGE=1`은 env를 바꿨을 때만 붙인다.
- 이전 컨테이너는 `wiseacct-sso-fastapi-prod-<이전 태그>`로 남는다. 같은 이름이 이미 있으면 교체가 멈춘다.

### 1-4. 확인

- GitLab, 허브, FANTRA 운영, FANTRA dev 로그인
- 관리 화면: 감사 로그, 외부 계정, 보안·이상 징후, 운영 상태(커밋 표시)
- 허브 비밀번호 변경 (`docs/service-password-change.md`)

### 1-5. 되돌리기

```sh
cp -p /home/ruci/secure/prod-fastapi.env.before-release-<시각> /home/ruci/secure/prod-fastapi.env
ALLOW_ENV_CHANGE=1 ~/cutover/swap-prod.sh wiseacct-sso-fastapi:cutover-<이전 commit> /home/ruci/secure/prod-fastapi.env
~/cutover/post-cutover-check.sh
```

- 이전 버전과 호환되는 마이그레이션은 되돌리지 않는다.

## 2. 옛 주소 입구를 4번 서버로 (auth.financenow.kr, 주소 그대로)

`auth.financenow.kr`은 financenow·temis Cloudflare 계정 주소라 새 운영 터널에 넣을 수 없다. 4번 서버의 financenow·temis 계정 터널(`cloudflared.service`)을 쓴다. wiseaccounting 계정 터널이 아니다.

- `cloudflared.service`, `/etc/cloudflared/config.yml`에 추가한다.
  ```yaml
  - hostname: auth.financenow.kr
    service: http://192.168.0.4:4002
  ```
  - 마지막 기본 항목(404)보다 위에 넣는다.
- 검사, 재시작, DNS 변경
  ```sh
  sudo cloudflared tunnel --config /etc/cloudflared/config.yml ingress validate
  sudo systemctl restart cloudflared
  cloudflared tunnel route dns -f <financenow 계정 터널 이름> auth.financenow.kr
  ```
- 확인: `/healthz`, `/.well-known/openid-configuration`(issuer 그대로), `/.well-known/jwks.json`, 각 서비스 로그인, Google 로그인
- 하루 정도 지켜본 뒤 7번 터널 설정에서 해당 항목을 지운다. 그 전에는 DNS만 되돌리면 원래대로 돌아간다.

## 3. 새 주소 연결 (발급자는 아직 옛 주소)

- 운영 터널에 `auth.wiseaccounting.co.kr` → `http://192.168.0.4:4002` 추가, DNS 연결. 외부에는 안내하지 않는다.
- 확인
  - `/healthz` 200, Access 화면이 뜨지 않음
  - discovery 응답 (`issuer`는 아직 `https://auth.financenow.kr`가 정상)
  - `curl -s -o /dev/null -w '%{http_code}\n' -X POST https://auth.wiseaccounting.co.kr/oauth2/token` → 400 또는 401 (302면 Access가 남아 있음)

## 4. 주소 전환 (auth.financenow.kr → auth.wiseaccounting.co.kr)

SSO 주소는 토큰 발급자(`iss`)다. 주소를 바꾸면 SSO를 쓰는 모든 서비스가 같은 시점에 바라보는 SSO 주소를 바꿔야 하고, 사용자는 한 번 다시 로그인한다. 각 서비스 자기 주소는 이때 바꾸지 않는다.

### 4-1. 바꿀 곳

| 위치 | 항목 | 값 |
| --- | --- | --- |
| SSO 운영 env | `JWT_ISSUER`, `OIDC_PUBLIC_ORIGIN` | `https://auth.wiseaccounting.co.kr` |
| SSO 운영 env | `GOOGLE_REDIRECT_URI`, `OIDC_GOOGLE_REDIRECT_URI` | 경로 그대로, 호스트만 새 주소 |
| SSO 운영 env | `FRONTEND_REDIRECT_URL` | 호스트만 새 주소 (메일 링크) |
| SSO 운영 env | `CORS_ALLOWED_ORIGINS` | 옛 SSO 주소가 있으면 새 주소 추가 |
| 배포 키트 | `envcheck.py`의 `JWT_ISSUER` 기대값, `post-cutover-check.sh`의 `PUB` | 새 주소 |
| Google Cloud 콘솔 | OAuth 승인된 리디렉션 URI | 새 주소 콜백 추가 (옛 주소 유지) |
| GitLab | OIDC `issuer` | 새 주소 |
| 도트오피스(허브) | 로그인 issuer, 서비스 토큰 주소(`sso_service.url`) | 새 주소 |
| FANTRA 운영 | 로그인·가입 주소, `/auth/exchange`·`/auth/refresh`, JWKS 주소, `iss` 검사값 | 새 주소 |
| FANTRA dev | issuer, authorize·token·JWKS 주소 | 새 주소 |

- 코드 수정은 없다. 서명 키도 그대로 둔다.

### 4-2. 순서

- 미리보기 환경에서 새 발급자로 시험 로그인
- Google 콘솔에 새 콜백 추가
- GitLab, 도트오피스, FANTRA 담당과 전환 시간 확정
- 전환: 운영 env 백업 → 수정 → 배포 키트로 검사·교체·점검 → 각 서비스 설정 변경
- 확인: 새 주소 discovery의 `issuer`, 각 서비스 로그인, Google 로그인, 비밀번호 재설정 메일 링크, 도트오피스 손님 초대·비밀번호 변경, 관리 화면

### 4-3. 되돌리기

- 운영 env 백업본 복구 후 배포 키트로 교체
- 각 서비스 설정을 옛 주소로 복구
- 새 주소 연결은 지우지 않아도 된다.

## 5. 마무리

- 모든 서비스 전환 확인 후 `auth.financenow.kr`을 새 주소로 301 이동 (경로·쿼리 유지), 몇 주 뒤 정리
- 7번 터널의 `auth.financenow.kr` 항목 삭제 확인
- 완료 기준: 새 주소 `issuer`, 각 서비스 로그인 정상, 7번 서버 미경유, 실습은 `auth-lab`에서 정상

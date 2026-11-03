# 관리자 브라우저 로그인

작성일: 2026-11-03. 전제: 정책·중앙 SSO·사용자 유형 일괄 변경 패키지까지 적용한 feat/local-auth-policy.

## 사용 방법

https://localhost:4444/oauth2/admin/dashboard 에 접속하고 `employee@wise-lab.invalid` 계정으로 로그인한다. 비밀번호는 로컬 `integration-lab/.local/fixtures.json`에서 확인한다. 로그인하면 사용자 목록을 자동 조회한다. 관리자 토큰을 발급·복사·저장할 필요가 없다.

기존 http://127.0.0.1:4003/manage/dashboard 와 /admin/dashboard 는 OIDC가 활성화되어 있으면 설정된 HTTPS 관리자 화면으로 이동한다. 브라우저 인증은 HTTPS 주소에서 수행한다. 로컬 인증서 경고 처리 방식은 기존 통합 실험실과 같다.

## 적용과 자동 확인

ZIP의 apply.py로 소스를 적용한 뒤 저장소 루트에서 실행한다.

```bash
docker compose -f docker-compose.oauth-local.yml build app
bash integration-lab/lab.sh up
bash integration-lab/lab.sh admin-login-check
bash integration-lab/lab.sh bulk-check
bash integration-lab/lab.sh policy-check
bash integration-lab/lab.sh sso-check
```

DB 마이그레이션·setup·seed·추가 환경변수·새 client secret은 필요 없다. 더미 이미지를 다시 빌드할 필요도 없다. 기존 .env/.local과 테스트 계정을 유지한다. app 재생성 후 lab.sh up은 프록시도 reload한다.

admin-login-check의 기대 결과는 PASS 7개다.

1. 미인증 관리자 API 거부와 고정된 HTTPS 진입점 확인.
2. 직원 관리자 비밀번호 로그인과 HttpOnly 중앙 쿠키 발급.
3. 수동 토큰 입력 없는 화면과 쿠키 기반 사용자 목록 조회.
4. CSRF 없는 변경 거부, 올바른 Origin/CSRF를 가진 동일 유형 요청의 변경 0명 확인.
5. 최근 중앙 인증 세션 재사용.
6. 중앙 세션 종료 뒤 관리자 API 재사용 거부.
7. 고객과 관리자 역할 없는 직원의 관리자 로그인 거부.

검사 대상은 개발용 전용 DB와 issuer로 제한한다. 토큰·비밀번호를 출력하지 않으며 계정 유형을 변경하지 않는다. 검사에서 생성한 중앙 세션은 정리한다. 기존 bulk-check는 별도로 실행하며 유형 변경·복원과 감사 기록을 검증한다.

## 브라우저 확인

1. 새 시크릿 창에서 위 HTTPS 관리자 주소에 접속한다.
2. employee 계정으로 로그인한다. 토큰 입력란이 없어야 하고 사용자 목록이 자동 표시되어야 한다.
3. [BULK_USER_TYPES.md](BULK_USER_TYPES.md)의 일괄 변경·복원·관리자 보호 절차를 확인한다.
4. 화면의 중앙 세션 종료 버튼을 누른 뒤 관리자 주소에 재접속한다. 로그인 화면이 나와야 한다.
5. customer 또는 unapproved 계정으로 로그인하면 관리자 권한 없음으로 거부되어야 한다.

## 인증과 권한 경계

- 기존 Redis 중앙 세션과 Secure·HttpOnly·SameSite=Lax `__Host-wise_sso` 쿠키를 사용한다. 브라우저 JavaScript에 access/refresh 토큰을 전달하거나 저장하지 않는다.
- 중앙 세션은 기존처럼 최대 8시간이지만 관리자 기능은 최초 인증 시각부터 15분 이내에만 허용한다. 15분이 지나면 비밀번호 재인증을 요구한다. 화면/API 요청으로 인증 시각을 연장하지 않는다.
- 매 요청마다 DB에서 ACTIVE·인증된 이메일·EMPLOYEE·sso:admin과 세션 버전을 확인한다. 권한을 회수한 계정은 이후 관리자 요청이 거부된다.
- 변경 API는 정확한 Origin, 세션에 묶인 CSRF 헤더, JSON 본문을 요구한다. 인증을 본문 파싱보다 먼저 검사하고 본문 크기도 제한한다.
- 관리자 로그인 요청은 일반 OIDC 로그인 요청과 목적을 구분한다. 브라우저 바인딩·CSRF·유효기간·단일 사용을 검사한다. 로그인 성공/권한 거부는 감사 기록을 남긴다.
- `/oauth2/admin/api`만 쿠키 인증을 사용한다. 기존 `/admin`, `/manage-api` Bearer API는 기존 자동 검사·외부 호출과의 호환성을 유지한다.
- OIDC가 비활성화된 환경은 기존 수동 토큰 관리자 화면을 유지한다. 이번 실험실은 OIDC 활성 환경이다.

현재 전용 관리자 로그인 폼은 이메일/비밀번호를 받는다. 이미 발급된 최근 중앙 세션이 관리자 조건을 만족하면 재사용할 수 있다. 관리자 소셜 로그인 버튼·MFA·직원 초대/등록은 이번 범위가 아니다. 중앙 세션 종료가 이미 열린 모든 하위 서비스 세션까지 즉시 종료하는 것은 아니다.

## 개발 검증과 한계

단위·HTTP/OIDC dispatch 검사 701 passed, 12 skipped, Express oracle 1개 제외. 더미 검사 20 passed. mypy 139개 소스 파일 통과. 관리자 JS의 세션/기존 Bearer 동작을 Node DOM oracle로 확인했다. 새 로그인·권한 회수·만료·목적 격리·Origin/CSRF·로그아웃과 실제 검사 스크립트의 HTTP 흐름도 검사했다.

Docker 실환경과 사용자 브라우저 검증은 위 명령·절차로 별도 수행한다. 운영 배포·실제 서비스 연동 완료를 의미하지 않는다. 커밋/푸시는 자동 수행하지 않는다.

참고: [OWASP CSRF 방어](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), [OWASP 세션 관리](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).

# 사용자 유형 일괄 변경: 로컬 적용과 검증

작성일: 2026-11-03. 전제: 정책 1단계와 중앙 SSO 세션 패키지까지 적용·검증한 feat/local-auth-policy.

## 이번 변경

- 관리자 화면에서 현재 조회된 사용자를 선택하고 직원·고객·미분류로 일괄 변경한다.
- 현재 페이지 전체 선택, 선택 수 표시, 적용 전 확인을 제공한다. 조회 결과·필터·토큰이 바뀌면 선택을 초기화한다.
- API는 `PATCH /admin/users/type`와 `/manage-api/users/type`다.
- JSON 예: `{"userIds":["사용자ID1","사용자ID2"],"userType":"EMPLOYEE","reasonCode":"ADMIN_BULK_USER_TYPE_CHANGE"}`. 미분류는 userType=null을 명시한다.
- 대상은 중복 없는 ID 1~100개다. 대상 전체를 사전 검증하고 하나의 DB 트랜잭션으로 처리한다.
- 같은 유형은 변경하지 않으며 해당 사용자의 세션을 폐기하거나 변경 로그를 추가하지 않는다.
- 변경된 사용자마다 기존 Refresh Token을 폐기하고 중앙 세션 버전을 증가시키며 감사 로그를 남긴다. 일괄 작업의 감사 로그는 같은 batchId를 갖는다.
- 존재하지 않는 사용자, 중앙 관리자 보호 위반, DB/감사 기록 실패가 있으면 전체 요청을 실패시킨다. 일부 사용자만 성공한 상태로 남기지 않는다.
- 유형 변경만으로 계정을 활성화하거나 서비스 역할을 부여하지 않는다. GitLab/dashboard 접근 역할은 별도로 승인한다. 기존 역할 기록은 유지하고 로그인 시 유형과 역할을 함께 검사한다.

## 로컬 적용

전달 ZIP의 apply.py --check / apply.py로 소스를 적용한 뒤 저장소 루트에서 실행한다.

```bash
docker compose -f docker-compose.oauth-local.yml build app
bash integration-lab/lab.sh up
bash integration-lab/lab.sh bulk-check
```

**이번 패키지는 DB 스키마를 변경하지 않는다. 새 마이그레이션, setup, seed, policy-setup은 필요 없다.**
더미 앱 소스도 변경하지 않으므로 더미 이미지 재빌드는 필요 없다. 기존 .env와 .local은 유지한다.

bulk-check는 로컬 DB·개발 환경·issuer와 테스트 계정 UUID/이메일을 확인한다. 테스트 직원의 관리자 권한으로 unapproved/suspended 계정 두 개를 미분류로 변경하고, 멱등성·감사 로그·보호된 관리자 포함 시 전체 거부를 검사한 뒤 두 유형을 원래 EMPLOYEE로 복원한다. ACTIVE/SUSPENDED 상태는 유지한다. 토큰과 비밀번호는 출력하지 않는다.

기대 출력은 PASS 5개다. 변경한 테스트 계정의 이전 인증 세션은 복원 후에도 폐기된 상태다. 복원 PASS 없이 실패했다면 관리자 화면에서 두 계정의 유형을 확인한다. 고객/직원 계정 자체의 유형은 변경하지 않는다.

기존 검사도 실행한다.

```bash
bash integration-lab/lab.sh policy-check
bash integration-lab/lab.sh sso-check
```

## 관리자 화면 확인

관리자 브라우저 로그인 패키지 적용 후 https://localhost:4444/oauth2/admin/dashboard 에서 employee 테스트 계정으로 로그인한다. 토큰을 수동 입력하지 않는다. 비밀번호는 로컬 .local/fixtures.json에서 확인한다. 자세한 절차는 [ADMIN_BROWSER_LOGIN.md](ADMIN_BROWSER_LOGIN.md)를 참고한다.

1. 이메일 필터를 `@wise-lab.invalid`로 조회한다.
2. unapproved/suspended 두 계정만 체크한다. 선택 2명을 확인한다.
3. 미분류를 선택하고 일괄 변경을 실행한다. 확인 대화창에서 대상을 검토한다.
4. 미분류 필터로 두 계정이 표시되는지 확인한다.
5. 두 계정을 다시 선택해 직원으로 복원한다. 상태는 ACTIVE/SUSPENDED 그대로여야 한다.
6. 감사 로그에서 사용자별 admin_user_type_changed 기록을 확인한다. API의 detailsJson에는 이전·변경 유형, batchId, batchSize가 기록된다.
7. employee 중앙 관리자와 unapproved를 함께 선택해 고객으로 변경한다. 전체 거부되고 두 계정 모두 직원으로 유지되는지 재조회한다.
8. 필터를 바꾸거나 다시 조회했을 때 선택이 0명으로 초기화되는지 확인한다.

단위·HTTP 검사와 실제 JS DOM 이벤트 검사에서는 대상·중복·상한 검증, 전부 사전 검증, 감사 실패 롤백, 세션 버전 롤백, 취소, 처리 중 변경 방지, 필터/조회 후 선택 초기화, 실패 시 선택 유지, 안전한 텍스트 렌더링을 확인한다. 실제 Docker/브라우저 검증은 위 명령으로 수행해야 한다.

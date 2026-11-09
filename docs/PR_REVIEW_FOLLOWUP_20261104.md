# Client 정책 강화와 직원 초대

사용자 유형을 명시하지 않은 OIDC client를 거부하고, 중앙 관리자 보호를 모든 비활성 상태로 확장한다. 기존 temis:admin은 유지하면서 신규 부여는 막고 sso:admin을 중앙 관리에 사용한다. 직원은 관리자 초대 메일의 72시간 일회용 링크에서 직접 비밀번호를 설정한다.

- main 7fc3a19 위로 rebase.
- client별 ssoAutoLogin(default true), 필수 bulk reasonCode, provider 조건부 버튼.
- auth-portal 원본 동일성 및 XSS DOM oracle 보완.
- 초대 생성·재발송·취소·수락·메일 실패 감사, hash-only token, 신규 직원/역할의 원자적 생성.
- 기존 사용자 read-only 분류 preview와 운영자 실행용 SQL 분리. 자동 운영 쓰기 없음.

검증: 단위/HTTP 727 passed(12 skipped, IPC oracle 1개 제외), 자산/정책/초대 HTTP 묶음 14 passed +109 subtests, 보안 번들 관련 원본/수정본 각81 passed, mypy145, Prisma validate, 임시 WASM PostgreSQL의 fresh/기존 초안 migration·분류·초대 SQL replay.

로컬 검증: PostgreSQL 마이그레이션 2개 적용, 실제 Docker/SMTP 자동 검사 27개 통과(직원 초대 6, 관리자 로그인 7, 일괄 변경 5, 정책 3, 중앙 SSO 6). 사용자가 관리자 초대 → 로컬 메일 수신 → 직원 비밀번호 설정 → 직원 더미 로그인 브라우저 흐름을 확인했다.

미확인: 운영 환경·실제 서비스, 정확한 보안 번들 실패 traceback. 보안 번들 실패는 현재 원본/수정본에서 재현하지 못했다.

운영 분류 조회 결과: **미조회 — 운영 DB 접속 환경이 제공되지 않음.** 운영자가 preview.sql을 읽기 전용으로 실행한 뒤 실제 건수와 익명 샘플을 여기에 추가한다. 합성 테스트 수치를 운영 건수로 쓰지 않는다. apply.sql은 자동 실행하지 않는다.

Fantra 주의: 기존 legacy client ID/audience temis와 신규 OIDC ID를 중복시킬 수 없어, 신규 OIDC 예시는 fantra-oidc / 역할 temis:user로 분리했다. 기존 Fantra 연결 방식을 확정하기 전에는 운영 env를 교체하지 않는다. 초기 정책 SQL 수정에 따른 기존 DB checksum 경고와 legacy grant 복구 마이그레이션도 배포 검토 대상이다.

세부 검증: integration-lab/REVIEW_FEEDBACK_20261104.md. 고객 가입 패키지는 여전히 미적용·보류다.

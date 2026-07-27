# Changelog

이 프로젝트의 사용자 영향 변경을 기록합니다.

## Unreleased

### Changed

- 모노레포의 `ko-sqlguard/` 이력을 보존해 독립 저장소로 전환했습니다.
- 패키지 성숙도 표기를 실제 릴리스 증거에 맞춰 Beta로 조정했습니다.
- 독립 CI, 배포 경계, 보안 신고 및 기여 절차를 추가했습니다.

### Removed

- 중복 임시 분석 파일과 모노레포 전용 서비스 Dockerfile을 제거했습니다.

## 0.2.0

- PostgreSQL-first AST 검사, fail-closed 파싱, allowlist, 민감 컬럼, 위험 함수,
  카탈로그 정찰, tautology, cartesian 및 비용 가드를 포함합니다.
- 이 버전은 독립 저장소의 첫 릴리스 후보이며 stable tag는 별도 승격 gate 통과 후 생성합니다.

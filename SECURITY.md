# Security Policy

## Supported Versions

현재 지원 브랜치는 `main`입니다. Software Stable은 API와 패키지 품질 상태이며, 고객별
정책·스키마 qualification이나 운영 효과 보증과는 별개입니다.

## Reporting

SQL 우회, fail-open, 정책 우회, 민감정보 노출 또는 공급망 문제는 공개 issue로 먼저
보고하지 마십시오. 저장소의 **Security > Report a vulnerability**를 사용해 재현 절차,
영향 범위, 영향을 받는 commit과 가능한 완화책을 비공개로 전달해 주십시오.

private vulnerability reporting을 사용할 수 없다면 공개 exploit이나 실제 데이터 없이
최소한의 연락 요청만 issue에 남기고, 저장소 관리자가 비공개 채널을 제공할 때까지 상세 내용을
게시하지 마십시오.

관리자는 영업일 기준 3일 이내 접수를 확인하고, 7일 이내 초기 영향 판정과 다음 일정을
공유하는 것을 목표로 합니다.

## Scope

- SQL parser 또는 AST 검사 우회
- 허용되지 않은 쓰기, 카탈로그, 함수, 테이블 또는 컬럼 접근
- BLOCK 입력이 예외나 fallback으로 실행 가능해지는 fail-open
- 패키지, CI 또는 릴리스 provenance 위조

실제 개인정보, 자격증명, 고객 SQL 또는 미공개 취약점 증거를 공개 저장소에 올리지 마십시오.

# Contributing

## Before You Start

동작 변경은 먼저 issue에서 위협 모델, 예상 판정과 호환성 영향을 합의해 주십시오. 보안 문제는
공개 issue 대신 [SECURITY.md](./SECURITY.md)의 비공개 절차를 사용합니다.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
python -m ruff check src tests
python -m mypy
python -m pytest
```

변경에는 악성 입력과 인접한 정상 입력을 함께 고정하는 회귀 테스트가 필요합니다. `check()`가
SQL, DB 또는 네트워크를 실행하지 않는다는 계약과 fail-closed 기본값을 유지하십시오.

## Pull Requests

- 한 PR은 하나의 명확한 동작 변경에 집중합니다.
- 사용자 영향 변경은 `CHANGELOG.md`의 `Unreleased`에 기록합니다.
- 새 정책이나 violation code는 README와 타입/API 문서를 함께 갱신합니다.
- 생성물, 실제 고객 SQL, 자격증명과 비공개 평가 데이터는 커밋하지 않습니다.
- CI의 지원 Python 버전 테스트, ruff, mypy, pytest와 distribution build를 모두 통과합니다.

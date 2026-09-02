import json

import pytest

from ko_sqlguard.cli import main


def test_cli_checks_stdin_and_returns_block_exit(capsys, monkeypatch) -> None:
    monkeypatch.setattr("sys.stdin.read", lambda: "SELECT pg_sleep(1)")
    assert main([]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "block"
    assert payload["sql"] is None


def test_cli_accepts_schema_catalog(tmp_path, capsys) -> None:
    catalog = tmp_path / "schema.json"
    catalog.write_text(json.dumps({"orders": ["id"]}), "utf-8")
    assert main(["SELECT id FROM orders", "--schema-catalog", str(catalog)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "transform"
    assert "LIMIT" in payload["sql"].upper()


def test_cli_rejects_malformed_catalog_without_traceback(tmp_path, capsys) -> None:
    catalog = tmp_path / "schema.json"
    catalog.write_text("{", "utf-8")
    with pytest.raises(SystemExit) as exc_info:
        main(["SELECT 1", "--schema-catalog", str(catalog)])
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Traceback" not in captured.err

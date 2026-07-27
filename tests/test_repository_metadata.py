from pathlib import Path

from ko_sqlguard import __version__

ROOT = Path(__file__).resolve().parent.parent


def test_standalone_repository_contract() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text("utf-8")

    assert f'version = "{__version__}"' in pyproject
    assert '"Development Status :: 4 - Beta"' in pyproject
    assert (
        'Repository = "https://github.com/Marker-Inc-Korea/ko-sqlguard"'
        in pyproject
    )
    assert not (ROOT / "Dockerfile").exists()

    if (ROOT / ".git").exists():
        assert (ROOT / ".github" / "workflows" / "tests.yml").is_file()
        assert (ROOT / "CHANGELOG.md").is_file()
        assert (ROOT / "SECURITY.md").is_file()
        assert (ROOT / "CONTRIBUTING.md").is_file()

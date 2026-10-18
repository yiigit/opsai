from pathlib import Path
import importlib.util
import pytest

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_check", ROOT / "scripts" / "check_release_version.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_matching_tag():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    module.check_version(f"v{project['project']['version']}", ROOT / "pyproject.toml")


def test_package_version_matches_project_version():
    import opsai

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert opsai.__version__ == project["project"]["version"]


@pytest.mark.parametrize("tag", ["0.0.9", "v0.0.9", "v0.1.0", "bad"])
def test_invalid_tags(tag):
    with pytest.raises(ValueError):
        module.check_version(tag, ROOT / "pyproject.toml")


def test_commitizen_configuration():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert config["tool"]["commitizen"]["version_provider"] == "pep621"
    assert config["tool"]["commitizen"]["update_changelog_on_bump"] is True
    assert config["tool"]["commitizen"]["tag_format"] == "v$version"


def test_workflows_exist():
    for file in ["commitlint.yml", "release.yml", "ci.yml"]:
        assert (ROOT / ".github" / "workflows" / file).is_file()


def test_debian_installation_scripts_exist():
    for file in ["install.sh", "update.sh", "uninstall.sh", "scripts/build_deb.sh"]:
        assert (ROOT / file).is_file()

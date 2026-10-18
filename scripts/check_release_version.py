"""Fail a release if its tag disagrees with the PEP 621 project version."""
import sys
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib
from pathlib import Path


def check_version(tag: str, project_file: Path) -> None:
    if not tag.startswith("v"):
        raise ValueError("Release tag must start with v")
    data = tomllib.loads(project_file.read_text(encoding="utf-8"))
    actual = data["project"]["version"]
    if tag != f"v{actual}":
        raise ValueError(f"Tag {tag!r} does not match project version v{actual}")


if __name__ == "__main__":
    try:
        check_version(sys.argv[1], Path(__file__).resolve().parents[1] / "pyproject.toml")
    except (IndexError, ValueError, KeyError) as exc:
        print(f"Release version check failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

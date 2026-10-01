"""Test workers retain their tools without downloading the type-checker runtime."""

from pathlib import Path

import yaml

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[1]


def test_ci_group_preserves_dev_tools_except_the_type_checker() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    dev = project["project"]["optional-dependencies"]["dev"]
    group = project["dependency-groups"]["ci-test"]
    assert group == [requirement for requirement in dev if not requirement.startswith("basedpyright")]
    assert any(requirement.startswith("basedpyright") for requirement in dev)
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    package = next(package for package in lock["package"] if package["name"] == "hol-guard")
    assert {item["name"] for item in package["dev-dependencies"]["ci-test"]} == {
        "build",
        "pytest",
        "pytest-cov",
        "ruff",
    }


def test_test_workers_select_the_frozen_group_without_default_dev_dependencies() -> None:
    for filename in ("setup-ci-python", "native-regression"):
        action = yaml.safe_load((ROOT / f".github/actions/{filename}/action.yml").read_text())
        commands = "\n".join(step.get("run", "") for step in action["runs"]["steps"])
        assert "uv sync --frozen --no-dev --group ci-test" in commands
        assert "--extra dev" not in commands
    workflow = yaml.safe_load((ROOT / ".github/workflows/native-wheel-ci.yml").read_text())
    for job in ("wheel-contracts", "linux-build", "linux-proof", "windows-build", "windows-proof"):
        commands = "\n".join(step.get("run", "") for step in workflow["jobs"][job]["steps"])
        assert "uv sync --frozen --no-dev --group ci-test" in commands
    proof_setup = (ROOT / "scripts/ci/install-native-proof-dependencies.sh").read_text()
    assert "extras=(--group ci-test)" in proof_setup
    assert "--frozen --no-dev --no-install-project" in proof_setup

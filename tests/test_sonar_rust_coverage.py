"""Rust coverage must come from instrumented tests of the analyzed checkout."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.support.ci_workflow import expand_ci_job_actions

ROOT = Path(__file__).resolve().parents[1]


def test_rust_coverage_follows_verified_shards_and_precedes_scan_without_sonar_credentials() -> None:
    workflow = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")))
    steps = workflow["jobs"]["sonar"]["steps"]
    wait_index = next(i for i, step in enumerate(steps) if step.get("name") == "Wait for successful pytest coverage producers")
    download_index = next(i for i, step in enumerate(steps) if step.get("name") == "Download pytest coverage data")
    python_index = next(i for i, step in enumerate(steps) if step.get("name") == "Prepare Python coverage")
    coverage_index = next(i for i, step in enumerate(steps) if step.get("name") == "Generate current-checkout Rust coverage")
    scan_index = next(i for i, step in enumerate(steps) if step.get("name") == "Analyze with SonarQube Cloud")
    step = steps[coverage_index]
    assert wait_index < download_index < python_index < coverage_index < scan_index
    assert step["run"] == "bash scripts/ci/prepare_sonar_rust_coverage.sh coverage-data"
    assert step["if"] == "steps.token-presence.outputs.has-token == 'true'"
    assert not step.get("continue-on-error", False)
    assert "SONAR_TOKEN" not in step.get("env", {})
    properties = (ROOT / "sonar-project.properties").read_text(encoding="utf-8")
    assert "sonar.rust.lcov.reportPaths=coverage-reports/rust-lcov.info" in properties.splitlines()


def _run_rust_coverage(
    tmp_path: Path, mode: str = "", fail_command: str = "", *, external_profiles: int = 1
) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    bash = shutil.which("bash")
    if os.name == "nt" or bash is None:
        pytest.skip("Rust coverage runs on an Ubuntu Bash runner")
    script = tmp_path / "scripts/ci/prepare_sonar_rust_coverage.sh"
    script.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts/ci/prepare_sonar_rust_coverage.sh", script)
    (tmp_path / "rust").mkdir()
    coverage_data = tmp_path / "coverage-data"
    for index in range(external_profiles):
        profile = coverage_data / f"pytest-coverage-1-{index}" / "rust-profraw" / f"shard-{index}-1-module.profraw"
        profile.parent.mkdir(parents=True, exist_ok=True)
        profile.write_bytes(b"synthetic-profile")
    binaries = tmp_path / "bin"
    binaries.mkdir()
    log = tmp_path / "commands.log"
    report = tmp_path / "coverage-reports/rust-lcov.info"
    report.parent.mkdir()
    report.write_text("SF:stale.rs\nDA:1,1\nend_of_record\n", encoding="utf-8")
    for name in ("cargo", "rustup", "python"):
        stub = binaries / name
        stub.write_text(
            f"#!{bash}\n"
            'command="${0##*/} $*"\n'
            'printf "%s\\n" "$command" >> "$COMMAND_LOG"\n'
            'if [[ -n "$FAIL_COMMAND" && "$command" == "$FAIL_COMMAND"* ]]; then exit 7; fi\n'
            'if [[ "${0##*/}" == python ]]; then echo 1.88.0; exit 0; fi\n'
            'if [[ "$*" == *"llvm-cov --version"* ]]; then\n'
            '  if [[ "$COVERAGE_MODE" != install ]]; then echo "cargo-llvm-cov 0.6.21"; fi\n'
            '  exit 0\n'
            'fi\n'
            'if [[ "$*" == *"llvm-cov show-env --export-prefix"* ]]; then\n'
            '  printf "export LLVM_PROFILE_FILE=%q\\n" "$PWD/target/native-coverage/hol-guard-%p-%m.profraw"\n'
            '  printf "export RUSTFLAGS=%q\\n" "-C instrument-coverage"\n'
            '  exit 0\n'
            'fi\n'
            'if [[ "$*" == *"llvm-cov report"* && "$*" == *"--output-path"* ]]; then\n'
            '  if [[ -e "$REPORT" ]]; then echo "stale report survived" >&2; exit 8; fi\n'
            '  case "$COVERAGE_MODE" in\n'
            '    missing) ;;\n'
            '    empty) : > "$REPORT" ;;\n'
            '    malformed) echo "not LCOV" > "$REPORT" ;;\n'
            '    *) printf "SF:crates/example/src/lib.rs\\nDA:1,1\\nend_of_record\\n" > "$REPORT" ;;\n'
            '  esac\n'
            'fi\n',
            encoding="utf-8",
        )
        stub.chmod(0o700)
    result = subprocess.run(
        [bash, str(script), str(coverage_data)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        env={
            **os.environ,
            "PATH": f"{binaries}{os.pathsep}{os.environ.get('PATH', '')}",
            "COMMAND_LOG": str(log),
            "FAIL_COMMAND": fail_command,
            "COVERAGE_MODE": mode,
            "REPORT": str(report),
        },
    )
    return result, log.read_text(encoding="utf-8").splitlines()


@pytest.mark.parametrize("mode", ["", "install"])
def test_rust_coverage_merges_cargo_tests_and_external_native_profiles(tmp_path: Path, mode: str) -> None:
    result, commands = _run_rust_coverage(tmp_path, mode)
    assert result.returncode == 0, result.stderr
    assert "rustup component add --toolchain 1.88.0 llvm-tools-preview" in commands
    assert "cargo +1.88.0 llvm-cov show-env --export-prefix" in commands
    assert "cargo +1.88.0 llvm-cov clean --workspace" in commands
    assert "cargo +1.88.0 test --locked --release --workspace --all-targets" in commands
    assert (
        "cargo +1.88.0 build --locked --release -p guard-command -p hol-guard-runtime "
        "--bin guard-command-source --bin hol-guard-runtime"
    ) in commands
    expected = "cargo +1.88.0 llvm-cov report --release --lcov --output-path "
    assert any(command.startswith(expected) for command in commands)
    install = "cargo +1.88.0 install cargo-llvm-cov --version =0.6.21 --locked --force"
    assert (install in commands) == (mode == "install")


@pytest.mark.parametrize("mode", ["missing", "empty", "malformed"])
def test_rust_coverage_rejects_missing_empty_or_invalid_current_report(tmp_path: Path, mode: str) -> None:
    result, _ = _run_rust_coverage(tmp_path, mode)
    assert result.returncode != 0


def test_rust_coverage_requires_external_profiles_from_verified_shards(tmp_path: Path) -> None:
    result, _ = _run_rust_coverage(tmp_path, external_profiles=0)
    assert result.returncode != 0
    assert "Merging 0 external native coverage profiles" in result.stdout


@pytest.mark.parametrize(
    "fail_command",
    [
        "python",
        "rustup component add",
        "cargo +1.88.0 install",
        "cargo +1.88.0 llvm-cov show-env",
        "cargo +1.88.0 llvm-cov clean",
        "cargo +1.88.0 test --locked",
        "cargo +1.88.0 build --locked",
        "cargo +1.88.0 llvm-cov report",
    ],
)
def test_rust_coverage_propagates_setup_cleanup_and_test_failures(tmp_path: Path, fail_command: str) -> None:
    result, commands = _run_rust_coverage(tmp_path, "install", fail_command)
    assert result.returncode == 7, result.stderr
    assert commands[-1].startswith(fail_command)

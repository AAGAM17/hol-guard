"""Keep one mandatory Linux workspace proof and all specialized security qualification."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
STANDALONE = "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'"


def workflow(name: str) -> dict:
    """Load only declarative workflow metadata, never repository runtime code."""
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))


def test_required_native_preflight_proves_the_complete_workspace_before_shards() -> None:
    ci = workflow("ci.yml")
    events = ci.get("on", ci.get(True))
    for event in ("push", "pull_request"):
        assert "main" in events[event]["branches"]
        assert "paths" not in events[event] and "paths-ignore" not in events[event]
    jobs = ci["jobs"]
    native = jobs["native-command-evaluators"]
    assert "if" not in native and "continue-on-error" not in native
    assert 10 <= native["timeout-minutes"] <= 20
    steps = native["steps"]
    fmt = next(i for i, step in enumerate(steps) if "cargo fmt " in step.get("run", ""))
    lint = next(i for i, step in enumerate(steps) if "cargo clippy " in step.get("run", ""))
    test = next(i for i, step in enumerate(steps) if "cargo test " in step.get("run", ""))
    build = next(i for i, step in enumerate(steps) if "cargo build " in step.get("run", ""))
    assert fmt < lint < test < build
    for index in (lint, test):
        step = steps[index]
        assert "--locked --workspace --all-targets" in step["run"]
        assert "if" not in step and "continue-on-error" not in step
        assert "--skip" not in step["run"] and "|| true" not in step["run"]
    assert "-- -D warnings" in steps[lint]["run"]
    setup = next(step for step in steps if step.get("uses") == "./.github/actions/setup-rust")
    assert setup["with"]["components"] == "rustfmt clippy"
    assert jobs["quality"]["needs"] == "native-command-evaluators"
    assert jobs["coverage-plan"]["needs"] == "native-command-evaluators"
    assert "native-command-evaluators" in jobs["coverage"]["needs"]
    required = jobs["ci-python-312"]
    assert required["name"] == "ci (3.12)" and required["if"] == "always()"
    assert {"quality", "coverage-plan", "coverage"} <= set(required["needs"])


@pytest.mark.skipif(os.name == "nt", reason="The required aggregate executes on Ubuntu with Bash")
@pytest.mark.parametrize("result", ["failure", "cancelled", "skipped", "timed_out"])
@pytest.mark.parametrize("dependency", ["QUALITY_RESULT", "COVERAGE_PLAN_RESULT", "COVERAGE_RESULT"])
def test_required_aggregate_rejects_a_failed_or_skipped_native_dependency(result: str, dependency: str) -> None:
    job = workflow("ci.yml")["jobs"]["ci-python-312"]
    step = job["steps"][0]
    environment = {name: "success" for name in step["env"]}
    environment[dependency] = result
    completed = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", step["run"]],
        env={**os.environ, **environment},
        check=False,
        capture_output=True,
        timeout=5,
    )
    assert completed.returncode != 0


@pytest.mark.parametrize(
    ("name", "job_id", "step_name"),
    [
        ("rust-authority-ownership.yml", "ownership", "Compile and lint complete Rust workspace"),
        ("rust-command-model-differential.yml", "command-model", "Validate locked command workspace"),
        ("rust-posttool-authority-acceptance.yml", "authority", "Build and lint"),
        ("rust-runtime-rule-contract.yml", "rule-contract", "Validate locked Rust workspace"),
        ("rust-runtime-windows-resident.yml", "unix-regression", "Check locked Rust workspace"),
        ("rust-runtime.yml", "rust", "Test"),
    ],
)
def test_standalone_workspace_proofs_remain_available_without_duplicate_pr_execution(name, job_id, step_name):
    job = workflow(name)["jobs"][job_id]
    proof = next(step for step in job["steps"] if step.get("name") == step_name)
    assert proof["if"] == STANDALONE
    assert "cargo test" in proof["run"] and "--workspace --all-targets" in proof["run"]
    assert "continue-on-error" not in job and "continue-on-error" not in proof
    # Independent runtime builds still run for these workflow-specific probes.
    builds = [step for step in job["steps"] if "cargo build" in step.get("run", "")]
    assert builds and all("if" not in step and "continue-on-error" not in step for step in builds)


def test_windows_and_macos_workspace_proofs_remain_platform_specific() -> None:
    for name in ("rust-daemon-edge-hardening.yml", "rust-runtime-windows-resident.yml"):
        job = workflow(name)["jobs"]["windows-workspace"]
        assert "if" not in job and "continue-on-error" not in job
        proof = next(step for step in job["steps"] if "cargo test " in step.get("run", ""))
        assert "if" not in proof and "--workspace --all-targets" in proof["run"]
    steps = workflow("rust-daemon-edge-hardening.yml")["jobs"]["cross-platform"]["steps"]
    proof = next(step for step in steps if "cargo test " in step.get("run", ""))
    assert proof["if"] == (
        "runner.os == 'macOS' || (runner.os == 'Linux' && "
        "(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'))"
    )
    lifecycle = next(step for step in steps if step.get("name") == "Validate real native client lifecycle")
    assert "if" not in lifecycle and "continue-on-error" not in lifecycle

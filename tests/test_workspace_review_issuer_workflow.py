"""The release-root issuer stays behind its reviewed main and custodian gates."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest
import yaml

_PATH = Path(__file__).resolve().parents[1] / ".github/workflows/issue-workspace-review-authority.yml"
_MAIN_GATE = (
    "github.repository == 'hashgraph-online/hol-guard' && github.ref == 'refs/heads/main' && github.run_attempt == 1"
)
_ROOT_SEED = "HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_SEED_HEX"


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    raw = cast(dict[object, object], value)
    assert all(isinstance(key, str) for key in raw)
    return {cast(str, key): item for key, item in raw.items()}


def _workflow() -> dict[str, object]:
    return _mapping(cast(object, yaml.safe_load(_PATH.read_text(encoding="utf-8"))))


def _jobs(workflow: dict[str, object]) -> dict[str, dict[str, object]]:
    return {name: _mapping(job) for name, job in _mapping(workflow["jobs"]).items()}


def _steps(job: dict[str, object]) -> list[dict[str, object]]:
    value = job["steps"]
    assert isinstance(value, list)
    return [_mapping(step) for step in cast(list[object], value)]


def test_issuer_only_runs_from_main_after_public_validation_and_custodian_review() -> None:
    workflow = _workflow()
    triggers = _mapping(workflow["on"])
    assert set(triggers) == {"workflow_dispatch"}
    assert workflow["permissions"] == {"contents": "read"}
    jobs = _jobs(workflow)
    assert set(jobs) == {"validate", "sign"}
    assert jobs["validate"]["if"] == jobs["sign"]["if"] == _MAIN_GATE
    assert jobs["sign"]["needs"] == "validate"
    assert jobs["sign"]["environment"] == "guard-approval-root"
    for job in jobs.values():
        assert job["permissions"] == {"contents": "read", "actions": "read"}
        assert "env" not in job
        protection = str(_steps(job)[0]["run"])
        assert "environments/guard-approval-root" in protection
        assert "grep -qx true" in protection


def test_root_seed_only_reaches_the_signer_and_public_artifacts_are_exact_files() -> None:
    workflow = _workflow()
    seed_steps: list[dict[str, object]] = []
    for job in _jobs(workflow).values():
        for step in _steps(job):
            if _ROOT_SEED in json.dumps(step):
                seed_steps.append(step)
            if "uses" in step:
                assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", str(step["uses"]))
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step["with"] == {"ref": "${{ github.sha }}", "persist-credentials": False}
            if str(step.get("uses", "")).startswith("actions/upload-artifact@"):
                config = _mapping(step["with"])
                assert config["path"] in {"authority-request.json", "workspace-review-authority.json"}
                assert config["if-no-files-found"] == "error"
    assert len(seed_steps) == 1
    signer = seed_steps[0]
    assert signer["run"] == (
        "uv run --no-sync python scripts/approval/issue_workspace_review_authority.py "
        '--request authority-request.json --expected-request-sha256 "$EXPECTED_REQUEST_DIGEST" '
        "--output workspace-review-authority.json"
    )
    assert _mapping(signer["env"])["EXPECTED_REQUEST_DIGEST"] == "${{ needs.validate.outputs.request_digest }}"
    steps = _steps(_jobs(workflow)["sign"])
    assert steps.index(signer) > next(
        i for i, step in enumerate(steps) if step.get("name") == "Verify reviewed request digest"
    )
    assert steps.index(signer) > next(
        i for i, step in enumerate(steps) if step.get("name") == "Verify independent custodian reviewed these bytes"
    )
    assert all("secrets." not in json.dumps(step) for step in steps[: steps.index(signer)])


_GATE_CASES: tuple[tuple[list[object], bool], ...] = (
    ([], False),
    ([{"type": "wait_timer", "wait_timer": 1}], False),
    ([{"type": "required_reviewers", "prevent_self_review": False, "reviewers": [{"type": "User"}]}], False),
    ([{"type": "required_reviewers", "prevent_self_review": True, "reviewers": []}], False),
    ([{"type": "required_reviewers", "prevent_self_review": True, "reviewers": [{"type": "Team"}]}], False),
    ([{"type": "required_reviewers", "prevent_self_review": True, "reviewers": [{"type": "User"}]}], True),
)


@pytest.mark.parametrize(("rules", "accepted"), _GATE_CASES)
def test_custodian_gate_rejects_missing_or_self_reviewable_protection(rules: list[object], accepted: bool) -> None:
    jq = shutil.which("jq")
    if jq is None:
        pytest.skip("jq is required to execute the workflow's environment predicate")
    workflow = _workflow()
    for job in _jobs(workflow).values():
        command = str(_steps(job)[0]["run"])
        predicate = re.search(r"--jq '([^']+)'", command)
        assert predicate is not None
        result = subprocess.run(
            [jq, predicate.group(1)],
            input=json.dumps({"protection_rules": rules}),
            text=True,
            capture_output=True,
            check=True,
        )
        assert json.loads(result.stdout) is accepted


@pytest.mark.parametrize(
    ("change", "accepted"),
    (
        ("approved", True),
        ("no_review", False),
        ("wrong_digest", False),
        ("unlisted_reviewer", False),
        ("self_review", False),
        ("rerun_self_review", False),
        ("wrong_environment", False),
        ("rejected", False),
        ("team_only", False),
        ("self_review_allowed", False),
    ),
)
def test_actual_digest_bound_custodian_approval_is_required(tmp_path: Path, change: str, accepted: bool) -> None:
    rule: dict[str, object] = {
        "type": "required_reviewers",
        "prevent_self_review": change != "self_review_allowed",
        "reviewers": [{"type": "Team" if change == "team_only" else "User", "reviewer": {"id": 2}}],
    }
    login = {"self_review": "Initiator", "rerun_self_review": "Rerunner"}.get(change, "Custodian")
    review: dict[str, object] = {
        "state": "rejected" if change == "rejected" else "approved",
        "comment": "authority-request-sha256:" + ("b" if change == "wrong_digest" else "a") * 64,
        "user": {"id": 3 if change == "unlisted_reviewer" else 2, "login": login},
        "environments": [{"id": 43 if change == "wrong_environment" else 42}],
    }
    _ = (tmp_path / "authority-environment.json").write_text(
        json.dumps({"id": 42, "protection_rules": [rule]}), encoding="utf-8"
    )
    _ = (tmp_path / "authority-reviews.json").write_text(
        json.dumps([] if change == "no_review" else [review]), encoding="utf-8"
    )
    step = next(
        step
        for step in _steps(_jobs(_workflow())["sign"])
        if step.get("name") == "Verify independent custodian reviewed these bytes"
    )
    code = str(step["run"]).split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=tmp_path,
        env={
            "GITHUB_ACTOR": "initiator",
            "GITHUB_TRIGGERING_ACTOR": "rerunner",
            "EXPECTED_REQUEST_DIGEST": "a" * 64,
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode == 0) is accepted

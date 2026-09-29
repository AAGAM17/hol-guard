"""Focused checks for the bounded built-in synthetic evaluation runner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import evaluation_runner as runner
from codex_plugin_scanner.guard.evaluation_cli import main
from codex_plugin_scanner.guard.evaluation_contracts import EvaluationProfile
from codex_plugin_scanner.guard.evaluation_preflight import setup_evaluation

from .evaluation_cli_fixtures import _profile


def _write_runner_profile(tmp_path: Path, case_ids: tuple[str, ...]) -> tuple[Path, dict[str, object]]:
    executable = tmp_path / "unused-host"
    executable.write_text("#!/bin/sh\nexit 64\n", encoding="utf-8")
    executable.chmod(0o755)
    profile = _profile(tmp_path, executable)
    profile["expectedCapabilities"] = [
        {"capabilityId": case_id, "expectedAction": "block"} for case_id in case_ids
    ]
    profile_path = tmp_path / "runner-profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    return profile_path, profile


def _run_payload(capsys, profile_path: Path, *extra: str) -> tuple[int, dict[str, object]]:
    code = main(["run", "--profile", str(profile_path), *extra])
    payload = json.loads(capsys.readouterr().out)
    return code, payload


def test_run_rejects_profile_capability_outside_builtin_cases(tmp_path: Path, capsys) -> None:
    profile_path, _ = _write_runner_profile(tmp_path, ("synthetic.read",))

    code, payload = _run_payload(capsys, profile_path)

    assert code == 2
    assert payload["status"] == "not_run"
    assert payload["error"]["code"] == "case_not_supported"


def test_run_rejects_partial_case_selection(tmp_path: Path, capsys) -> None:
    profile_path, _ = _write_runner_profile(
        tmp_path,
        (runner.SHELL_CASE_ID, runner.EGRESS_CASE_ID),
    )

    code, payload = _run_payload(capsys, profile_path, "--case", runner.SHELL_CASE_ID)

    assert code == 2
    assert payload["status"] == "not_run"
    assert payload["error"]["code"] == "case_coverage_invalid"


def test_run_reports_timeout_and_cleans_owned_setup(monkeypatch, tmp_path: Path, capsys) -> None:
    profile_path, _ = _write_runner_profile(tmp_path, (runner.SHELL_CASE_ID,))

    def timeout(*_args, **_kwargs):
        raise runner.EvaluationRunnerError("run_timeout", "deadline", status="blocked_environment")

    monkeypatch.setattr(runner, "_run_case", timeout)
    code, payload = _run_payload(capsys, profile_path)

    assert code == 2
    assert payload["status"] == "blocked_environment"
    assert payload["run"]["cases"][0]["errorCode"] == "run_timeout"
    assert payload["cleanup"] == {"removed": True, "recoveryTokenRetained": False}
    assert not list(tmp_path.glob("hol-guard-eval-*"))


@pytest.mark.parametrize(
    ("patch_name", "error_code"),
    (
        ("check_network_ready", "receiver_not_ready"),
        ("_fixed_network_control", "control_failed"),
    ),
)
def test_run_reports_receiver_and_control_failures(
    monkeypatch,
    tmp_path: Path,
    capsys,
    patch_name: str,
    error_code: str,
) -> None:
    profile_path, _ = _write_runner_profile(tmp_path, (runner.EGRESS_CASE_ID,))
    if patch_name == "check_network_ready":
        monkeypatch.setattr(runner.LocalSideEffectWitness, patch_name, lambda _self: False)
    else:
        monkeypatch.setattr(
            runner,
            patch_name,
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                runner.EvaluationRunnerError(error_code, "control", status="failed")
            ),
        )

    code, payload = _run_payload(capsys, profile_path)

    assert code == 2
    assert payload["run"]["cases"][0]["errorCode"] == error_code
    assert payload["cleanup"]["removed"] is True
    assert not list(tmp_path.glob("hol-guard-eval-*"))


def test_run_preserves_unrelated_bytes_and_never_invokes_host(tmp_path: Path, capsys) -> None:
    profile_path, profile = _write_runner_profile(
        tmp_path,
        (runner.SHELL_CASE_ID, runner.EGRESS_CASE_ID),
    )
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_bytes(b"keep me")
    host_path = Path(str(profile["hostIdentity"]["executable"]))  # type: ignore[index]
    marker = tmp_path / "host-ran"
    host_path.write_text(
        "#!/bin/sh\n"
        f"touch '{marker}'\n"
        "exit 0\n",
        encoding="utf-8",
    )
    host_path.chmod(0o755)

    code, payload = _run_payload(capsys, profile_path)
    encoded = json.dumps(payload)

    assert code == 2
    assert payload["status"] == "blocked_environment"
    assert payload["run"]["proofBoundary"] == "synthetic_adapter_test"
    assert all(case["proofType"] == "synthetic_adapter_test" for case in payload["run"]["cases"])
    assert all(case["observedAction"] is None for case in payload["run"]["cases"])
    assert all(case["hostEventBound"] is False for case in payload["run"]["cases"])
    assert unrelated.read_bytes() == b"keep me"
    assert not marker.exists()
    assert str(tmp_path) not in encoded
    assert not list(tmp_path.glob("hol-guard-eval-*"))


def test_synthetic_setup_skips_host_probe_and_artifacts(tmp_path: Path) -> None:
    profile_path, profile_data = _write_runner_profile(tmp_path, (runner.SHELL_CASE_ID,))
    del profile_path
    profile = EvaluationProfile.from_dict(profile_data)

    setup = setup_evaluation(profile, execution_mode="synthetic_adapter")
    try:
        assert setup.report.status == "passed"
        assert {check["reason"] for check in setup.report.checks if check["name"] == "host_version"} == {
            "synthetic_adapter_mode"
        }
    finally:
        assert setup.cleanup() is True

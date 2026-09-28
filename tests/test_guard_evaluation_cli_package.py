from __future__ import annotations

import copy
import json
import os
import platform
from hashlib import sha256
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.evaluation_cli import main
from codex_plugin_scanner.guard.evaluation_contracts import EVALUATION_PROFILE_SCHEMA_VERSION
from codex_plugin_scanner.guard.evaluation_evidence_package import build_evaluation_evidence_package


def _host_os() -> str:
    value = platform.system().lower()
    return "macos" if value == "darwin" else value


def _host_architecture() -> str:
    value = platform.machine().lower().replace("-", "_")
    return {"amd64": "x86_64", "aarch64": "arm64"}.get(value, value)


def _profile(tmp_path: Path, executable: Path) -> dict[str, object]:
    root = tmp_path
    artifact_digest = "sha256:" + sha256(b"synthetic artifact").hexdigest()
    endpoint = "http://127.0.0.1:8765/receiver"
    return {
        "schemaVersion": EVALUATION_PROFILE_SCHEMA_VERSION,
        "profileId": "synthetic-cli-v1",
        "buildIdentity": {
            "product": "hol-guard-core",
            "version": "3.5.0",
            "commit": "a" * 40,
            "artifactDigest": artifact_digest,
        },
        "hostIdentity": {
            "product": "synthetic-agent",
            "version": "0.1.0",
            "os": _host_os(),
            "architecture": _host_architecture(),
            "runtimeLocation": "local",
            "requiredPrivilege": ("administrator" if hasattr(os, "geteuid") and os.geteuid() == 0 else "standard_user"),
            "executable": str(executable),
        },
        "installedArtifacts": [
            {
                "artifactId": "core-fixture",
                "kind": "core",
                "version": "3.5.0",
                "digest": artifact_digest,
            }
        ],
        "policyIdentity": {
            "policyId": "synthetic-policy-v1",
            "version": "1",
            "digest": "sha256:" + "b" * 64,
        },
        "network": {
            "mode": "local_only",
            "allowedEndpoints": [endpoint],
            "proxyUrl": None,
        },
        "fixture": {
            "fixtureId": "synthetic-fixture-v1",
            "version": "1",
            "digest": "sha256:" + "c" * 64,
        },
        "targetScope": {
            "rootPath": str(root),
            "allowedPaths": [str(root)],
            "allowedEndpoints": [endpoint],
        },
        "resourceLimits": {
            "maxDurationSeconds": 60,
            "maxOutputBytes": 1024 * 1024,
            "maxMemoryBytes": 128 * 1024 * 1024,
            "maxConcurrency": 2,
        },
        "expectedCapabilities": [
            {"capabilityId": "synthetic.read", "expectedAction": "allow"},
        ],
    }


def _write_profile(tmp_path: Path) -> tuple[Path, Path, dict[str, object]]:
    executable = tmp_path / "synthetic-agent"
    marker = tmp_path / "host-ran"
    executable.write_text(
        "#!/bin/sh\n"
        f"if [ \"$1\" = \"--version\" ]; then touch '{marker}'; printf '%s\\n' 'synthetic-agent 0.1.0'; exit 0; fi\n"
        "exit 64\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    artifact = tmp_path / "core-fixture.bin"
    artifact.write_bytes(b"synthetic artifact")
    profile = _profile(tmp_path, executable)
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    return profile_path, marker, profile


def _result(profile: dict[str, object], *, profile_id: str | None = None) -> dict[str, object]:
    artifact = profile["installedArtifacts"][0]  # type: ignore[index]
    return {
        "schemaVersion": "guard.evaluation-result.v1",
        "resultId": "result-1",
        "profileId": profile_id if profile_id is not None else profile["profileId"],
        "buildIdentity": copy.deepcopy(profile["buildIdentity"]),
        "artifactIdentity": copy.deepcopy(artifact),
        "evidenceIdentity": {
            "evidenceId": "evidence-1",
            "proofRunId": "run-1",
            "evidenceType": "unit_test",
            "artifactDigest": artifact["digest"],  # type: ignore[index]
        },
        "status": "passed",
        "startedAt": "2026-09-23T12:00:00Z",
        "finishedAt": "2026-09-23T12:00:01Z",
        "cases": [
            {
                "caseId": "synthetic.read",
                "status": "passed",
                "expectedAction": "allow",
                "observedAction": "allow",
                "proofType": "unit_test",
                "witness": {"kind": "none"},
            }
        ],
        "summary": {"passed": 1, "failed": 0, "unsupported": 0, "blockedEnvironment": 0, "notRun": 0},
    }


def _payload(capsys) -> dict[str, object]:
    return json.loads(capsys.readouterr().out)


def test_verify_evidence_reports_canonical_manifest(tmp_path: Path, capsys) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    artifact = profile["installedArtifacts"][0]  # type: ignore[index]
    result = {
        "schemaVersion": "guard.evaluation-result.v1",
        "resultId": "result-1",
        "profileId": profile["profileId"],
        "buildIdentity": copy.deepcopy(profile["buildIdentity"]),
        "artifactIdentity": copy.deepcopy(artifact),
        "evidenceIdentity": {
            "evidenceId": "evidence-1",
            "proofRunId": "run-1",
            "evidenceType": "unit_test",
            "artifactDigest": artifact["digest"],  # type: ignore[index]
        },
        "status": "passed",
        "startedAt": "2026-09-23T12:00:00Z",
        "finishedAt": "2026-09-23T12:00:01Z",
        "cases": [
            {
                "caseId": "synthetic.read",
                "status": "passed",
                "expectedAction": "allow",
                "observedAction": "allow",
                "proofType": "unit_test",
                "witness": {"kind": "none"},
            }
        ],
        "summary": {"passed": 1, "failed": 0, "unsupported": 0, "blockedEnvironment": 0, "notRun": 0},
    }
    package_path = tmp_path / "evidence.zip"
    package_path.write_bytes(build_evaluation_evidence_package(profile, result))

    status = main(["verify-evidence", str(package_path)])

    payload = _payload(capsys)
    assert status == 0
    assert payload["status"] == "passed"
    assert payload["manifest"]["proofBoundary"] == "caller_supplied_unverified"  # type: ignore[index]
    assert payload["manifest"]["profileId"] == profile["profileId"]  # type: ignore[index]
    assert profile_path.is_file()


@pytest.mark.skipif(os.name == "nt", reason="evidence package writer requires POSIX directory descriptors")
def test_package_evidence_writes_a_private_package_that_verify_can_read(tmp_path: Path, capsys) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_result(profile)), encoding="utf-8")

    status = main(
        [
            "package-evidence",
            "--profile",
            str(profile_path),
            "--result",
            str(result_path),
            "--output-dir",
            str(tmp_path),
        ]
    )

    payload = _payload(capsys)
    assert status == 0
    assert payload["command"] == "package-evidence"
    assert payload["status"] == "passed"
    package = payload["package"]
    package_path = Path(package["path"])  # type: ignore[index]
    assert package_path.parent == tmp_path
    assert package["digest"].startswith("sha256:")  # type: ignore[index]
    assert package["proofBoundary"] == "caller_supplied_unverified"  # type: ignore[index]
    assert package_path.is_file()

    verify_status = main(["verify-evidence", str(package_path)])
    verify_payload = _payload(capsys)
    assert verify_status == 0
    assert verify_payload["status"] == "passed"
    assert verify_payload["manifest"]["proofBoundary"] == "caller_supplied_unverified"  # type: ignore[index]


def test_package_evidence_rejects_mismatched_result_without_echoing_values(tmp_path: Path, capsys) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    secret_marker = "private-result-marker"
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_result(profile, profile_id=secret_marker)), encoding="utf-8")

    status = main(
        [
            "package-evidence",
            "--profile",
            str(profile_path),
            "--result",
            str(result_path),
            "--output-dir",
            str(tmp_path),
        ]
    )

    payload = _payload(capsys)
    assert status == 2
    assert payload["status"] == "not_run"
    assert payload["error"] == {"code": "result_invalid", "message": "evaluation result is invalid"}
    assert secret_marker not in json.dumps(payload)
    assert not list(tmp_path.glob("hol-guard-eval-evidence-*.zip"))


def test_package_evidence_bounds_result_json_before_parsing(tmp_path: Path, capsys) -> None:
    profile_path, _, _ = _write_profile(tmp_path)
    secret_marker = b"private-oversized-result-marker"
    result_path = tmp_path / "result.json"
    result_path.write_bytes(b'{"marker":"' + secret_marker + b'","padding":"' + b"x" * (1024 * 1024) + b'"}')

    status = main(
        [
            "package-evidence",
            "--profile",
            str(profile_path),
            "--result",
            str(result_path),
            "--output-dir",
            str(tmp_path),
        ]
    )

    payload = _payload(capsys)
    assert status == 2
    assert payload["status"] == "blocked_environment"
    assert payload["error"] == {
        "code": "result_too_large",
        "message": "evaluation result exceeds the configured input limit",
    }
    assert secret_marker.decode() not in json.dumps(payload)
    assert not list(tmp_path.glob("hol-guard-eval-evidence-*.zip"))


@pytest.mark.parametrize(
    ("record", "raw", "expected_code"),
    [
        ("profile", '{"profileId":"one","profileId":"two"}', "profile_json_invalid"),
        ("profile", '{"profileId":NaN}', "profile_json_invalid"),
        ("result", '{"resultId":"one","resultId":"two"}', "result_json_invalid"),
        ("result", '{"resultId":Infinity}', "result_json_invalid"),
    ],
)
def test_package_evidence_rejects_ambiguous_json_records(
    tmp_path: Path, capsys, record: str, raw: str, expected_code: str
) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    result_path = tmp_path / "result.json"
    if record == "profile":
        profile_path.write_text(raw, encoding="utf-8")
        result_path.write_text(json.dumps(_result(profile)), encoding="utf-8")
    else:
        result_path.write_text(raw, encoding="utf-8")

    status = main(
        [
            "package-evidence",
            "--profile",
            str(profile_path),
            "--result",
            str(result_path),
            "--output-dir",
            str(tmp_path),
        ]
    )

    payload = _payload(capsys)
    assert status == 2
    assert payload["error"]["code"] == expected_code  # type: ignore[index]
    assert not list(tmp_path.glob("hol-guard-eval-evidence-*.zip"))


@pytest.mark.skipif(os.name == "nt", reason="evidence package writer requires POSIX directory descriptors")
def test_package_evidence_rejects_overwrite_and_out_of_scope_output(tmp_path: Path, capsys) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_result(profile)), encoding="utf-8")
    arguments = [
        "package-evidence",
        "--profile",
        str(profile_path),
        "--result",
        str(result_path),
        "--output-dir",
        str(tmp_path),
    ]

    assert main(arguments) == 0
    first_payload = _payload(capsys)
    package_path = Path(first_payload["package"]["path"])  # type: ignore[index]

    assert main(arguments) == 2
    overwrite_payload = _payload(capsys)
    assert overwrite_payload["status"] == "blocked_environment"
    assert overwrite_payload["error"] == {
        "code": "output_exists",
        "message": "evaluation evidence package already exists",
    }
    assert package_path.is_file()

    outside = tmp_path / "different-private-root"
    outside.mkdir(mode=0o700)
    outside_arguments = [*arguments[:-1], str(outside)]
    assert main(outside_arguments) == 2
    scope_payload = _payload(capsys)
    assert scope_payload["status"] == "blocked_environment"
    assert scope_payload["error"] == {
        "code": "output_scope_invalid",
        "message": "evaluation evidence output is outside the profile private temporary scope",
    }
    assert list(outside.iterdir()) == []


@pytest.mark.skipif(os.name == "nt", reason="evidence package writer requires POSIX directory descriptors")
def test_package_evidence_reports_generic_write_failure_without_calling_it_an_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_result(profile)), encoding="utf-8")

    def fail_sync(_descriptor: int) -> None:
        raise OSError("synthetic permission failure")

    monkeypatch.setattr("codex_plugin_scanner.guard.evaluation_evidence_package.os.fsync", fail_sync)
    status = main(
        [
            "package-evidence",
            "--profile",
            str(profile_path),
            "--result",
            str(result_path),
            "--output-dir",
            str(tmp_path),
        ]
    )

    payload = _payload(capsys)
    assert status == 2
    assert payload["status"] == "blocked_environment"
    assert payload["error"] == {
        "code": "evidence_package_write_failed",
        "message": "evaluation evidence package could not be written safely",
    }
    assert not list(tmp_path.glob("hol-guard-eval-evidence-*.zip"))


@pytest.mark.skipif(os.name == "nt", reason="evidence package writer requires POSIX directory descriptors")
def test_package_evidence_rejects_nonportable_root_before_writing(tmp_path: Path, capsys) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    (tmp_path / "nested").mkdir(mode=0o700)
    declared_root = str(tmp_path / "nested" / "..")
    profile["targetScope"]["rootPath"] = declared_root  # type: ignore[index]
    profile["targetScope"]["allowedPaths"] = [str(tmp_path / "workspace")]  # type: ignore[index]
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_result(profile)), encoding="utf-8")

    status = main(["package-evidence", str(profile_path), str(result_path), str(tmp_path)])

    payload = _payload(capsys)
    assert status == 2
    assert payload["status"] != "passed"
    assert not list(tmp_path.glob("hol-guard-eval-evidence-*.zip"))


@pytest.mark.skipif(os.name == "nt", reason="evidence package writer requires POSIX directory descriptors")
def test_package_evidence_reports_unpaired_surrogate_without_traceback(tmp_path: Path, capsys) -> None:
    profile_path, _, profile = _write_profile(tmp_path)
    profile["hostIdentity"]["product"] = "\ud800"  # type: ignore[index]
    profile_path.write_text(json.dumps(profile), encoding="utf-8")
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps(_result(profile)), encoding="utf-8")

    status = main(["package-evidence", str(profile_path), str(result_path), str(tmp_path)])

    payload = _payload(capsys)
    assert status == 2
    assert payload["error"]["code"] == "evidence_package_invalid"  # type: ignore[index]
    assert "\ud800" not in json.dumps(payload)
    assert not list(tmp_path.glob("hol-guard-eval-evidence-*.zip"))

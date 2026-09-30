"""Reject stale dependency pins before actual SDK qualification."""

import json
from pathlib import Path

import pytest

from scripts.ci import verify_pi_exact_continuation as verifier


@pytest.mark.parametrize("field,value", [("version", "5.0.9"), ("integrity", "sha512-invalid")])
def test_lock_rejects_stale_brace_dependency(tmp_path: Path, field: str, value: str) -> None:
    lock = json.loads(Path("ci/pi-exact-continuation/package-lock.json").read_text())
    lock["packages"][f"node_modules/{verifier.PI_PACKAGE}/node_modules/brace-expansion"][field] = value
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(lock))
    with pytest.raises(SystemExit, match="brace-expansion lock entry drifted"):
        verifier.verify_lock(path)


@pytest.mark.parametrize(
    "version,expected",
    [("5.0.9", "installed brace-expansion version drifted"), ("5.0.11", "installed brace-expansion integrity drifted")],
)
def test_installed_gate_rejects_stale_version_or_wrong_integrity(
    tmp_path: Path, version: str, expected: str
) -> None:
    for name, (sdk_version, _) in verifier.EXPECTED.items():
        root = tmp_path / "node_modules" / name
        root.mkdir(parents=True)
        (root / "package.json").write_text(json.dumps({"name": name, "version": sdk_version}))
    brace = tmp_path / "node_modules" / verifier.PI_PACKAGE / "node_modules" / "brace-expansion"
    brace.mkdir(parents=True)
    (brace / "package.json").write_text(json.dumps({"version": version}))
    (brace.parent / ".package-lock.json").write_text(
        json.dumps({"packages": {"node_modules/brace-expansion": {"integrity": "sha512-invalid"}}})
    )
    with pytest.raises(SystemExit, match=expected):
        verifier.verify_installed_sdk(tmp_path)

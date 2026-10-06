"""Native business content bridge and durable publisher identity regressions."""

from __future__ import annotations

import copy
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot as api
from codex_plugin_scanner.guard.native_policy_snapshot_business_bridge import validate_business_snapshot_content


def binding(action: str = "block") -> dict[str, object]:
    return {"schema": "guard.native-business-policy.v1", "version": 1, "defaultAction": action, "rules": []}


def build(home: Path, business: dict[str, object]) -> dict[str, object]:
    return api.build_policy_snapshot_v3(
        config={},
        guard_home=home,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        verifier_key=b"k" * 32,
        generation=1,
        issued_at_ms=100,
        expires_at_ms=1000,
        business_policy=business,
    )


def test_business_content_requires_native_consumer_without_python_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    with pytest.raises(api.NativePolicySnapshotError, match="native_business_policy_consumer_unavailable"):
        build(tmp_path, binding())
    legacy = api.build_policy_snapshot_v3(
        config={},
        guard_home=tmp_path,
        runtime_identity="a" * 64,
        rule_digest="b" * 64,
        verifier_key=b"k" * 32,
        generation=1,
        issued_at_ms=100,
        expires_at_ms=1000,
    )
    assert "business_policy" not in legacy


def test_older_native_consumer_refuses_before_constructor_receives_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard import native_runtime

    old = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "unused"),
        capabilities=SimpleNamespace(features=("native-policy-snapshot-build-v1",)),
    )
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: old)

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("An older consumer must not receive a constructor request or verifier key")

    monkeypatch.setattr(native_runtime, "_run_native_process", forbidden)
    with pytest.raises(api.NativePolicySnapshotError, match="native_business_policy_consumer_unavailable"):
        build(tmp_path, binding())


def test_native_business_builder_preserves_binding_and_cache_authentication(
    tmp_path: Path,
    native_hook_force: Path,
) -> None:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    snapshot = build(home, binding())
    assert snapshot["business_policy"] == binding()
    api._write_v3_snapshot_cache(home, snapshot)
    cached = api._read_v3_snapshot_cache(home, verifier_key=b"k" * 32)
    assert cached is not None and cached[0] == snapshot
    with pytest.raises(api.NativePolicySnapshotError, match="integrity_invalid"):
        api._read_v3_snapshot_cache(home, verifier_key=b"z" * 32)


def test_native_business_content_success_does_not_authenticate_forged_mac(
    tmp_path: Path,
    native_hook_force: Path,
) -> None:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    snapshot = build(home, binding())
    snapshot["integrity"]["mac"] = "0" * 64
    validate_business_snapshot_content(snapshot)
    api._write_v3_snapshot_cache(home, snapshot)
    with pytest.raises(api.NativePolicySnapshotError, match="integrity_invalid"):
        api._read_v3_snapshot_cache(home, verifier_key=b"k" * 32)


def test_changed_business_content_and_each_claimed_digest_are_refused(
    tmp_path: Path,
    native_hook_force: Path,
) -> None:
    original = build(tmp_path, binding())
    for field in ("config_digest", "policy_digest", "business_policy"):
        tampered = copy.deepcopy(original)
        tampered[field] = binding("allow") if field == "business_policy" else "f" * 64
        with pytest.raises(api.NativePolicySnapshotError, match="digest_mismatch"):
            validate_business_snapshot_content(tampered)
    for value in (None, {**binding(), "private_canary": "not-reflected"}):
        tampered = {**original, "business_policy": value}
        with pytest.raises(api.NativePolicySnapshotError, match="content_invalid"):
            validate_business_snapshot_content(tampered)


def test_business_binding_rotates_generation_and_reuses_exact_cache(
    tmp_path: Path,
    native_hook_force: Path,
) -> None:
    home = tmp_path / "guard"
    home.mkdir(mode=0o700)
    inputs = dict(
        config={}, guard_home=home, runtime_identity="a" * 64, rule_digest="b" * 64, policy_integrity_key=b"m" * 32
    )
    first = api.native_policy_snapshot_v3(**inputs, business_policy=binding())
    again = api.native_policy_snapshot_v3(**inputs, business_policy=binding())
    changed = api.native_policy_snapshot_v3(**inputs, business_policy=binding("allow"))
    assert first == again
    assert changed["generation"] == first["generation"] + 1
    assert changed["policy_digest"] != first["policy_digest"]
    renewed = api.native_policy_snapshot_v3(
        **inputs,
        business_policy=binding("allow"),
        renew_after_generation=changed["generation"],
    )
    assert renewed["generation"] > changed["generation"]
    assert renewed["policy_digest"] == changed["policy_digest"]


def test_business_transport_receives_real_native_ack_without_provider_dispatch(
    tmp_path: Path,
    native_hook_force: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from codex_plugin_scanner.guard.native_command_control_binding import read_native_command_control_binding
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport import _publish_snapshot_v3
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents, native_resident_client_request
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status
    from codex_plugin_scanner.guard.store import GuardStore

    # Keep command authority and snapshot signing on the same synthetic master;
    # this test must never ask a real credential store for integrity material.
    monkeypatch.setattr(GuardStore, "_policy_integrity_secret_material", lambda self, **kwargs: (b"m" * 32, "fixture"))
    home = tmp_path / "guard"
    status = native_runtime_status()
    assert status.compatible and status.identity is not None and status.capabilities is not None
    controls, _ = read_native_command_control_binding(GuardStore(home))
    publisher = SimpleNamespace(
        guard_home=home,
        _snapshot=None,
        _wall_clock=time.time,
        _monotonic_clock=time.monotonic,
    )
    try:
        snapshot, resident_generation = _publish_snapshot_v3(
            publisher=publisher,
            identity=status.identity,
            capabilities=status.capabilities,
            config={},
            command_extensions=controls,
            master_key=b"m" * 32,
            client=native_resident_client_request,
            renew_after_generation=None,
            business_policy=binding(),
        )
        assert snapshot["business_policy"] == binding()
        assert resident_generation >= snapshot["generation"]
        cached = api._read_v3_snapshot_cache(home, verifier_key=api.derive_native_policy_verifier_key(b"m" * 32))
        assert cached is not None and cached[0] == snapshot
    finally:
        assert close_native_residents(home, deadline_monotonic=time.monotonic() + 5.0)

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime


def _runtime(tmp_path: Path, payload: bytes = b"native-runtime") -> native_runtime.NativeRuntimeIdentity:
    runtime = tmp_path / ("hol-guard-runtime.exe" if os.name == "nt" else "hol-guard-runtime")
    runtime.write_bytes(payload)
    if os.name != "nt":
        runtime.chmod(0o700)
    metadata = runtime.stat()
    return native_runtime.NativeRuntimeIdentity(
        path=runtime.resolve(),
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        sha256=hashlib.sha256(payload).hexdigest(),
    )


def _manifest(identity: native_runtime.NativeRuntimeIdentity, **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": "3.0.0a1",
        "target": "x86_64-unknown-linux-musl",
        "platform_tag": "manylinux_2_17_x86_64",
        "source_sha": "a" * 40,
        "rule_digest": "b" * 64,
        "runtime_sha256": identity.sha256,
        "runtime_size": identity.size,
    }
    payload.update(overrides)
    return payload


def _write_manifest(identity: native_runtime.NativeRuntimeIdentity, payload: dict[str, object]) -> None:
    path = identity.path.with_name("runtime-manifest.json")
    path.write_text(json.dumps(payload), encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)


def test_manifest_binds_exact_runtime_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _runtime(tmp_path)
    _write_manifest(identity, _manifest(identity))
    monkeypatch.setattr(native_runtime, "_python_package_version", lambda: "3.0.0a1")

    manifest, reason = native_runtime._manifest_for_bundled_identity(identity)

    assert reason is None
    assert manifest is not None
    assert manifest.runtime_sha256 == identity.sha256
    assert manifest.runtime_size == identity.size


def test_manifest_rejects_runtime_digest_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _runtime(tmp_path)
    _write_manifest(identity, _manifest(identity, runtime_sha256="c" * 64))
    monkeypatch.setattr(native_runtime, "_python_package_version", lambda: "3.0.0a1")

    manifest, reason = native_runtime._manifest_for_bundled_identity(identity)

    assert manifest is None
    assert reason == "native_manifest_runtime_mismatch"


def test_manifest_rejects_package_version_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _runtime(tmp_path)
    _write_manifest(identity, _manifest(identity, package_version="3.0.0a2"))
    monkeypatch.setattr(native_runtime, "_python_package_version", lambda: "3.0.0a1")

    manifest, reason = native_runtime._manifest_for_bundled_identity(identity)

    assert manifest is None
    assert reason == "native_manifest_version_mismatch"


def test_auto_mode_does_not_consider_separate_runtime_distribution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bundled = tmp_path / "_native" / ("hol-guard-runtime.exe" if os.name == "nt" else "hol-guard-runtime")
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.delenv("HOL_GUARD_NATIVE_BINARY", raising=False)
    monkeypatch.setattr(native_runtime, "_bundled_runtime_candidate", lambda: bundled)

    def unexpected_distribution(_name: str) -> object:
        raise AssertionError("automatic mode must not inspect a separately installed runtime distribution")

    monkeypatch.setattr(native_runtime.importlib.metadata, "distribution", unexpected_distribution)

    assert native_runtime._runtime_candidates() == (bundled,)


def test_status_rejects_manifest_build_sha_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _runtime(tmp_path)
    _write_manifest(identity, _manifest(identity))
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setattr(native_runtime, "_bundled_runtime_candidate", lambda: identity.path)
    monkeypatch.setattr(native_runtime, "_runtime_candidates", lambda: (identity.path,))
    monkeypatch.setattr(native_runtime, "_validate_binary", lambda _path: identity)
    monkeypatch.setattr(native_runtime, "_python_package_version", lambda: "3.0.0a1")
    monkeypatch.setattr(
        native_runtime,
        "_capabilities_for_identity",
        lambda *_args, **_kwargs: native_runtime.NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version="3.0.0a1",
            rule_digest="b" * 64,
            build_sha="d" * 40,
            target="x86_64-linux",
            features=(),
        ),
    )

    status = native_runtime.native_runtime_status()

    assert status.available is True
    assert status.compatible is False
    assert status.reason == "native_manifest_build_mismatch"


def test_status_accepts_fully_bound_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    identity = _runtime(tmp_path)
    _write_manifest(identity, _manifest(identity))
    monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
    monkeypatch.setattr(native_runtime, "_bundled_runtime_candidate", lambda: identity.path)
    monkeypatch.setattr(native_runtime, "_runtime_candidates", lambda: (identity.path,))
    monkeypatch.setattr(native_runtime, "_validate_binary", lambda _path: identity)
    monkeypatch.setattr(native_runtime, "_python_package_version", lambda: "3.0.0a1")
    monkeypatch.setattr(
        native_runtime,
        "_capabilities_for_identity",
        lambda *_args, **_kwargs: native_runtime.NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version="3.0.0a1",
            rule_digest="b" * 64,
            build_sha="a" * 40,
            target="x86_64-linux",
            features=("post-tool-inline-v1",),
        ),
    )

    status = native_runtime.native_runtime_status()

    assert status.available is True
    assert status.compatible is True
    assert status.reason == "native_ready"


def test_manifest_decoder_rejects_boolean_runtime_size() -> None:
    payload = {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": "3.0.0a1",
        "target": "x86_64-unknown-linux-musl",
        "platform_tag": "manylinux_2_17_x86_64",
        "source_sha": "a" * 40,
        "rule_digest": "b" * 64,
        "runtime_sha256": "c" * 64,
        "runtime_size": True,
    }
    assert native_runtime._decode_runtime_manifest(payload) is None


def test_manifest_rejects_symlink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    if os.name == "nt":
        pytest.skip("symlink permissions vary on Windows runners")
    identity = _runtime(tmp_path)
    real_manifest = tmp_path / "real-manifest.json"
    real_manifest.write_text(json.dumps(_manifest(identity)), encoding="utf-8")
    identity.path.with_name("runtime-manifest.json").symlink_to(real_manifest)
    monkeypatch.setattr(native_runtime, "_python_package_version", lambda: "3.0.0a1")

    manifest, reason = native_runtime._manifest_for_bundled_identity(identity)

    assert manifest is None
    assert reason == "native_manifest_invalid"


def _capabilities_payload() -> str:
    return json.dumps(
        {
            "protocol_version": 1,
            "runtime_version": "3.0.0a1",
            "rule_digest": "b" * 64,
            "build_sha": "a" * 40,
            "target": "x86_64-unknown-linux-musl",
            "features": ["hook-envelope-v2"],
        }
    )


def test_capability_probe_records_retry_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed probe is remembered briefly: a second call inside the retry
    window must not spawn the binary again."""
    identity = _runtime(tmp_path)
    calls: list[str] = []

    def _fake_run(*args: object, **kwargs: object) -> None:
        calls.append("probe")
        return None

    monkeypatch.setattr(native_runtime, "_run_native_process", _fake_run)
    native_runtime._clear_capabilities_probe_state()

    key = (str(identity.path), identity.size, identity.mtime_ns, identity.sha256)
    assert native_runtime._capabilities_for_identity(*key) is None
    assert key in native_runtime._capabilities_retry_after
    # Inside the retry window the cached failure short-circuits.
    assert native_runtime._capabilities_for_identity(*key) is None
    assert calls == ["probe"]


def test_capability_probe_respects_caller_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exhausted caller deadline prevents any subprocess spawn."""
    identity = _runtime(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(
        native_runtime,
        "_run_native_process",
        lambda *args, **kwargs: calls.append("probe") or "",
    )
    native_runtime._clear_capabilities_probe_state()

    result = native_runtime._capabilities_for_identity(
        str(identity.path),
        identity.size,
        identity.mtime_ns,
        identity.sha256,
        deadline_monotonic=time.monotonic() - 1.0,
    )
    assert result is None
    assert calls == []


def test_capability_probe_rejects_malformed_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _runtime(tmp_path)
    monkeypatch.setattr(
        native_runtime,
        "_run_native_process",
        lambda *args, **kwargs: "not-json",
    )
    native_runtime._clear_capabilities_probe_state()

    assert (
        native_runtime._capabilities_for_identity(
            str(identity.path), identity.size, identity.mtime_ns, identity.sha256
        )
        is None
    )


def test_capability_probe_evicts_oldest_when_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _runtime(tmp_path)
    monkeypatch.setattr(
        native_runtime,
        "_run_native_process",
        lambda *args, **kwargs: _capabilities_payload(),
    )
    native_runtime._clear_capabilities_probe_state()
    for index in range(native_runtime._CAPABILITIES_CACHE_MAX):
        native_runtime._capabilities_cache[(f"old-{index}", 0, 0, "x")] = (
            native_runtime.NativeRuntimeCapabilities(
                protocol_version=1,
                runtime_version="0",
                rule_digest="b" * 64,
                build_sha="a" * 40,
                target="x",
                features=(),
            )
        )

    result = native_runtime._capabilities_for_identity(
        str(identity.path), identity.size, identity.mtime_ns, identity.sha256
    )

    assert result is not None
    assert len(native_runtime._capabilities_cache) <= native_runtime._CAPABILITIES_CACHE_MAX


def test_status_breaks_when_deadline_already_spent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The candidate loop must not start a probe once the budget is spent."""
    identity = _runtime(tmp_path)
    monkeypatch.setenv(native_runtime._NATIVE_BINARY_ENV, str(identity.path))
    monkeypatch.setenv("HOL_GUARD_NATIVE", "force")
    calls: list[str] = []
    monkeypatch.setattr(
        native_runtime,
        "_run_native_process",
        lambda *args, **kwargs: calls.append("probe") or "",
    )
    native_runtime._clear_capabilities_probe_state()

    status = native_runtime.native_runtime_status(
        deadline_monotonic=time.monotonic() - 1.0
    )

    assert status.available is False
    assert calls == []


def test_clear_capabilities_probe_state_resets_both_maps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(native_runtime, "_run_native_process", lambda *a, **k: None)
    key = ("binary", 1, 2, "x")
    native_runtime._capabilities_retry_after[key] = time.monotonic()
    native_runtime._capabilities_cache[key] = native_runtime.NativeRuntimeCapabilities(
        protocol_version=1,
        runtime_version="0",
        rule_digest="b" * 64,
        build_sha="a" * 40,
        target="x",
        features=(),
    )

    native_runtime._clear_capabilities_probe_state()

    assert native_runtime._capabilities_cache == {}
    assert native_runtime._capabilities_retry_after == {}

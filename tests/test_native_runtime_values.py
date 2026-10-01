from __future__ import annotations

import importlib.metadata
from pathlib import Path

from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.native_runtime_values import (
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
    _decode_capabilities,
    _identity_key,
    _python_package_version,
)


def _manifest_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": native_runtime._NATIVE_MANIFEST_SCHEMA,
        "protocol_version": native_runtime._NATIVE_PROTOCOL_VERSION,
        "package_version": "1.2.3",
        "target": "x86_64-unknown-linux-gnu",
        "platform_tag": "manylinux_2_28_x86_64",
        "source_sha": "a" * 40,
        "rule_digest": "b" * 64,
        "runtime_sha256": "c" * 64,
        "runtime_size": 12,
    }
    payload.update(overrides)
    return payload


def test_runtime_manifest_decoder_accepts_only_a_matching_payload() -> None:
    decoded = native_runtime._decode_runtime_manifest(_manifest_payload())

    assert decoded is not None
    assert decoded.schema == native_runtime._NATIVE_MANIFEST_SCHEMA
    assert decoded.runtime_size == 12
    assert native_runtime._decode_runtime_manifest(["not-a-manifest"]) is None
    assert native_runtime._decode_runtime_manifest(_manifest_payload(source_sha="g" * 40)) is None
    assert native_runtime._decode_runtime_manifest(_manifest_payload(source_sha="A" * 40)) is None
    assert native_runtime._decode_runtime_manifest(_manifest_payload(runtime_size=True)) is None


def test_capability_decoder_rejects_a_non_object_and_a_partial_object() -> None:
    assert _decode_capabilities("nope") is None
    assert _decode_capabilities({"protocol_version": 1}) is None


def test_identity_key_uses_the_runtime_digest_or_zeros() -> None:
    missing = NativeRuntimeStatus(mode="off", available=False, compatible=False, reason="missing")
    identity = NativeRuntimeIdentity(path=Path("runtime"), size=4, mtime_ns=1, sha256="d" * 64)
    present = NativeRuntimeStatus(
        mode="auto",
        available=True,
        compatible=True,
        reason="ok",
        identity=identity,
    )

    assert _identity_key(missing) == "0" * 64
    assert _identity_key(present) == "d" * 64


def test_package_version_is_absent_when_the_distribution_is_missing(monkeypatch) -> None:
    def missing(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_runtime_values.importlib.metadata.version",
        missing,
    )

    assert _python_package_version() is None

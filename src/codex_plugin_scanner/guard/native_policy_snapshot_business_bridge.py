"""Thin offline native content bridge; no business decision or admission."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Mapping
from typing import cast

from .native_policy_snapshot_codec import (
    _canonical_json_bytes_v3,
    _strict_json_loads_v3,
    _valid_digest_v3,
)
from .native_policy_snapshot_constants import POLICY_SNAPSHOT_MAX_BYTES, NativePolicySnapshotError

_INSPECTION_FIELDS = frozenset(
    {
        "schema",
        "version",
        "authenticity",
        "currentness",
        "snapshot_digest",
        "config_digest",
        "policy_digest",
        "business_policy_present",
    }
)

_VALIDATED: dict[bytes, dict[str, object]] = {}


def _deadline_timeout_seconds(deadline_monotonic: float | None) -> float:
    return 5.0 if deadline_monotonic is None else max(0.0, deadline_monotonic - time.monotonic())


def capture_business_binding(value: Mapping[str, object]) -> dict[str, object]:
    """Own an immutable-in-flight wire copy; Rust still validates semantics."""

    encoded = _canonical_json_bytes_v3(value)
    if len(encoded) > POLICY_SNAPSHOT_MAX_BYTES:
        raise NativePolicySnapshotError("native_policy_snapshot_too_large")
    result = _strict_json_loads_v3(encoded)
    if not isinstance(result, dict):
        raise NativePolicySnapshotError("native_business_policy_content_invalid")
    return cast(dict[str, object], result)


def _native_content_operation(
    command: str,
    value: Mapping[str, object],
    *,
    timeout_seconds: float = 5.0,
) -> dict[str, object]:
    from .native_runtime import _run_native_process, native_runtime_status

    if command not in {"policy-snapshot-build", "policy-snapshot-inspect"}:
        raise NativePolicySnapshotError("native_business_policy_consumer_unavailable")
    status = native_runtime_status()
    required = {"native-policy-snapshot-build-v1", "native-policy-snapshot-inspect-v1"}
    if (
        not status.available
        or not status.compatible
        or status.identity is None
        or status.capabilities is None
        or not required <= set(status.capabilities.features)
    ):
        raise NativePolicySnapshotError("native_business_policy_consumer_unavailable")
    encoded = _canonical_json_bytes_v3(value)
    if len(encoded) > POLICY_SNAPSHOT_MAX_BYTES:
        raise NativePolicySnapshotError("native_policy_snapshot_too_large")
    output = _run_native_process(
        status.identity.path,
        (command, "--stdin"),
        input_text=encoded.decode("utf-8"),
        timeout_seconds=timeout_seconds,
    )
    if output is None or len(output.encode("utf-8")) > POLICY_SNAPSHOT_MAX_BYTES:
        raise NativePolicySnapshotError("native_business_policy_content_invalid")
    result = _strict_json_loads_v3(output.encode("utf-8"))
    if not isinstance(result, dict):
        raise NativePolicySnapshotError("native_business_policy_content_invalid")
    return cast(dict[str, object], result)


def _inspect_cached(value: Mapping[str, object], timeout: float) -> dict[str, object]:
    key = hashlib.sha256(_canonical_json_bytes_v3(value)).digest()
    hit = _VALIDATED.get(key)
    if hit is None:
        hit = _native_content_operation("policy-snapshot-inspect", value, timeout_seconds=timeout)
        if len(_VALIDATED) > 64:
            _VALIDATED.clear()
        _VALIDATED[key] = hit
    return hit


def validate_business_snapshot_content(
    snapshot: Mapping[str, object],
    *,
    allow_empty_mac: bool = False,
    verify_digests: bool = True,
    deadline_monotonic: float | None = None,
) -> None:
    """Validate content with Rust; does not authenticate MAC or currentness."""

    value = dict(snapshot)
    if allow_empty_mac:
        integrity = value.get("integrity")
        if isinstance(integrity, Mapping) and integrity.get("mac") == "":
            value["integrity"] = {**integrity, "mac": "0" * 64}
    result = _inspect_cached(value, _deadline_timeout_seconds(deadline_monotonic))
    if (
        set(result) != _INSPECTION_FIELDS
        or result.get("schema") != "guard-native-policy-content-inspection.v1"
        or type(result.get("version")) is not int
        or result.get("version") != 1
        or result.get("authenticity") != "not_checked"
        or result.get("currentness") != "not_checked"
        or result.get("business_policy_present") is not True
        or any(
            not _valid_digest_v3(result.get(field)) for field in ("snapshot_digest", "config_digest", "policy_digest")
        )
        or result.get("snapshot_digest") != hashlib.sha256(_canonical_json_bytes_v3(value)).hexdigest()
    ):
        raise NativePolicySnapshotError("native_business_policy_content_invalid")
    if verify_digests and any(result[field] != snapshot.get(field) for field in ("config_digest", "policy_digest")):
        raise NativePolicySnapshotError("native_policy_snapshot_digest_mismatch")


def build_native_business_snapshot(
    request: Mapping[str, object],
    *,
    deadline_monotonic: float | None = None,
) -> dict[str, object]:
    """Forward a typed constructor request, then verify returned binding/content."""

    result = _native_content_operation(
        "policy-snapshot-build",
        request,
        timeout_seconds=_deadline_timeout_seconds(deadline_monotonic),
    )
    for field in (
        "generation",
        "runtime_identity",
        "rule_digest",
        "mode",
        "scope_contract",
        "effective_policy",
        "issued_at_ms",
        "expires_at_ms",
        "business_policy",
    ):
        if result.get(field) != request.get(field):
            raise NativePolicySnapshotError("native_business_policy_content_invalid")
    if result.get("command_extensions") != request.get("command_extensions"):
        raise NativePolicySnapshotError("native_business_policy_content_invalid")
    validate_business_snapshot_content(result, deadline_monotonic=deadline_monotonic)
    return cast(dict[str, object], result)

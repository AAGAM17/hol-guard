from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin
from codex_plugin_scanner.guard.mdm.contracts import MDM_POLICY_SCHEMA_VERSION, ManagedPolicyState
from codex_plugin_scanner.guard.mdm.policy import parse_managed_policy
from codex_plugin_scanner.guard.runtime import structured_output_mediation
from codex_plugin_scanner.guard.runtime.structured_output_mediation import (
    STRUCTURED_OUTPUT_SETTING_PATH,
    StructuredOutputBinding,
    canonical_structured_content_bytes,
    mediate_native_post_tool_content,
    resolve_managed_structured_output_binding,
    resolve_managed_structured_output_resolution,
)


def _policy_value() -> dict[str, object]:
    return {
        "version": "hol-guard-structured-output-policy.v1",
        "enabled": True,
        "harnesses": ["pi", "omp"],
        "event": "PostToolUse",
        "destinationRole": "model_visible_tool_result",
        "schema": {
            "fields": [
                {
                    "path": ["employee", "email"],
                    "role": "protected_personal",
                    "valueType": "string",
                    "category": "email_address",
                },
                {"path": ["employee", "id"], "role": "ordinary", "valueType": "integer"},
                {"path": ["note"], "role": "ordinary", "valueType": "string"},
            ]
        },
        "onMatch": "withhold",
        "onUnsupported": "withhold",
    }


@dataclass
class _PolicyFixture:
    settings: dict[str, object]
    content_hash: str


@dataclass
class _ConfigFixture:
    managed_policy_status: str
    managed_policy_hash: str | None
    managed_locked_settings: tuple[str, ...]
    managed_policy: _PolicyFixture | None


def _config(*, status: str = "active", locked: tuple[str, ...] = (STRUCTURED_OUTPUT_SETTING_PATH,)) -> object:
    managed_policy = (
        _PolicyFixture(
            settings={"data_control": {"structured_output": _policy_value()}},
            content_hash="a" * 64,
        )
        if status != "absent"
        else None
    )
    return _ConfigFixture(
        managed_policy_status=status,
        managed_policy_hash=None if status == "absent" else "a" * 64,
        managed_locked_settings=locked,
        managed_policy=managed_policy,
    )


def _real_observe_managed_config(tmp_path: Path) -> object:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text('mode = "observe"\ndefault_action = "allow"\n', encoding="utf-8")
    managed_payload = {
        "schemaVersion": MDM_POLICY_SCHEMA_VERSION,
        "settings": {"data_control": {"structured_output": _policy_value()}},
        "lockedSettings": [STRUCTURED_OUTPUT_SETTING_PATH],
        "update": {"owner": "mdm"},
    }
    managed_policy = parse_managed_policy(managed_payload)
    config = load_guard_config(
        guard_home,
        managed_policy_state=ManagedPolicyState("active", "machine-policy-fixture", policy=managed_policy),
    )
    assert config.mode == "observe"
    assert config.managed_policy_status == "active"
    assert config.managed_locked_settings == (STRUCTURED_OUTPUT_SETTING_PATH,)
    assert config.install_owner == "mdm"
    return config


def _binding(harness: str = "pi") -> StructuredOutputBinding:
    binding = resolve_managed_structured_output_binding(_config(), harness=harness)
    assert binding is not None
    return binding


def _native_result(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "policy_action": "allow",
        "observe_mode": False,
    }
    result.update(overrides)
    return result


def _receipt(**overrides: object) -> dict[str, object]:
    receipt: dict[str, object] = {"decision_id": "b" * 64, "decision": "allow"}
    receipt.update(overrides)
    return receipt


def test_managed_policy_requires_active_locked_reserved_setting() -> None:
    assert resolve_managed_structured_output_binding(_config(status="absent"), harness="pi") is None
    assert resolve_managed_structured_output_binding(_config(locked=()), harness="pi") is None
    assert resolve_managed_structured_output_binding(_config(), harness="codex") is None

    invalid = _config()
    invalid.managed_policy.settings["data_control"]["structured_output"]["onMatch"] = "allow"
    assert resolve_managed_structured_output_binding(invalid, harness="pi") is None


@pytest.mark.parametrize("status", ["invalid", "inaccessible", "tampered", "revoked"])
def test_configured_authority_failure_is_required_and_fail_closed(status: str) -> None:
    resolution = resolve_managed_structured_output_resolution(_config(status=status), harness="pi")
    assert resolution.binding is None
    assert resolution.required is True
    assert resolution.reason_code in {
        "structured_managed_authority_unavailable",
        "structured_managed_authority_revoked",
    }


def test_active_locked_malformed_or_missing_setting_is_required() -> None:
    malformed = _config()
    malformed.managed_policy.settings["data_control"]["structured_output"]["onMatch"] = "allow"
    malformed_resolution = resolve_managed_structured_output_resolution(malformed, harness="pi")
    assert malformed_resolution.binding is None
    assert malformed_resolution.required is True
    assert malformed_resolution.reason_code == "structured_managed_policy_invalid"

    missing = _config()
    missing.managed_policy.settings = {"mode": "enforce"}
    missing_resolution = resolve_managed_structured_output_resolution(missing, harness="pi")
    assert missing_resolution.binding is None
    assert missing_resolution.required is True
    assert missing_resolution.reason_code == "structured_managed_policy_invalid"

    missing_authority = _config()
    missing_authority.managed_policy = None
    missing_authority_resolution = resolve_managed_structured_output_resolution(missing_authority, harness="pi")
    assert missing_authority_resolution.binding is None
    assert missing_authority_resolution.required is True
    assert missing_authority_resolution.reason_code == "structured_managed_policy_missing"

    unlocked = _config(locked=())
    unlocked_resolution = resolve_managed_structured_output_resolution(unlocked, harness="pi")
    assert unlocked_resolution.binding is None
    assert unlocked_resolution.required is True
    assert unlocked_resolution.reason_code == "structured_managed_policy_invalid"

    explicitly_empty = _config(locked=())
    explicitly_empty.managed_policy.settings["data_control"]["structured_output"] = None
    explicitly_empty_resolution = resolve_managed_structured_output_resolution(explicitly_empty, harness="pi")
    assert explicitly_empty_resolution.required is True
    assert explicitly_empty_resolution.reason_code == "structured_managed_policy_invalid"

    changed_hash = _config()
    changed_hash.managed_policy.content_hash = "b" * 64
    changed_hash_resolution = resolve_managed_structured_output_resolution(changed_hash, harness="pi")
    assert changed_hash_resolution.required is True
    assert changed_hash_resolution.reason_code == "structured_managed_policy_invalid"


def test_absent_unconfigured_authority_stays_off() -> None:
    resolution = resolve_managed_structured_output_resolution(_config(status="absent", locked=()), harness="pi")
    assert resolution == type(resolution)(None, False)


def test_required_authority_failure_withholds_after_native_receipt() -> None:
    result = mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result=_native_result(),
        validated_receipt=_receipt(),
        structured_output_json=None,
        binding=None,
        required_reason_code="structured_managed_authority_unavailable",
    )
    assert result is not None
    assert result.action == "withhold"
    assert result.reason_code == "structured_managed_authority_unavailable"


@pytest.mark.parametrize("status", ["invalid", "inaccessible", "tampered"])
def test_load_config_fail_closed_floor_keeps_structured_authority_required(
    tmp_path: Path,
    status: str,
) -> None:
    config = load_guard_config(
        tmp_path / "guard-home",
        managed_policy_state=ManagedPolicyState(status, "machine-policy-fixture"),
    )
    assert config.managed_policy_status == status
    assert config.mode == "enforce"
    assert config.default_action == "block"
    assert config.managed_policy is not None
    resolution = resolve_managed_structured_output_resolution(config, harness="pi")
    assert resolution.required is True
    assert resolution.reason_code == "structured_managed_authority_unavailable"


@pytest.mark.parametrize(
    "candidate",
    (
        '{"employee":{"email":"","id":7},"note":"x"}',
        '{"note":"x","employee": {"email":"","id":7}}',
        '{"note":"x","employee":{"email":"\\u0061","id":7}}',
        '{"note":"x","employee":{"email":[],"id":7}}',
        '{"note":"x","employee":{"email":"","id":9007199254740992}}',
    ),
)
def test_canonical_structured_bytes_require_fixed_object_encoding(candidate: str) -> None:
    canonical = canonical_structured_content_bytes(candidate)
    if candidate == '{"employee":{"email":"","id":7},"note":"x"}':
        assert canonical == candidate.encode()
    else:
        assert canonical is None


def test_canonical_structured_bytes_honors_absolute_deadline() -> None:
    assert (
        canonical_structured_content_bytes(
            '{"employee":{"email":"","id":7},"note":"x"}',
            deadline_monotonic=time.monotonic() - 1,
        )
        is None
    )


def test_canonical_structured_bytes_withholds_recursion_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_recursion(*_args: object, **_kwargs: object) -> bool:
        raise RecursionError("fixture recursion")

    monkeypatch.setattr(structured_output_mediation, "_has_safe_numbers", raise_recursion)
    assert canonical_structured_content_bytes('{"value":1}') is None


def test_clean_forward_requires_complete_recheck_and_exposes_only_ephemeral_digest() -> None:
    candidate = '{"employee":{"email":"","id":7},"note":"π"}'
    binding = _binding()
    refreshed: list[StructuredOutputBinding | None] = [binding]
    result = mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result=_native_result(),
        validated_receipt=_receipt(),
        structured_output_json=candidate,
        binding=binding,
        recheck_binding=lambda: refreshed[0],
    )

    assert result is not None
    assert result.action == "forward"
    assert result.reason_code == "structured_clean_forward"
    assert result.native_decision_id == "b" * 64
    assert result.content_sha256 == hashlib.sha256(candidate.encode()).hexdigest()
    assert "email" not in str(result.to_harness_json())
    assert "π" not in str(result.to_harness_json())

    refreshed[0] = None
    changed = mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result=_native_result(),
        validated_receipt=_receipt(),
        structured_output_json=candidate,
        binding=binding,
        recheck_binding=lambda: refreshed[0],
    )
    assert changed is not None
    assert changed.action == "withhold"
    assert changed.reason_code == "structured_binding_changed"
    assert changed.content_sha256 is None


@pytest.mark.parametrize("error_type", [ValueError, OSError])
def test_binding_recheck_failure_withholds_without_logging_callback_details(
    error_type: type[Exception],
    caplog: pytest.LogCaptureFixture,
) -> None:
    def fail_recheck() -> StructuredOutputBinding | None:
        raise error_type("untrusted callback detail")

    native_result = _native_result()
    result = mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result=native_result,
        validated_receipt=_receipt(),
        structured_output_json='{"employee":{"email":"","id":7},"note":"x"}',
        binding=_binding(),
        recheck_binding=fail_recheck,
    )
    assert result is not None
    assert result.action == "withhold"
    assert result.content_sha256 is None
    assert native_result == _native_result()
    assert "untrusted callback detail" not in caplog.text
    assert "untrusted callback detail" not in str(result.to_harness_json())
    if error_type is OSError:
        assert result.reason_code == "structured_binding_recheck_failed"
        assert "OSError" in caplog.text
    else:
        assert result.reason_code == "structured_binding_changed"
        assert not caplog.records


@pytest.mark.parametrize("property_name", ["role", "valueType", "category"])
def test_policy_rejects_untyped_field_values(property_name: str) -> None:
    policy = _policy_value()
    field: dict[str, object] = {
        "path": ["note"],
        "role": "protected_personal",
        "valueType": "string",
        "category": "person_name",
    }
    field[property_name] = ["unexpected"]
    policy["schema"] = {"fields": [field]}
    with pytest.raises(ValueError, match="is invalid"):
        structured_output_mediation.parse_structured_output_policy(policy)


def test_match_unsupported_deadline_missing_receipt_and_native_deny_withhold() -> None:
    binding = _binding("omp")
    cases = (
        ("{'employee': {'email': 'person@example.test', 'id': 7}, 'note': 'x'}", "structured_content_unproved"),
        ('{"employee":{"email":"person@example.test","id":7},"note":"x"}', "structured_declared_schema_scan"),
        ('{"employee":{"email":"","id":7},"note":"x"}', "structured_receipt_missing"),
    )
    for candidate, expected_reason in cases:
        result = mediate_native_post_tool_content(
            harness="omp",
            event_name="PostToolUse",
            native_result=_native_result(),
            validated_receipt=None if expected_reason == "structured_receipt_missing" else _receipt(),
            structured_output_json=candidate,
            binding=binding,
            recheck_binding=lambda: binding,
        )
        assert result is not None
        assert result.action == "withhold"
        assert result.reason_code == expected_reason
        assert result.content_sha256 is None

    denied = mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result=_native_result(decision="deny", model_output_action="block"),
        validated_receipt=_receipt(decision="deny"),
        structured_output_json='{"employee":{"email":"","id":7},"note":"x"}',
        binding=binding,
        recheck_binding=lambda: binding,
    )
    assert denied is None

    expired = mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result=_native_result(),
        validated_receipt=_receipt(),
        structured_output_json='{"employee":{"email":"","id":7},"note":"x"}',
        binding=_binding("pi"),
        recheck_binding=lambda: _binding("pi"),
        deadline_monotonic=-1,
    )
    assert expired is not None
    assert expired.reason_code == "structured_review_deadline_exceeded"


@dataclass
class _NativeRouteFixture(HookWorkerNativeMixin):
    config: object
    raw_result: object | None = None
    raw_receipt: object | None = None
    recorded_receipt: object | None = None

    def _load_config(self, _guard_home: Path, _workspace: Path | None) -> object:
        return self.config

    def _review_raw_hook_native(self, **_kwargs: object) -> dict[str, object]:
        result = _native_result()
        receipt = _receipt()
        self.raw_result = result
        self.raw_receipt = receipt
        return {
            "event_name": "PostToolUse",
            "harness": "pi",
            "result": result,
            "receipt": receipt,
        }

    def _record_native_decision_receipt(self, receipt: object) -> object:
        self.recorded_receipt = receipt
        return receipt

    def _record_post_tool_activity(self, **_kwargs: object) -> None:
        return None


@dataclass
class _LoadErrorNativeRouteFixture(_NativeRouteFixture):
    def _load_config(self, _guard_home: Path, _workspace: Path | None) -> object:
        raise OSError("machine policy unavailable")


@dataclass
class _UnavailableNativeRouteFixture(_NativeRouteFixture):
    def _review_raw_hook_native(self, **_kwargs: object) -> None:
        return None


@dataclass
class _ObserveNativeRouteFixture(_NativeRouteFixture):
    def _review_raw_hook_native(self, **_kwargs: object) -> dict[str, object]:
        result = _native_result(observe_mode=True)
        receipt = _receipt()
        self.raw_result = result
        self.raw_receipt = receipt
        return {
            "event_name": "PostToolUse",
            "harness": "pi",
            "result": result,
            "receipt": receipt,
        }


def test_native_route_attaches_adapter_field_after_receipt_without_mutating_native_result(tmp_path: Path) -> None:
    fixture = _NativeRouteFixture(_config())
    native = fixture._review_native_edge_with_snapshot(
        payload={
            "hook_event_name": "PostToolUse",
            "structured_output_json": '{"employee":{"email":"","id":7},"note":"x"}',
        },
        harness="pi",
        event_name="PostToolUse",
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=None,
        policy_snapshot={"mode": "enforce"},
        recording_only=False,
    )
    response, native_used = native
    assert native_used is True
    mediation = response["structured_content_mediation"]
    assert isinstance(mediation, dict)
    assert mediation["action"] == "forward"
    assert response["decision"] == "allow"
    assert response["policy_action"] == "allow"


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_native_unavailable_required_structured_route_withholds_model_output(
    tmp_path: Path,
    harness: str,
) -> None:
    class _Metrics:
        def record_route(self, _route: str) -> None:
            return None

    fixture = _UnavailableNativeRouteFixture(_config())
    fixture.metrics = _Metrics()
    fixture.activity_writer = None
    response, native_used = fixture._review_native_edge_with_snapshot(
        payload={"hook_event_name": "PostToolUse"},
        harness=harness,
        event_name="PostToolUse",
        default_harness=harness,
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=None,
        policy_snapshot={"mode": "enforce"},
        recording_only=False,
    )

    assert native_used is False
    assert response["decision"] == "allow"
    mediation = response["structured_content_mediation"]
    assert isinstance(mediation, dict)
    assert mediation == {
        "schema": "guard-structured-content-mediation.v1",
        "action": "withhold",
        "reason_code": "structured_native_edge_unavailable",
    }


def test_native_route_load_error_attaches_fail_closed_mediation(tmp_path: Path) -> None:
    fixture = _LoadErrorNativeRouteFixture(_config())
    response, native_used = fixture._review_native_edge_with_snapshot(
        payload={
            "hook_event_name": "PostToolUse",
            "structured_output_json": '{"employee":{"email":"","id":7},"note":"x"}',
        },
        harness="pi",
        event_name="PostToolUse",
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=None,
        policy_snapshot={"mode": "enforce"},
        recording_only=False,
    )
    assert native_used is True
    mediation = response["structured_content_mediation"]
    assert isinstance(mediation, dict)
    assert mediation["action"] == "withhold"
    assert mediation["reason_code"] == "structured_managed_authority_unavailable"


@pytest.mark.parametrize("variant", ["malformed", "missing", "revoked"])
def test_native_route_does_not_skip_configured_authority_failures(tmp_path: Path, variant: str) -> None:
    config = _config(status="revoked" if variant == "revoked" else "active")
    if variant == "malformed":
        config.managed_policy.settings["data_control"]["structured_output"]["onMatch"] = "allow"
    elif variant == "missing":
        config.managed_policy = None
    fixture = _NativeRouteFixture(config)
    response, native_used = fixture._review_native_edge_with_snapshot(
        payload={
            "hook_event_name": "PostToolUse",
            "structured_output_json": '{"employee":{"email":"","id":7},"note":"x"}',
        },
        harness="pi",
        event_name="PostToolUse",
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=None,
        policy_snapshot={"mode": "enforce"},
        recording_only=False,
    )
    assert native_used is True
    mediation = response["structured_content_mediation"]
    assert isinstance(mediation, dict)
    assert mediation["action"] == "withhold"
    assert mediation["reason_code"] in {
        "structured_managed_policy_invalid",
        "structured_managed_policy_missing",
        "structured_managed_authority_revoked",
    }


@pytest.mark.parametrize(
    ("candidate", "expected_action"),
    (
        ('{"employee":{"email":"","id":7},"note":"x"}', "forward"),
        ('{"employee":{"email":"person@example.test","id":7},"note":"x"}', "withhold"),
    ),
)
def test_recording_only_cannot_bypass_real_managed_structured_policy(
    tmp_path: Path,
    candidate: str,
    expected_action: str,
) -> None:
    config = _real_observe_managed_config(tmp_path)
    fixture = _ObserveNativeRouteFixture(config)
    response, native_used = fixture._review_native_edge_with_snapshot(
        payload={
            "hook_event_name": "PostToolUse",
            "structured_output_json": candidate,
        },
        harness="pi",
        event_name="PostToolUse",
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path,
        deadline=None,
        policy_snapshot={"mode": "observe"},
        recording_only=True,
    )
    assert native_used is True
    assert response["observe_mode"] is True
    assert fixture.raw_result == _native_result(observe_mode=True)
    assert fixture.raw_receipt == _receipt()
    assert fixture.recorded_receipt == _receipt()
    assert response["decision"] == fixture.raw_result["decision"]
    mediation = response["structured_content_mediation"]
    assert isinstance(mediation, dict)
    assert mediation["action"] == expected_action


def test_recording_only_unconfigured_route_keeps_existing_watch_behavior(tmp_path: Path) -> None:
    fixture = _ObserveNativeRouteFixture(_config(status="absent", locked=()))
    response, native_used = fixture._review_native_edge_with_snapshot(
        payload={
            "hook_event_name": "PostToolUse",
            "structured_output_json": '{"employee":{"email":"person@example.test","id":7},"note":"x"}',
        },
        harness="pi",
        event_name="PostToolUse",
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=None,
        policy_snapshot={"mode": "observe"},
        recording_only=True,
    )
    assert native_used is True
    assert response["observe_mode"] is True
    assert "structured_content_mediation" not in response


@pytest.mark.parametrize(
    ("variant", "expected_message"),
    [
        ("root_not_object", "must be an object"),
        ("unknown_top_level", "unknown or missing keys"),
        ("wrong_version", "version is unsupported"),
        ("disabled", "must be enabled"),
        ("empty_harnesses", "non-empty array"),
        ("duplicate_harnesses", "must not contain duplicates"),
        ("unsupported_harness", "harness is unsupported"),
        ("wrong_event", "event is unsupported"),
        ("wrong_destination", "destination role is unsupported"),
        ("permissive_disposition", "must withhold"),
        ("schema_extra", "schema has unknown or missing keys"),
        ("empty_fields", "fields must be non-empty"),
        ("field_extra", "field 0 has unknown or missing keys"),
        ("field_bad_path", "field 0 path is invalid"),
    ],
)
def test_managed_policy_parser_rejects_untrusted_authority_shapes(
    variant: str,
    expected_message: str,
) -> None:
    policy = _policy_value()
    candidate: object = policy
    if variant == "root_not_object":
        candidate = []
    elif variant == "unknown_top_level":
        policy["unexpected"] = True
    elif variant == "wrong_version":
        policy["version"] = "other-policy.v1"
    elif variant == "disabled":
        policy["enabled"] = False
    elif variant == "empty_harnesses":
        policy["harnesses"] = []
    elif variant == "duplicate_harnesses":
        policy["harnesses"] = ["pi", "pi"]
    elif variant == "unsupported_harness":
        policy["harnesses"] = ["codex"]
    elif variant == "wrong_event":
        policy["event"] = "PreToolUse"
    elif variant == "wrong_destination":
        policy["destinationRole"] = "terminal_output"
    elif variant == "permissive_disposition":
        policy["onMatch"] = "allow"
    elif variant == "schema_extra":
        policy["schema"] = {"fields": policy["schema"]["fields"], "extra": True}
    elif variant == "empty_fields":
        policy["schema"] = {"fields": []}
    elif variant == "field_extra":
        field = dict(policy["schema"]["fields"][0])
        field["extra"] = True
        policy["schema"] = {"fields": [field]}
    elif variant == "field_bad_path":
        field = dict(policy["schema"]["fields"][0])
        field["path"] = []
        policy["schema"] = {"fields": [field]}
    else:
        raise AssertionError(variant)

    with pytest.raises(ValueError, match=expected_message):
        structured_output_mediation.parse_structured_output_policy(candidate)


@pytest.mark.parametrize(
    ("variant", "expected_required", "expected_reason"),
    [
        ("unsupported_harness", False, None),
        ("unknown_status", True, "structured_managed_authority_unavailable"),
        ("absent_stale_hash", True, "structured_managed_authority_revoked"),
        ("active_unlocked_without_setting", False, None),
        ("invalid_policy_hash", True, "structured_managed_policy_invalid"),
        ("non_mapping_settings", True, "structured_managed_policy_invalid"),
        ("harness_not_enrolled", False, None),
    ],
)
def test_managed_resolution_keeps_malformed_authority_fail_closed(
    variant: str,
    expected_required: bool,
    expected_reason: str | None,
) -> None:
    config = _config()
    harness = "pi"
    if variant == "unsupported_harness":
        harness = "codex"
    elif variant == "unknown_status":
        config.managed_policy_status = "future-status"
    elif variant == "absent_stale_hash":
        config = _config(status="absent", locked=())
        config.managed_policy_hash = "a" * 64
    elif variant == "active_unlocked_without_setting":
        config = _config(locked=())
        config.managed_policy.settings = {}
    elif variant == "invalid_policy_hash":
        config.managed_policy_hash = "not-a-policy-hash"
    elif variant == "non_mapping_settings":
        config.managed_policy.settings = []
    elif variant == "harness_not_enrolled":
        config.managed_policy.settings["data_control"]["structured_output"]["harnesses"] = ["pi"]
        harness = "omp"
    else:  # pragma: no cover - the parameter table is exhaustive
        raise AssertionError(variant)

    resolution = resolve_managed_structured_output_resolution(config, harness=harness)
    assert resolution.binding is None
    assert resolution.required is expected_required
    assert resolution.reason_code == expected_reason


def test_managed_resolution_rejects_binding_validation_disagreement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        structured_output_mediation,
        "resolve_managed_structured_output_binding",
        lambda *_args, **_kwargs: None,
    )
    resolution = resolve_managed_structured_output_resolution(_config(), harness="pi")
    assert resolution.binding is None
    assert resolution.required is True
    assert resolution.reason_code == "structured_managed_policy_invalid"


@pytest.mark.parametrize(
    "candidate",
    [
        '{"value":1.5}',
        '{"value":NaN}',
        '{"value":[1]}',
        '{"value":"' + chr(0xD800) + '"}',
        '{"value":"' + ("x" * (64 * 1024)) + '"}',
        '{"value":1,"value":2}',
    ],
)
def test_canonical_structured_bytes_withholds_malformed_or_oversized_payload(candidate: str) -> None:
    assert canonical_structured_content_bytes(candidate) is None


@pytest.mark.parametrize(
    ("harness", "event_name", "native_overrides", "binding", "required_reason"),
    [
        ("codex", "PostToolUse", {}, _binding("pi"), None),
        ("pi", "PreToolUse", {}, _binding("pi"), None),
        ("pi", "PostToolUse", {"observe_mode": True}, _binding("pi"), None),
        ("pi", "PostToolUse", {}, None, None),
        ("omp", "PostToolUse", {}, _binding("pi"), None),
    ],
)
def test_mediation_early_exits_preserve_native_authority(
    harness: str,
    event_name: str,
    native_overrides: dict[str, object],
    binding: StructuredOutputBinding | None,
    required_reason: str | None,
) -> None:
    native_result = _native_result(**native_overrides)
    original_result = dict(native_result)
    result = mediate_native_post_tool_content(
        harness=harness,
        event_name=event_name,
        native_result=native_result,
        validated_receipt=_receipt(),
        structured_output_json='{"employee":{"email":"","id":7},"note":"x"}',
        binding=binding,
        required_reason_code=required_reason,
    )
    assert result is None
    assert native_result == original_result


@pytest.mark.parametrize(
    ("native_overrides", "expected_reason", "cancelled", "recheck"),
    [
        ({"model_output_action": "review"}, "structured_content_unproved", False, "present"),
        ({}, "structured_review_cancelled", True, "present"),
        ({}, "structured_binding_recheck_missing", False, "missing"),
    ],
)
def test_mediation_withholds_unproved_or_cancelled_content_without_native_rewrite(
    native_overrides: dict[str, object],
    expected_reason: str,
    cancelled: bool,
    recheck: str,
) -> None:
    native_result = _native_result(**native_overrides)
    original_result = dict(native_result)
    result = mediate_native_post_tool_content(
        harness="pi",
        event_name="PostToolUse",
        native_result=native_result,
        validated_receipt=_receipt(),
        structured_output_json='{"employee":{"email":"","id":7},"note":"x"}',
        binding=_binding(),
        cancelled=cancelled,
        recheck_binding=(lambda: _binding()) if recheck == "present" else None,
    )
    assert result is not None
    assert result.action == "withhold"
    assert result.reason_code == expected_reason
    assert result.content_sha256 is None
    assert native_result == original_result

"""Native bridge review regressions: malformed data must not become authority."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import get_args

import pytest

from codex_plugin_scanner.guard import config, local_supply_chain, native_execution
from codex_plugin_scanner.guard.contained_workspace_write_execution import ContainedWriteOperation
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime import local_mcp_stdio, runner
from codex_plugin_scanner.guard.runtime.effect_decision import FinalDisposition


def _decision(**overrides):
    return {
        "action": "review",
        "disposition": "review",
        "proof_routes": [],
        "controlling_reasons": [],
        "reasons": [],
        **overrides,
    }


def _write_payload(operation):
    return {
        "attestation": {"exit_code": 0},
        "decision": _decision(),
        "stdout": "",
        "stderr": "",
        "operation_id": operation,
    }


def test_request_ids_are_unique_across_threads():
    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(lambda _: native_execution._request_id("review"), range(2000)))
    assert len(set(ids)) == len(ids)
    assert all(value.startswith("review-") and len(value) == 39 for value in ids)


@pytest.mark.parametrize("action", get_args(GuardAction))
def test_native_decision_accepts_only_declared_guard_actions(action):
    assert native_execution._effect_decision(_decision(action=action)).action == action
    reason = native_execution._decision_reason({"source": "policy", "reason_code": "test", "action_floor": action})
    assert reason.action_floor == action


@pytest.mark.parametrize("action", ["ALLOW", "unknown", "", None, 1])
def test_native_decision_rejects_invalid_actions(action):
    with pytest.raises(ValueError):
        native_execution._effect_decision(_decision(action=action))
    with pytest.raises(ValueError):
        native_execution._decision_reason({"source": "policy", "reason_code": "test", "action_floor": action})


@pytest.mark.parametrize("disposition", list(FinalDisposition))
def test_native_disposition_is_an_enum(disposition):
    result = native_execution._effect_decision(_decision(disposition=disposition.value))
    assert result.disposition is disposition


def test_invalid_native_disposition_is_rejected():
    with pytest.raises(ValueError):
        native_execution._effect_decision(_decision(disposition="unknown"))


@pytest.mark.parametrize("operation", get_args(ContainedWriteOperation))
def test_contained_write_accepts_declared_operations(operation):
    assert native_execution._contained_workspace_write_result(_write_payload(operation)).operation_id == operation


def test_contained_write_rejects_unknown_operation():
    with pytest.raises(ValueError, match="invalid contained write operation"):
        native_execution._contained_workspace_write_result(_write_payload("unknown"))


@pytest.mark.parametrize("requests", [[{}, None], ["bad"], "bad", {}, 7])
def test_malformed_prompt_requests_do_not_reach_resident(monkeypatch, tmp_path, requests):
    monkeypatch.setattr(native_execution, "_resident_request", lambda **_: pytest.fail("transport called"))
    assert native_execution.prompt_analyze_native("extract", guard_home=tmp_path, requests=requests) is None


@pytest.mark.parametrize("classes", [["read", 1], "read", {}, 7])
def test_malformed_approval_classes_do_not_reach_resident(monkeypatch, tmp_path, classes):
    monkeypatch.setattr(native_execution, "_resident_request", lambda **_: pytest.fail("transport called"))
    assert native_execution.prompt_analyze_native("extract", guard_home=tmp_path, approved_classes=classes) is None


def test_valid_prompt_requests_keep_their_fields(monkeypatch, tmp_path):
    captured = {}

    def resident(**kwargs):
        captured.update(kwargs)
        return {"result": False}

    monkeypatch.setattr(native_execution, "_resident_request", resident)
    requests = [{"request_id": "r", "severity": 8}]
    assert (
        native_execution.prompt_analyze_native(
            "should_force_reapproval", guard_home=tmp_path, requests=requests, approved_classes=["read"]
        )
        is False
    )
    assert captured["request"]["requests"] == requests
    assert captured["request"]["approved_classes"] == ["read"]


@pytest.mark.parametrize("explicit", [False, True])
def test_mcp_probe_uses_resolved_or_explicit_guard_home(monkeypatch, tmp_path, explicit):
    captured = {}

    def probe(*_args, **kwargs):
        captured.update(kwargs)
        return {"status": "failed", "reason": "test"}

    monkeypatch.setattr(native_execution, "mcp_stdio_probe_native", probe)
    monkeypatch.setattr(config, "resolve_guard_home", lambda: tmp_path / "resolved")
    override = tmp_path / "override" if explicit else None
    result = local_mcp_stdio.run_mcp_catalog(["test-server"], guard_home=override)
    assert captured["guard_home"] == (override if explicit else tmp_path / "resolved")
    assert result.reason == "test"


@pytest.mark.parametrize("error", [OSError("transport"), ValueError("payload")])
def test_expected_prompt_transport_errors_fall_back(monkeypatch, error):
    def fail(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(native_execution, "prompt_analyze_native", fail)
    assert runner._prompt_analyze_native("extract", prompt_text="test") is None


def test_prompt_programming_errors_are_not_hidden(monkeypatch):
    def fail(*_args, **_kwargs):
        raise RuntimeError("programming regression")

    monkeypatch.setattr(native_execution, "prompt_analyze_native", fail)
    with pytest.raises(RuntimeError, match="programming regression"):
        runner._prompt_analyze_native("extract", prompt_text="test")


@pytest.mark.parametrize("native", [[{"request_id": "r", "request_class": "read"}, None], [None]])
def test_prompt_extraction_falls_back_on_any_malformed_item(monkeypatch, native):
    fallback = [object()]
    monkeypatch.setattr(runner, "_prompt_analyze_native", lambda *_args, **_kwargs: native)
    monkeypatch.setattr(runner, "_extract_prompt_requests_python", lambda _: fallback)
    assert runner.extract_prompt_requests("test") is fallback


def test_artifacts_fall_back_on_any_malformed_item(monkeypatch, tmp_path):
    fallback = [object()]
    monkeypatch.setattr(runner, "_prompt_policy_path", lambda *_: tmp_path / "policy")
    monkeypatch.setattr(runner, "_prompt_analyze_native", lambda *_args, **_kwargs: [{"artifact_id": "a"}, None])
    monkeypatch.setattr(runner, "_prompt_requests_to_artifacts_python", lambda **_: fallback)
    assert (
        runner.prompt_requests_to_artifacts(
            detection=SimpleNamespace(harness="claude-code"), context=SimpleNamespace(), requests=[]
        )
        is fallback
    )


def test_approval_filter_cannot_turn_non_string_into_permission(monkeypatch):
    captured = {}

    def unavailable(*_args, **kwargs):
        captured.update(kwargs)
        return None

    monkeypatch.setattr(runner, "_prompt_analyze_native", unavailable)
    request = runner._prompt_request_from_dict({"request_id": "r", "request_class": "42", "severity": 1})
    assert request is not None
    assert runner.should_force_reapproval([request], {"approved_prompt_classes": [42, "read"]})
    assert captured["approved_classes"] == ["read"]


@pytest.mark.parametrize("native,expected", [(["npm"], ["npm"]), (["npm", None], ["fallback"]), ({}, ["fallback"])])
def test_supported_manager_list_is_validated(monkeypatch, tmp_path, native, expected):
    monkeypatch.setattr(local_supply_chain, "package_shim_dashboard_status", lambda _: {})
    monkeypatch.setattr(local_supply_chain, "package_shim_supported_managers", lambda: ("fallback",))
    monkeypatch.setattr(native_execution, "shim_admin_native", lambda *_args, **_kwargs: native)
    result = local_supply_chain._build_package_manager_protection(SimpleNamespace(guard_home=tmp_path))
    assert result["supported_managers"] == expected

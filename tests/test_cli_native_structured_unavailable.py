"""CLI native-unavailable presentation for managed structured destinations."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook_native_pipeline as pipeline
from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin
from codex_plugin_scanner.guard.runtime.structured_output_mediation import STRUCTURED_OUTPUT_SETTING_PATH


def _structured_policy() -> dict[str, object]:
    return {
        "version": "hol-guard-structured-output-policy.v1",
        "enabled": True,
        "harnesses": ["pi", "omp"],
        "event": "PostToolUse",
        "destinationRole": "model_visible_tool_result",
        "schema": {"fields": [{"path": ["note"], "role": "ordinary", "valueType": "string"}]},
        "onMatch": "withhold",
        "onUnsupported": "withhold",
    }


@dataclass
class _Args:
    harness: str
    json: bool = True


@dataclass
class _ManagedPolicy:
    settings: dict[str, object]
    content_hash: str


@dataclass
class _Config:
    managed_policy_status: str
    managed_policy_hash: str | None
    managed_locked_settings: tuple[str, ...]
    managed_policy: _ManagedPolicy | None


def _managed_config() -> _Config:
    policy_hash = "a" * 64
    return _Config(
        managed_policy_status="active",
        managed_policy_hash=policy_hash,
        managed_locked_settings=(STRUCTURED_OUTPUT_SETTING_PATH,),
        managed_policy=_ManagedPolicy(
            settings={"data_control": {"structured_output": _structured_policy()}},
            content_hash=policy_hash,
        ),
    )


def _optional_config() -> _Config:
    return _Config(
        managed_policy_status="absent",
        managed_policy_hash=None,
        managed_locked_settings=(),
        managed_policy=None,
    )


@dataclass
class _OverlayWorker(HookWorkerNativeMixin):
    config: _Config

    def _load_config(self, _guard_home: Path, _workspace: Path | None) -> _Config:
        return self.config


def _emit_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    harness: str,
    event_name: str,
    reason_code: str,
    config: _Config,
    recording_only: bool = False,
) -> dict[str, object]:
    emitted: dict[str, object] = {}

    def capture(command: str, payload: dict[str, object], as_json: bool) -> None:
        emitted.update(command=command, payload=payload, as_json=as_json)

    monkeypatch.setattr(pipeline, "_emit", capture)
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )
    args = _Args(harness=harness)
    assert (
        pipeline._emit_native_unavailable(
            args,
            payload={"hook_event_name": event_name},
            workspace=context.workspace_dir,
            context=context,
            event_name=event_name,
            reason_code=reason_code,
            worker=_OverlayWorker(config),
            recording_only=recording_only,
        )
        == 0
    )
    assert emitted["command"] == "hook"
    assert emitted["as_json"] is True
    response = emitted["payload"]
    assert isinstance(response, dict)
    return response


@pytest.mark.parametrize("harness", ["pi", "omp"])
@pytest.mark.parametrize(
    "reason_code",
    [
        "native_post_tool_unavailable",
        "native_review_deadline_exceeded",
        "native_command_control_fence_unavailable",
    ],
)
def test_cli_native_unavailable_withholds_managed_posttool_destination(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    harness: str,
    reason_code: str,
) -> None:
    response = _emit_unavailable(
        monkeypatch,
        tmp_path,
        harness=harness,
        event_name="PostToolUse",
        reason_code=reason_code,
        config=_managed_config(),
    )

    assert response["decision"] == "allow"
    assert response["policy_action"] == "allow"
    assert response["reason_code"] == reason_code
    assert response["structured_content_mediation"] == {
        "schema": "guard-structured-content-mediation.v1",
        "action": "withhold",
        "reason_code": "structured_native_edge_unavailable",
    }
    assert "receipt" not in response
    assert "native_decision_id" not in response["structured_content_mediation"]


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_cli_native_unavailable_keeps_optional_structured_destination_off(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    harness: str,
) -> None:
    response = _emit_unavailable(
        monkeypatch,
        tmp_path,
        harness=harness,
        event_name="PostToolUse",
        reason_code="native_post_tool_unavailable",
        config=_optional_config(),
    )

    assert response == {
        "decision": "allow",
        "policy_action": "allow",
        "reason_code": "native_post_tool_unavailable",
    }


@pytest.mark.parametrize(
    ("recording_only", "decision", "reason_code"),
    [
        (False, "block", "native_prompt_unavailable"),
        (True, "allow", "native_prompt_deadline_exceeded"),
    ],
)
def test_cli_native_unavailable_preserves_native_recording_posture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    recording_only: bool,
    decision: str,
    reason_code: str,
) -> None:
    response = _emit_unavailable(
        monkeypatch,
        tmp_path,
        harness="pi",
        event_name="UserPromptSubmit",
        reason_code=reason_code,
        config=_optional_config(),
        recording_only=recording_only,
    )

    assert response["decision"] == decision
    assert response["reason_code"] == reason_code

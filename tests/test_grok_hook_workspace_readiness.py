from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType

import pytest

from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import (
    _render_bounded_hook_script,
)

READY = {"ready": True, "workspace_acknowledged": True, "worker_ready": True}


def _load_script(tmp_path: Path, *, harness: str, timeout_seconds: float = 8) -> ModuleType:
    module = ModuleType("generated_grok_readiness")
    source = _render_bounded_hook_script(
        guard_home=tmp_path / "guard-home", harness=harness, timeout_seconds=timeout_seconds
    )
    exec(compile(source, "generated-grok-readiness.py", "exec"), module.__dict__)
    return module


@pytest.mark.parametrize("event", ["UserPromptSubmit", "user_prompt_submit", "UserPromptSubmitted"])
def test_prompt_prepares_workspace_and_preserves_native_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, event: str
) -> None:
    module = _load_script(tmp_path, harness="grok", timeout_seconds=85)
    clock = [10.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module, "_HOOK_DEADLINE_MONOTONIC", 95.0)
    monkeypatch.setattr(module, "_daemon_auth", lambda: ("127.0.0.1", 9, "fixture"))
    calls = []

    def transport(url, token, *, data, timeout):
        assert token == "fixture"
        body = json.loads(data)
        calls.append((url, timeout, body))
        if url.endswith("/readiness"):
            assert body == {"cwd": str(tmp_path)}
            clock[0] += 2.0
            return READY
        assert body["prompt"] == "synthetic prompt"
        assert body["guard_remaining_ms"] == 3000
        assert "guard_remaining_seconds" not in body
        return {"decision": "block", "policy_action": "block", "reason": "native block"}

    monkeypatch.setattr(module, "_http_json", transport)
    result = module._post_hook(json.dumps({
        "hook_event_name": event, "cwd": str(tmp_path), "prompt": "synthetic prompt",
        "guard_remaining_seconds": 999, "guard_remaining_ms": 999000,
    }))
    assert result is not None
    stdout, _, status = result
    assert status != 0
    assert json.loads(stdout)["policy_action"] == "block"
    assert [call[1] for call in calls] == [5.0, 3.0]


@pytest.mark.parametrize(
    "ready",
    [None, {}, {"ready": True}, {**READY, "ready": 1}, {**READY, "worker_ready": False},
     {"ready": True, "native_required": 0}],
)
def test_failed_readiness_cannot_admit_prompt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], ready: object
) -> None:
    module = _load_script(tmp_path, harness="grok")
    monkeypatch.setattr(module, "_daemon_auth", lambda: ("127.0.0.1", 9, "fixture"))
    calls = []

    def transport(url, *_args, **_kwargs):
        calls.append(url)
        return ready

    monkeypatch.setattr(module, "_http_json", transport)
    assert module._post_hook('{"hook_event_name":"UserPromptSubmit"}') is None
    assert len(calls) == 1 and calls[0].endswith("/readiness")
    module._fail('{"hook_event_name":"UserPromptSubmit"}')
    assert json.loads(capsys.readouterr().out)["decision"] == "block"


def test_explicit_non_enforcing_readiness_still_requires_hook_decision(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script(tmp_path, harness="grok")
    monkeypatch.setattr(module, "_daemon_auth", lambda: ("127.0.0.1", 9, "fixture"))
    calls = []

    def transport(url, *_args, **_kwargs):
        calls.append(url)
        if url.endswith("/readiness"):
            return {"ready": True, "native_required": False, "workspace_acknowledged": False, "worker_ready": True}
        return {"decision": "block", "policy_action": "block", "reason": "hook block"}

    monkeypatch.setattr(module, "_http_json", transport)
    result = module._post_hook('{"hook_event_name":"UserPromptSubmit"}')
    assert result is not None
    assert json.loads(result[0])["policy_action"] == "block"
    assert len(calls) == 2


def test_spent_readiness_budget_does_not_start_semantic_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_script(tmp_path, harness="grok", timeout_seconds=85)
    clock = [10.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module, "_HOOK_DEADLINE_MONOTONIC", 95.0)
    monkeypatch.setattr(module, "_daemon_auth", lambda: ("127.0.0.1", 9, "fixture"))
    calls = []

    def transport(url, *_args, **_kwargs):
        calls.append(url)
        clock[0] = 15.0
        return READY

    monkeypatch.setattr(module, "_http_json", transport)
    assert module._post_hook('{"hook_event_name":"UserPromptSubmit"}') is None
    assert len(calls) == 1


@pytest.mark.parametrize("event,timeout", [("SessionStart", 1.0), ("PreToolUse", 5.0)])
def test_passive_and_pretool_calls_keep_existing_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, event: str, timeout: float
) -> None:
    module = _load_script(tmp_path, harness="grok", timeout_seconds=85)
    monkeypatch.setattr(module, "_daemon_auth", lambda: ("127.0.0.1", 9, "fixture"))
    calls = []

    def transport(url, *_args, **kwargs):
        calls.append((url, kwargs["timeout"]))
        return None

    monkeypatch.setattr(module, "_http_json", transport)
    assert module._post_hook(json.dumps({"hook_event_name": event})) is None
    assert calls == [("http://127.0.0.1:9/v1/hooks/grok", timeout)]


def test_python_bridge_prepares_workspace_with_one_budget_and_preserves_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.adapters import bounded_cli_hook_daemon as daemon
    from codex_plugin_scanner.guard.adapters import bounded_hook_http as http

    clock = [10.0]
    monkeypatch.setattr(http.time, "monotonic", lambda: clock[0])
    calls = []

    def transport(endpoint, token, data, *, deadline, **_kwargs):
        assert token == "fixture"
        assert deadline == 15.0
        calls.append((endpoint, json.loads(data)))
        if endpoint.endswith("/readiness"):
            clock[0] += 2.0
            return READY
        assert calls[-1][1]["guard_remaining_ms"] == 3000
        assert "guard_remaining_seconds" not in calls[-1][1]
        return {"decision": "block", "policy_action": "block", "reason": "native block"}

    monkeypatch.setattr(http, "post_hook_json", transport)
    monkeypatch.setattr(daemon, "post_hook_json", transport)
    result = daemon.try_daemon_hook(
        guard_home=tmp_path, harness="grok", timeout_seconds=85,
        input_text=json.dumps({"hook_event_name": "user_prompt_submit", "cwd": str(tmp_path),
                               "guard_remaining_seconds": 999}),
        _endpoint_loader=lambda *_args: "http://127.0.0.1:9/v1/hooks/grok",
        _token_loader=lambda *_args: "fixture",
        _opener_builder=lambda: object(),
    )
    assert result is not None
    assert json.loads(result[0])["policy_action"] == "block"
    assert len(calls) == 2

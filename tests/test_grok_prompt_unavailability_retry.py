from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType

import pytest

from codex_plugin_scanner.guard.adapters import bounded_hook_http
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import _render_bounded_hook_script

UNAVAILABLE = {"decision": "block", "reason_code": "native_prompt_unavailable"}
READY = {"ready": True, "workspace_acknowledged": True, "worker_ready": True}


@pytest.mark.parametrize("bridge", [False, True])
@pytest.mark.parametrize(
    "second", [{}, UNAVAILABLE, {"decision": "block", "reason_code": "native_prompt_injection_review"}]
)
def test_retry_requires_fresh_native_result_inside_original_budget(tmp_path: Path, monkeypatch, bridge, second) -> None:
    clock = [10.0]
    calls = []
    replies = [READY, UNAVAILABLE, READY, second]

    def transport(url, token, *, data, timeout):
        calls.append((url, json.loads(data), timeout))
        clock[0] += 1
        return replies.pop(0)

    result = _review(tmp_path, monkeypatch, bridge, clock, transport)
    assert result == second
    assert len(calls) == 4
    assert [call[2] for call in calls] == [10, 9, 8, 7]
    assert calls[1][1]["guard_remaining_ms"] == 9000
    assert calls[3][1]["guard_remaining_ms"] == 7000


@pytest.mark.parametrize("bridge", [False, True])
@pytest.mark.parametrize(
    "response",
    [
        None,
        {"decision": "block", "reason_code": "native_prompt_injection_review"},
        {"decision": "block", "reason_code": "other"},
    ],
)
def test_transport_failure_and_policy_denials_are_not_retried(tmp_path: Path, monkeypatch, bridge, response) -> None:
    calls = []

    def transport(url, token, *, data, timeout):
        calls.append(url)
        return READY if url.endswith("/readiness") else response

    assert _review(tmp_path, monkeypatch, bridge, [10.0], transport) == response
    assert len(calls) == 2


@pytest.mark.parametrize("bridge", [False, True])
def test_retry_cannot_extend_exhausted_deadline(tmp_path: Path, monkeypatch, bridge) -> None:
    clock = [10.0]
    calls = []

    def transport(url, token, *, data, timeout):
        calls.append(url)
        if url.endswith("/readiness"):
            return READY
        clock[0] = 20.0
        return UNAVAILABLE

    assert _review(tmp_path, monkeypatch, bridge, clock, transport) is None
    assert len(calls) == 2


def _review(tmp_path, monkeypatch, bridge, clock, transport):
    payload = json.dumps({"hook_event_name": "UserPromptSubmit", "cwd": str(tmp_path), "prompt": "synthetic"})
    if bridge:
        monkeypatch.setattr(bounded_hook_http.time, "monotonic", lambda: clock[0])
        monkeypatch.setattr(
            bounded_hook_http,
            "post_hook_json",
            lambda url, token, data, **kwargs: transport(url, token, data=data, timeout=kwargs["deadline"] - clock[0]),
        )
        return bounded_hook_http.post_grok_prompt(
            "http://127.0.0.1:9/v1/hooks/grok", "fixture", payload, opener=None, deadline=20.0, max_bytes=10000
        )
    module = ModuleType("generated_retry_client")
    exec(_render_bounded_hook_script(guard_home=tmp_path, harness="grok", timeout_seconds=85), module.__dict__)
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(module, "_HOOK_DEADLINE_MONOTONIC", 95.0)
    monkeypatch.setattr(module, "_http_json", transport)
    return module._post_grok_prompt(payload, "127.0.0.1", 9, "fixture", 10.0)

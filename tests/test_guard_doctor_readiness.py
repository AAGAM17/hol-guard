"""Doctor separates passive setup checks from proof of Guard evaluation."""

from __future__ import annotations

import json
from io import StringIO

import pytest
from rich.console import Console

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters import list_adapters
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.cli.doctor_readiness import doctor_runtime_readiness
from codex_plugin_scanner.guard.cli.render import _render_doctor, emit_guard_payload


@pytest.mark.parametrize(
    ("setup_status", "probe", "state", "reason"),
    [
        ("active", None, "unknown", "hook_evaluation_unverified"),
        ("active", {"ok": True, "return_code": 0}, "unknown", "hook_evaluation_unverified"),
        ("active", {"ok": False, "return_code": 1}, "unknown", "harness_probe_failed"),
        ("active", {"ok": False, "timed_out": True}, "unknown", "harness_probe_timed_out"),
        ("broken", {"ok": True}, "fail", "guard_setup_broken"),
        ("partial", {"ok": True}, "unknown", "hook_registration_unconfirmed"),
        ("not_found", None, "unknown", "hook_registration_unconfirmed"),
    ],
)
def test_doctor_json_does_not_promote_registration_or_cli_success_to_readiness(
    tmp_path, monkeypatch, capsys, setup_status, probe, state, reason
) -> None:
    monkeypatch.setattr(
        CodexHarnessAdapter,
        "diagnostics",
        lambda _self, _context: {
            "harness": "codex",
            "installed": True,
            "command_available": True,
            "setup_status": setup_status,
            "runtime_probe": probe,
            "native_hook_state": {"integrity_status": "valid", "protection_active": True},
            "warnings": [],
            "artifacts": [],
        },
    )
    rc = main(
        [
            "guard",
            "doctor",
            "codex",
            "--json",
            "--home",
            str(tmp_path / "home"),
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--workspace",
            str(tmp_path / "workspace"),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["setup_status"] == setup_status
    assert payload["runtime_readiness"]["state"] == state
    assert payload["runtime_readiness"]["reason_code"] == reason


def test_global_doctor_reports_readiness_for_every_registered_harness(tmp_path, capsys) -> None:
    rc = main(
        [
            "guard",
            "doctor",
            "--json",
            "--home",
            str(tmp_path / "home"),
            "--guard-home",
            str(tmp_path / "guard-home"),
            "--workspace",
            str(tmp_path / "workspace"),
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert {item["harness"] for item in payload["adapters"]} == {item.harness for item in list_adapters()}
    assert all(item["runtime_readiness"]["state"] == "unknown" for item in payload["adapters"])


@pytest.mark.parametrize("probe", [None, {"ok": True, "return_code": 0}])
def test_doctor_text_shows_unverified_evaluation_even_when_setup_is_active(capsys, probe) -> None:
    emit_guard_payload(
        "doctor",
        {
            "harness": "codex",
            "installed": True,
            "command_available": True,
            "setup_status": "active",
            "runtime_probe": probe,
            "warnings": [],
        },
        False,
    )
    output = " ".join(capsys.readouterr().out.split())

    assert "Registration" in output
    assert "Runtime readiness" in output
    assert "Unverified" in output
    assert "authenticated Guard decision" in output


def test_global_doctor_text_does_not_label_detected_harness_ready(capsys) -> None:
    emit_guard_payload(
        "doctor",
        {
            "tables": [],
            "adapters": [{"harness": "codex", "installed": True, "command_available": True}],
        },
        False,
    )
    output = " ".join(capsys.readouterr().out.split())

    assert "Detection" in output
    assert "Runtime readiness" in output
    assert "Unverified" in output
    assert "Ready" not in output


def test_doctor_readiness_does_not_echo_raw_probe_data_or_accept_claimed_health() -> None:
    readiness = doctor_runtime_readiness(
        {
            "setup_status": "active",
            "runtime_probe": {
                "ok": True,
                "ready": True,
                "authenticated": True,
                "stdout": "private-probe-output",
                "stderr": "private-probe-error",
            },
            "runtime_readiness": {"state": "pass"},
            "trust": {"healthy": True},
        }
    )

    assert readiness["state"] == "unknown"
    assert readiness["reason_code"] == "hook_evaluation_unverified"
    assert "private-probe" not in json.dumps(readiness)


@pytest.mark.parametrize("width", [48, 80, 120])
def test_doctor_readiness_is_visible_at_narrow_terminal_widths(width) -> None:
    stream = StringIO()
    console = Console(file=stream, width=width, color_system=None)
    _render_doctor(
        console,
        {
            "harness": "antigravity",
            "installed": True,
            "command_available": True,
            "setup_status": "active",
            "warnings": [],
        },
    )

    output = stream.getvalue()
    assert "Unverified" in output
    assert "Registration" in output
    assert "active" in output

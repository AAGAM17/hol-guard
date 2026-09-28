"""Offline incident output preserves authenticated versus loaded-runtime boundaries."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
from codex_plugin_scanner.guard.cli.commands_router import run_guard_command
from codex_plugin_scanner.guard.cli.doctor_incident import codex_incident_report, run_codex_incident_export
from codex_plugin_scanner.guard.codex_hook_integrity import hook_manifest_path


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    home.mkdir()
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard-home")


def test_incident_export_is_independent_of_guard_store(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_router.GuardStore",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("store opened")),
    )
    output = io.StringIO()
    args = argparse.Namespace(
        guard_command="doctor",
        harness="codex",
        incident=True,
        json=True,
        home=str(context.home_dir),
        guard_home=str(context.guard_home),
        workspace=None,
        repair=False,
    )

    assert run_guard_command(args, output_stream=output) == 0
    report = json.loads(output.getvalue())
    assert report["configured"]["config_status"] == "missing"
    assert report["loaded_harness"]["state"] == "unknown"
    assert report["authenticated_hook_decision"]["state"] == "unknown"
    assert report["daemon"]["discovery_authentication"] == "unverified"
    assert len(output.getvalue().encode()) < 8192


def test_incident_export_reports_authenticated_config_without_loaded_claim(tmp_path: Path) -> None:
    context = _context(tmp_path)
    CodexHarnessAdapter().install(context)

    report = codex_incident_report(context)

    assert report["configured"]["manifest_integrity"] == "valid"
    assert all(report["configured"]["managed_events"].values())
    assert report["configured"]["manifest_package_version"] == report["cli_package_version"]
    assert len(report["configured"]["bridge_sha256"]) == 64
    assert len(report["configured"]["interpreter_sha256"]) == 64
    assert report["configured"]["manifest_generated_at"]
    assert report["loaded_harness"]["state"] == "unknown"
    assert report["authenticated_hook_decision"]["state"] == "unknown"


def test_incident_export_rejects_oversized_config_without_reading_it(tmp_path: Path) -> None:
    context = _context(tmp_path)
    config_path = context.home_dir / ".codex" / "config.toml"
    config_path.parent.mkdir()
    config_path.write_bytes(b" " * (1024 * 1024 + 1))

    report = codex_incident_report(context)

    assert report["configured"]["config_status"] == "too_large"
    assert report["configured"]["manifest_integrity"] == "unverified"
    assert report["configured"]["manifest_package_version"] is None
    assert report["configured"]["bridge_sha256"] is None


def test_incident_export_does_not_expose_identity_from_tampered_manifest(tmp_path: Path) -> None:
    context = _context(tmp_path)
    CodexHarnessAdapter().install(context)
    manifest_path = hook_manifest_path(context.guard_home, CodexHarnessAdapter._hook_config_path(context))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["package_version"] = "forged-version"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    report = codex_incident_report(context)

    assert report["configured"]["manifest_integrity"] != "valid"
    assert report["configured"]["manifest_package_version"] is None
    assert report["configured"]["bridge_sha256"] is None
    assert report["loaded_harness"]["state"] == "unknown"


def test_incident_cli_parser_emits_one_bounded_json_report(tmp_path: Path, capsys) -> None:
    context = _context(tmp_path)

    result = main(
        [
            "guard",
            "doctor",
            "codex",
            "--incident",
            "--json",
            "--home",
            str(context.home_dir),
            "--guard-home",
            str(context.guard_home),
        ]
    )

    output = capsys.readouterr()
    assert result == 0
    assert output.err == ""
    assert json.loads(output.out)["schema"] == "hol-guard.codex-incident.v1"
    assert len(output.out.encode()) < 8192


def test_incident_export_never_echoes_untrusted_config_or_exception(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    config_path = context.home_dir / ".codex" / "config.toml"
    config_path.parent.mkdir()
    config_path.write_text("[features]\nhooks = true\n# PRIVATE_TOKEN\n", encoding="utf-8")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.doctor_incident.verify_live_hook_manifest",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("PRIVATE_TOKEN")),
    )

    report = codex_incident_report(context)

    assert report["configured"]["reason_code"] == "codex_integrity_probe_failed"
    assert "PRIVATE_TOKEN" not in json.dumps(report)


def test_incident_export_rejects_repair_without_running_diagnostics(tmp_path: Path, monkeypatch) -> None:
    context = _context(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.doctor_incident.codex_incident_report",
        lambda _context: (_ for _ in ()).throw(AssertionError("diagnostics ran")),
    )
    output = io.StringIO()

    result = run_codex_incident_export(
        argparse.Namespace(harness="codex", repair=True), context, output_stream=output
    )

    assert result == 2
    assert json.loads(output.getvalue())["error"] == "incident_export_requires_codex_without_other_doctor_actions"

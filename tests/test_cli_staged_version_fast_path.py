"""Version probes must stay cheap under temporary executable names."""

from __future__ import annotations

import sys

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.version import __version__


def test_staged_candidate_version_avoids_full_command_surface(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    candidate_name = "hol-guard-3.8.1-123-456.partial"
    monkeypatch.setattr(sys, "argv", [candidate_name, "--version"])
    monkeypatch.setattr(sys, "frozen", True, raising=False)

    def unexpected_parser(*_args: object, **_kwargs: object) -> None:
        pytest.fail("a version probe must not build the full command surface")

    monkeypatch.setattr(cli, "_build_parser", unexpected_parser)

    assert cli.main() == 0
    assert capsys.readouterr().out.strip() == f"{candidate_name} {__version__}"

"""Version probes must stay cheap under temporary executable names."""

from __future__ import annotations

import sys

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.version import __version__


@pytest.mark.parametrize(
    ("program_name", "frozen"),
    [
        ("hol-guard-3.8.1-123-456.partial", True),
        ("hol-guard-3.8.1-123-456.partial", False),
        ("hol-guard", False),
        ("plugin-guard", False),
        ("plugin-scanner", False),
    ],
)
def test_version_probe_avoids_full_command_surface_for_executable_names(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    program_name: str,
    frozen: bool,
) -> None:
    monkeypatch.setattr(sys, "argv", [program_name, "--version"])
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)

    def unexpected_parser(*_args: object, **_kwargs: object) -> None:
        pytest.fail("a version probe must not build the full command surface")

    monkeypatch.setattr(cli, "_build_parser", unexpected_parser)

    assert cli.main() == 0
    assert capsys.readouterr().out.strip() == f"{program_name} {__version__}"

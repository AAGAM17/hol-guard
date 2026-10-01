"""Keep contribution validation distinct from strict generated-file freshness."""

from __future__ import annotations

import sys
from types import ModuleType

import pytest

from scripts.ci import verify_native_command_program as verifier


@pytest.mark.parametrize("base_sha", [None, "a" * 40])
@pytest.mark.parametrize("pending,changed", [(False, False), (True, False), (False, True)])
def test_shared_verifier_compiles_pending_pr_sources_and_keeps_other_runs_strict(
    monkeypatch: pytest.MonkeyPatch, base_sha: str | None, pending: bool, changed: bool
) -> None:
    detector = ModuleType("detect_pending_extension_regen")
    detector.contribution_ids = lambda: {"command.fixture"} if pending else set()
    detector.catalog_ids = set
    detector._contributions_changed = (
        lambda _sha: ["contributions/command-sources/command.fixture.json"] if changed else []
    )
    monkeypatch.setitem(sys.modules, "detect_pending_extension_regen", detector)
    monkeypatch.setattr(sys, "path", list(sys.path))
    arguments = ["verify", "--compiler", "fixture-compiler"]
    if base_sha:
        arguments += ["--changed-from", base_sha]
    monkeypatch.setattr(sys, "argv", arguments)
    calls: list[list[str]] = []
    monkeypatch.setattr(verifier, "_run", calls.append)

    assert verifier.main() == 0

    generate = [sys.executable, "scripts/build_native_command_program.py", "--compiler", "fixture-compiler"]
    if base_sha and (pending or changed):
        assert calls == [
            generate,
            ["git", "checkout", "--", *verifier.GENERATED_PATHS],
            ["git", "clean", "-fdq", "--", *verifier.GENERATED_PATHS],
        ]
    else:
        assert calls == [[*generate, "--check"]]


def test_invalid_pending_source_stays_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    detector = ModuleType("detect_pending_extension_regen")
    detector.contribution_ids = lambda: {"command.fixture"}
    detector.catalog_ids = set
    detector._contributions_changed = lambda _sha: []
    monkeypatch.setitem(sys.modules, "detect_pending_extension_regen", detector)
    monkeypatch.setattr(sys, "path", list(sys.path))
    monkeypatch.setattr(sys, "argv", ["verify", "--compiler", "fixture-compiler", "--changed-from", "a" * 40])
    calls: list[list[str]] = []

    def invalid_source(command: list[str]) -> None:
        calls.append(command)
        raise SystemExit(37)

    monkeypatch.setattr(verifier, "_run", invalid_source)
    with pytest.raises(SystemExit) as failure:
        verifier.main()
    assert failure.value.code == 37
    assert calls == [[sys.executable, "scripts/build_native_command_program.py", "--compiler", "fixture-compiler"]]

"""Cleanup failures must not skip independent containment or leak diagnostics."""

from pathlib import Path

import pytest

from ci.gauntlet import runner


@pytest.mark.parametrize("failed_steps", [(), ("daemon",), ("native",), ("daemon", "native")])
def test_cleanup_attempts_both_steps_and_keeps_failure_details_private(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failed_steps: tuple[str, ...]
) -> None:
    calls: list[str] = []

    def cleanup(step: str) -> None:
        calls.append(step)
        if step in failed_steps:
            try:
                raise ValueError("private underlying failure")
            except ValueError as exc:
                raise RuntimeError("private cleanup context") from exc

    monkeypatch.setattr(runner.probe, "_cleanup_installed_daemon", lambda _daemon: cleanup("daemon"))
    monkeypatch.setattr(runner.probe, "_cleanup_native", lambda _identity, _home: cleanup("native"))

    result = runner._cleanup_case_resources(object(), object(), tmp_path / "guard-home", tmp_path)

    assert calls == ["daemon", "native"]
    if failed_steps:
        assert result == {"cleanup_ok": False, "cleanup_error": "RuntimeError"}
        diagnostic = (tmp_path / "cleanup-error.txt").read_text()
        assert "private underlying failure" in diagnostic
        assert "private cleanup context" in diagnostic
        assert "private" not in str(result)
        for step in failed_steps:
            assert ("installed-daemon" if step == "daemon" else "native-resident") in diagnostic
    else:
        assert result == {"cleanup_ok": True}
        assert not (tmp_path / "cleanup-error.txt").exists()

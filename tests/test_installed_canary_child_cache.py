"""Installed canary children must not add bytecode to verified package files."""

import subprocess
import sys

from scripts.run_installed_canary import _child_python_environment


def test_child_interpreter_inherits_command_line_cache_prefix(tmp_path, monkeypatch):
    package = tmp_path / "installed-package"
    package.mkdir()
    module = package / "canary_cache_probe.py"
    module.write_text("VALUE = 1\n", encoding="utf-8")
    cache = tmp_path / "external-cache"
    monkeypatch.setattr(sys, "pycache_prefix", str(cache))
    monkeypatch.delenv("PYTHONPYCACHEPREFIX", raising=False)

    completed = subprocess.run(
        [sys.executable, "-c", "import canary_cache_probe; import sys; print(sys.pycache_prefix)"],
        cwd=package,
        env=_child_python_environment(),
        capture_output=True,
        text=True,
        check=True,
    )

    assert completed.stdout.strip() == str(cache)
    assert set(package.iterdir()) == {module}
    assert list(cache.rglob("canary_cache_probe.*.pyc"))


def test_child_environment_preserves_settings_without_command_line_prefix(monkeypatch):
    monkeypatch.setattr(sys, "pycache_prefix", None)
    monkeypatch.setenv("PYTHONPYCACHEPREFIX", "existing-cache")
    monkeypatch.setenv("CANARY_CACHE_PROBE", "preserved")

    environment = _child_python_environment()

    assert environment["PYTHONPYCACHEPREFIX"] == "existing-cache"
    assert environment["CANARY_CACHE_PROBE"] == "preserved"

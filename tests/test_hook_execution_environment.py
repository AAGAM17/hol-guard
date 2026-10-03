from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import hook_execution_environment as module


def _write_console_script(
    path: Path,
    interpreter: Path,
    *,
    extra: str = "",
    main_call: str = "main()",
    uv_normalization: bool = False,
    uv_branch_extra: str = "",
) -> None:
    normalization = (
        [
            '    if sys.argv[0].endswith("-script.pyw"):',
            '        sys.argv[0] = sys.argv[0][:-11]',
            *([uv_branch_extra] if uv_branch_extra else []),
            '    elif sys.argv[0].endswith(".exe"):',
            '        sys.argv[0] = sys.argv[0][:-4]',
        ]
        if uv_normalization
        else ["    sys.argv[0] = sys.argv[0].removesuffix('.exe')"]
    )
    path.write_text(
        "\n".join(
            [
                f"#!{interpreter}",
                "import sys",
                "from codex_plugin_scanner.cli import main",
                "if __name__ == '__main__':",
                *normalization,
                f"    sys.exit({main_call})",
                extra,
                "",
            ]
        ),
        encoding="utf-8",
    )
    path.chmod(0o700)


def test_stamp_overwrites_model_context_and_keeps_verified_cli_identity(monkeypatch) -> None:
    identity = {
        "schema": "guard-cli-identity-v1",
        "invocation_path": "/venv/bin/hol-guard",
        "target_path": "/venv/bin/hol-guard-real",
        "target_sha256": "a" * 64,
    }
    monkeypatch.setattr(module, "_verified_guard_cli_identity", lambda _interpreter=None: identity)
    payload = json.loads(
        module.stamp_hook_input_text(
            json.dumps(
                {
                    "command": "/venv/bin/hol-guard doctor",
                    "guard_execution_environment": {"path": "/attacker/path"},
                }
            ),
            cli_interpreter="/venv/bin/python",
        )
    )
    context = payload["guard_execution_environment"]
    assert context["cli_identity"] == identity
    assert context["path"] == os.environ.get("PATH", "")


def test_cli_identity_capture_rejects_fake_launcher_and_binds_script_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package_root = tmp_path / "site-packages"
    package = package_root / "codex_plugin_scanner"
    package.mkdir(parents=True)
    (package / "cli.py").write_text("main = object()\n", encoding="utf-8")
    interpreter = tmp_path / "bin" / "python"
    interpreter.parent.mkdir()
    interpreter.write_bytes(b"python")
    cli = interpreter.parent / "hol-guard"
    _write_console_script(cli, interpreter)
    monkeypatch.setattr(
        module,
        "_guard_cli_recorded_sha256",
        lambda path: hashlib.sha256(path.read_bytes()).hexdigest(),
    )

    identity = module._guard_cli_identity(cli, package_root, str(interpreter))
    assert identity is not None
    assert identity["invocation_path"] == str(cli.absolute())
    assert len(identity["target_sha256"]) == 64

    fake = tmp_path / "fake-hol-guard"
    fake.write_text(f"#!{interpreter}\necho fake\n", encoding="utf-8")
    fake.chmod(0o700)
    assert module._guard_cli_identity(fake, package_root, str(interpreter)) is None


def test_console_script_rejects_matching_import_with_extra_code(tmp_path: Path) -> None:
    package_root = tmp_path / "site-packages"
    package = package_root / "codex_plugin_scanner"
    package.mkdir(parents=True)
    (package / "cli.py").write_text("main = object()\n", encoding="utf-8")
    interpreter = tmp_path / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"python")
    cli = interpreter.parent / "hol-guard"
    _write_console_script(cli, interpreter, extra="print('unexpected side effect')")

    assert not module._python_console_script_matches(cli, package_root, str(interpreter))

    _write_console_script(cli, interpreter, main_call="main(exec('unexpected side effect'))")
    assert not module._python_console_script_matches(cli, package_root, str(interpreter))


def test_console_script_accepts_venv_interpreter_symlink(tmp_path: Path) -> None:
    package_root = tmp_path / "site-packages"
    package = package_root / "codex_plugin_scanner"
    package.mkdir(parents=True)
    (package / "cli.py").write_text("main = object()\n", encoding="utf-8")
    interpreter_target = Path(sys.executable).resolve()
    interpreter = tmp_path / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    try:
        interpreter.symlink_to(interpreter_target)
    except OSError:
        pytest.skip("symlinks are unavailable")
    cli = interpreter.parent / "hol-guard"
    _write_console_script(cli, interpreter)

    assert module._python_console_script_matches(cli, package_root, str(interpreter))


def test_console_script_accepts_uv_normalization_and_rejects_extra_branch_code(
    tmp_path: Path,
) -> None:
    package_root = tmp_path / "site-packages"
    package = package_root / "codex_plugin_scanner"
    package.mkdir(parents=True)
    (package / "cli.py").write_text("main = object()\n", encoding="utf-8")
    interpreter = tmp_path / "venv" / "bin" / "python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"python")
    cli = interpreter.parent / "hol-guard"

    _write_console_script(cli, interpreter, uv_normalization=True)
    assert module._python_console_script_matches(cli, package_root, str(interpreter))

    _write_console_script(
        cli,
        interpreter,
        uv_normalization=True,
        uv_branch_extra="        print('unexpected')",
    )
    assert not module._python_console_script_matches(cli, package_root, str(interpreter))


def test_real_installed_guard_cli_candidate_is_attested_without_mutation() -> None:
    distribution = importlib.metadata.distribution("hol-guard")
    package_root = Path(str(distribution.locate_file(""))).resolve()
    candidates = [
        Path(str(distribution.locate_file(entry)))
        for entry in distribution.files or ()
        if entry.name.lower() in {"hol-guard", "hol-guard.exe"}
    ]
    for candidate in candidates:
        interpreter = candidate.parent / "python"
        if not candidate.is_file() or not interpreter.exists():
            continue
        identity = module._guard_cli_identity(candidate, package_root, str(interpreter))
        if identity is not None:
            assert identity["invocation_path"] == os.path.abspath(str(candidate))
            assert len(identity["target_sha256"]) == 64
            return
    pytest.skip("installed hol-guard pip console script is unavailable")

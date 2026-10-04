"""Build package projections from authored sources with the native compiler."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CommandProjectionBuildHook(BuildHookInterface):
    """Ship frozen, validated metadata without keeping copies in Git."""

    def initialize(self, version: str, build_data: dict) -> None:
        root = Path(self.root)
        command = [sys.executable, str(root / "scripts/build_native_command_program.py"), "--projections-only"]
        compiler = os.environ.get("HOL_GUARD_BUILD_SOURCE_COMPILER")
        if compiler:
            compiler_path = Path(compiler)
            if not compiler_path.is_absolute():
                compiler_path = root / compiler_path
            if compiler_path.is_file():
                command.extend(["--compiler", str(compiler_path)])
        subprocess.run(command, cwd=root, check=True)
        subprocess.run([*command, "--check"], cwd=root, check=True)
        # Register only after generation so editable dependency setup works
        # with absent outputs. Ignored files still travel in both artifacts.
        for name in ("command-catalog.v1.json", "native-command-program.v1.json"):
            relative = f"contracts/extensions/{name}"
            destination = (
                relative
                if self.target_name == "sdist"
                else f"codex_plugin_scanner/guard/contracts/data/extensions/{name}"
            )
            build_data["force_include"][str(root / relative)] = destination

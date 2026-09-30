from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.opencode_pretool import pretool_plugin_source
from tests.test_opencode_pretool import _bun_executable, _ctx


@pytest.mark.parametrize(
    ("workdir", "expected"),
    [
        (None, "/project"),
        ("/project/subfolder", "/project/subfolder"),
        ("../other", "/other"),
        (" spaced folder ", "/project/ spaced folder "),
        ("", "/project"),
        (13, None),
    ],
)
@pytest.mark.parametrize("exit_code", [0, 1, 2])
def test_v2_shell_reviews_its_effective_workdir(
    tmp_path: Path, workdir: object, expected: str | None, exit_code: int
) -> None:
    bun = _bun_executable()
    if bun is None:
        pytest.skip("bun not installed")
    source = pretool_plugin_source(_ctx(tmp_path)).replace(
        "return spawnGuardProcess({", "return globalThis.guardTestSpawn({"
    )
    (tmp_path / "plugin.ts").write_text(source, encoding="utf-8")
    args: dict[str, object] = {"command": "pwd"}
    if workdir is not None:
        args["workdir"] = workdir
    script = tmp_path / "runner.ts"
    script.write_text(
        "import plugin from './plugin';\n"
        "import { resolve } from 'node:path';\n"
        "let handler; let calls = 0; let reviewed;\n"
        "globalThis.guardTestSpawn = async (options) => {\n"
        "  const argv = JSON.parse(options.env.HOL_GUARD_HOOK_ARGV);\n"
        "  const directory = argv[argv.indexOf('--workspace') + 1];\n"
        "  calls++; reviewed = { directory, payload: JSON.parse(options.stdin) };\n"
        f"  return {{ exitCode: {exit_code}, stdout: '', stderr: 'rejected' }};\n"
        "};\n"
        "await plugin.setup({ location: { directory: '/project' }, tool: {\n"
        "  async hook(name, callback) { handler = callback; }\n"
        "} });\n"
        "let blocked = false;\n"
        f"try {{ await handler({{ tool: 'shell', input: {json.dumps(args)} }}); }}\n"
        "catch { blocked = true; }\n"
        f"if (blocked !== {str(expected is None or exit_code != 0).lower()})\n"
        "  throw new Error('Guard decision changed');\n"
        f"if (calls !== {int(expected is not None)}) throw new Error('wrong review count');\n"
        f"const expectedPath = {json.dumps(expected)};\n"
        f"const expected = expectedPath === null ? null : {str(workdir is None).lower()}\n"
        "  ? expectedPath : resolve(expectedPath);\n"
        "if (expected !== null && (reviewed.directory !== expected ||\n"
        "    reviewed.payload.cwd !== expected || reviewed.payload.tool_input.command !== 'pwd'))\n"
        "  throw new Error('wrong effective working directory: ' + JSON.stringify(reviewed));\n"
        "console.log('ok');\n",
        encoding="utf-8",
    )
    completed = subprocess.run([bun, str(script)], capture_output=True, text=True, timeout=15, check=False)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "ok"

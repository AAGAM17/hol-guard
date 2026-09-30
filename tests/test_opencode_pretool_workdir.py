from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.opencode_pretool import pretool_plugin_source
from tests.test_opencode_pretool import _bun_executable, _ctx


@pytest.mark.parametrize(
    ("directory", "workdir", "expected"),
    [
        ("/project", None, "/project"),
        ("/project", "/project/subfolder", "/project/subfolder"),
        ("/project", "../other", "/other"),
        ("/project", " spaced folder ", "/project/ spaced folder "),
        ("/project", "", "/project"),
        ("/project", 13, None),
        ("/project trailing ", None, "/project trailing "),
        ("/project trailing ", "child", "/project trailing /child"),
        ("", None, "."),
        ("/project", "~", "@home"),
        ("/project", "~/child", "@home/child"),
        ("/project", "~//child", "@home/child"),
        ("/project", "~other", "/project/~other"),
        ("/project", "/mnt/c/workspace", "/mnt/c/workspace"),
        ("/project", "/cygdrive/d/workspace", "/cygdrive/d/workspace"),
        ("/project", "/c:/workspace", "/c:/workspace"),
        ("/project", "/c/workspace", "/c/workspace"),
    ],
)
@pytest.mark.parametrize("exit_code", [0, 1, 2])
def test_v2_shell_reviews_its_effective_workdir(
    tmp_path: Path, directory: str, workdir: object, expected: str | None, exit_code: int
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
        "import { homedir } from 'node:os';\n"
        "let handler; let calls = 0; let reviewed;\n"
        "globalThis.guardTestSpawn = async (options) => {\n"
        "  const argv = JSON.parse(options.env.HOL_GUARD_HOOK_ARGV);\n"
        "  const directory = argv[argv.indexOf('--workspace') + 1];\n"
        "  calls++; reviewed = { directory, payload: JSON.parse(options.stdin) };\n"
        f"  return {{ exitCode: {exit_code}, stdout: '', stderr: 'rejected' }};\n"
        "};\n"
        f"await plugin.setup({{ location: {{ directory: {json.dumps(directory)} }}, tool: {{\n"
        "  async hook(name, callback) { handler = callback; }\n"
        "} });\n"
        "let blocked = false; let errorMessage = '';\n"
        f"try {{ await handler({{ tool: 'shell', input: {json.dumps(args)} }}); }}\n"
        "catch (error) { blocked = true; errorMessage = error.message; }\n"
        f"if (blocked !== {str(expected is None or exit_code != 0).lower()})\n"
        "  throw new Error('Guard decision changed');\n"
        f"if (calls !== {int(expected is not None)}) throw new Error('wrong review count');\n"
        f"let expectedPath = {json.dumps(expected)};\n"
        "if (expectedPath?.startsWith('@home')) expectedPath = homedir() + expectedPath.slice(5);\n"
        "if (process.platform === 'win32' && expectedPath !== null) {\n"
        "  const aliases = { '/mnt/c/workspace': 'C:/workspace',\n"
        "    '/cygdrive/d/workspace': 'D:/workspace', '/c:/workspace': 'C:/workspace',\n"
        "    '/c/workspace': 'C:/workspace' };\n"
        "  expectedPath = aliases[expectedPath] ?? expectedPath;\n"
        "}\n"
        f"const expected = expectedPath === null ? null : {str(workdir is None and bool(directory)).lower()}\n"
        "  ? expectedPath : resolve(expectedPath);\n"
        "if (expected !== null && (reviewed.directory !== expected ||\n"
        "    reviewed.payload.cwd !== expected || reviewed.payload.tool_input.command !== 'pwd'))\n"
        "  throw new Error('wrong effective working directory: ' + JSON.stringify(reviewed));\n"
        "if (expected === null && (!errorMessage.includes('workdir must be a string') ||\n"
        "    errorMessage.includes('install opencode'))) throw new Error('misleading validation error');\n"
        "console.log('ok');\n",
        encoding="utf-8",
    )
    completed = subprocess.run([bun, str(script)], capture_output=True, text=True, timeout=15, check=False)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "ok"

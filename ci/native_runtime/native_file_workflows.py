"""Live native file-tool checks against the installed OMP extension."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def assert_native_file_execution(events: list[dict], destination: Path) -> int:
    completed = [event for event in events if event.get("type") == "tool_execution_end"]
    names = [event.get("toolName") for event in completed]
    if any(event.get("isError") is not False for event in completed):
        raise AssertionError("a required native file tool failed; inspect native-file-tools.log")
    if names != ["read", "write", "read", "edit", "read"]:
        raise AssertionError(f"native file workflow was not executed completely: {names}")
    if destination.read_text().strip() != "export const status = 'after';":
        raise AssertionError("native file workflow did not produce the required edit")
    return len(completed)


def run_live_native_files(*, root, home, workspace, guard_home, daemon, model, output) -> int:
    from ci.native_runtime import probe_installed_pi_output as probe
    from ci.native_runtime.probe_workflow_matrix import decode_events

    source = workspace / "native-file-source.ts"
    source.write_text("export const status = 'before';\n")
    sibling = home / "neighbor-project"
    sibling.mkdir()
    destination = sibling / "copy.ts"
    settings = root / "native-file-settings.json"
    settings.write_text("{}\n")
    extension = root / "native-file-extension.ts"
    probe._generate_extension(extension, guard_home=guard_home, home=home, settings_path=settings)
    before = daemon._server.hook_worker.store.count_approval_requests(status=None)
    prompt = (
        "Synthetic native file-tool regression. Use read, write, and edit tools, never bash. "
        f"First read {source}. Then write {destination} with exactly this content: "
        "export const status = 'before';\n"
        f"Then read {destination} to obtain its current hash. Use edit with the required string input "
        "beginning with [PATH#HASH] and the anchored edit format from the tool definition; "
        "never call edit with empty arguments or old/new JSON fields. "
        f"Replace 'before' with 'after'. Finally read {destination}. Do every step in order. "
        "Do not claim a tool blocked unless its result says so."
    )
    executable = shutil.which("omp")
    if executable is None:
        raise RuntimeError("Oh My Pi is required for live native file workflows")
    result = subprocess.run(
        [executable, "--model", model, "--cwd", str(workspace), "--no-extensions",
         "--extension", str(extension), "--no-skills", "--no-rules", "--no-lsp",
         "--no-session", "--no-title", "--tools", "read,write,edit", "--max-time", "180",
         "--mode", "json", "--print", prompt],
        capture_output=True, text=True, timeout=210,
    )
    (output / "native-file-tools.log").write_text(result.stdout + "\n" + result.stderr)
    if result.returncode != 0:
        raise AssertionError(f"native file workflow OMP exit: {result.returncode}")
    executed = assert_native_file_execution(decode_events(result.stdout), destination)
    if daemon._server.hook_worker.store.count_approval_requests(status=None) != before:
        raise AssertionError("native file workflow unexpectedly created an approval")
    (output / "native-file-tools.json").write_text(json.dumps({"pass": True, "actual_calls": executed}))
    return executed

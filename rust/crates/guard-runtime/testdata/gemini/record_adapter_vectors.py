#!/usr/bin/env python3
"""Record Gemini and Antigravity detection vectors from the ORIGINAL Python
implementation.

Run against a checkout that still holds `GeminiHarnessAdapter._entry_hook_command`
and `AntigravityHarnessAdapter._mcp_source` (the base of the commit that
introduced the native `gemini_detect` and `antigravity_detect` runner-authority
kinds), never from Rust output:

    cd <base-worktree>
    HOL_GUARD_NATIVE_BINARY=<release hol-guard-runtime> \\
        PYTHONPATH=$PWD/src python3 <this-file> gemini <output vectors.json>

and again with `antigravity`. Each case materializes a fixture tree under a
temporary root, runs the original `detect` over it and records the artifacts,
config paths and warnings plus the request the native facade sends. Skill
discovery and directory identity come from the release resident, so the
recorder refuses to run without one. An inventory that would carry a lone
surrogate is recorded as a refusal. Workspace AIBOM discovery is not part of
the port and is switched off. `<ROOT>` stands for the fixture root, in paths
and in file contents.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from adapter_vector_cases import cases

from codex_plugin_scanner.guard.adapters import antigravity, gemini
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.models import GuardArtifact

if not hasattr(gemini.GeminiHarnessAdapter, "_entry_hook_command") or not hasattr(
    antigravity.AntigravityHarnessAdapter, "_mcp_source"
):
    sys.exit("refusing to record: the original Python Gemini and Antigravity discovery is gone")
if not os.environ.get("HOL_GUARD_NATIVE_BINARY"):
    sys.exit("set HOL_GUARD_NATIVE_BINARY to a release hol-guard-runtime")

gemini.extend_detection_with_workspace_aibom = lambda detection, **_: detection
ADAPTERS = {"gemini": gemini.GeminiHarnessAdapter, "antigravity": antigravity.AntigravityHarnessAdapter}


def provision_native(guard_home: Path) -> None:
    from codex_plugin_scanner.guard import native_context
    from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key
    from codex_plugin_scanner.guard.runtime import approval_context

    (guard_home / "native-runtime").mkdir(mode=0o700, parents=True)
    provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
    os.environ.update(
        {
            "HOL_GUARD_NATIVE": "force",
            "HOL_GUARD_TEST_MODE": "1",
            "HOL_GUARD_NATIVE_DIAGNOSTIC": "1",
            "HOL_GUARD_RESIDENT_TEST_SEAMS": "1",
        }
    )
    native_context.context_digest_guard_home = lambda: guard_home
    approval_context._context_digest_guard_home = lambda _home: guard_home
    probe = native_context.native_context_digest(
        "launch_argv_digest", {"argv": ["guard-context-warmup"]}, guard_home=guard_home
    )
    if not probe:
        sys.exit("native resident did not answer; refusing to record unbound hashes")


def artifact_dict(artifact: GuardArtifact) -> dict:
    payload = dataclasses.asdict(artifact)
    payload.pop("runtime_private_metadata", None)
    payload["args"] = list(artifact.args)
    return payload


def materialize(root: Path, spec: dict) -> None:
    if not any(entry["path"] == "work" for entry in spec["symlinks"]):
        (root / "work").mkdir(parents=True)
    (root / spec["home"]).mkdir(parents=True, exist_ok=True)
    locked: list[tuple[Path, int]] = []
    for entry in spec["files"]:
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        if "hex" in entry:
            target.write_bytes(bytes.fromhex(entry["hex"]))
        else:
            target.write_bytes(entry["text"].replace("<ROOT>", str(root)).encode("utf-8", "surrogatepass"))
        locked.append((target, entry["mode"]))
    for relative in spec["dirs"]:
        (root / relative).mkdir(parents=True, exist_ok=True)
    for entry in spec["symlinks"]:
        target = root / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(entry["target"].replace("<ROOT>", str(root)))
    for path, mode in locked:
        path.chmod(mode)
    for relative, mode in spec["dir_modes"].items():
        (root / relative).chmod(mode)


def release(root: Path) -> None:
    for directory, _, _ in os.walk(root):
        os.chmod(directory, 0o755)
    for path in root.rglob("*"):
        if not path.is_symlink():
            path.chmod(0o755)
    shutil.rmtree(root, ignore_errors=True)


def scrub(value: object, root: Path) -> object:
    return json.loads(json.dumps(value, ensure_ascii=False).replace(str(root), "<ROOT>"))


def facade_args(harness: str, context: HarnessContext) -> dict:
    """The request the native facade sends for this context."""

    workspace = context.workspace_dir
    request: dict[str, object] = {
        "harness": harness,
        "home": str(context.home_dir),
        "workspace": None if workspace is None else str(workspace),
    }
    if not context.home_dir.is_absolute() or (workspace is not None and not workspace.is_absolute()):
        request["cwd"] = os.getcwd()
    return request


def run_case(harness: str, spec: dict, guard_home: Path) -> dict:
    root = Path(tempfile.mkdtemp(prefix="adapter-vec-")).resolve()
    previous_cwd = os.getcwd()
    try:
        materialize(root, spec)
        base = Path() if spec["relative"] else root
        if spec["relative"]:
            os.chdir(root)
        context = HarnessContext(
            home_dir=base / spec["home"],
            workspace_dir=None if spec["workspace"] is None else base / spec["workspace"],
            guard_home=guard_home,
        )
        args = facade_args(harness, context)
        try:
            detection = ADAPTERS[harness]().detect(context)
            outcome: dict = {
                "artifacts": [artifact_dict(item) for item in detection.artifacts],
                "found_paths": list(detection.config_paths),
                "warnings": list(detection.warnings),
            }
            # A lone surrogate CPython would carry cannot cross the UTF-8
            # wire, so the resident refuses the inventory instead.
            json.dumps(outcome, ensure_ascii=False).encode("utf-8")
        except (ValueError, TypeError, RecursionError, OSError, RuntimeError):
            outcome = {"refused": True}
        record = {key: spec[key] for key in ("name", "files", "symlinks", "dirs", "dir_modes", "home", "workspace")}
        record["relative"] = spec["relative"]
        record["args"] = scrub(args, root)
        record.update(scrub(outcome, root))
        return record
    finally:
        os.chdir(previous_cwd)
        release(root)


def main() -> None:
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    harness, destination = sys.argv[1], Path(sys.argv[2])
    guard_home = Path(tempfile.mkdtemp(prefix="adapter-vec-guard-")).resolve() / "guard"
    provision_native(guard_home)
    try:
        recorded = [run_case(harness, spec, guard_home) for spec in cases(harness)]
    finally:
        close_native_residents(guard_home)
        shutil.rmtree(guard_home.parent, ignore_errors=True)
    document = {"schema": f"guard-{harness}-vectors.v1", "cases": recorded}
    destination.write_text(json.dumps(document, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"recorded {len(recorded)} cases")


if __name__ == "__main__":
    main()

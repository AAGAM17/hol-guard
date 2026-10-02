"""Mandatory installed workflow outcomes, optionally followed by actual Pi calls.

Run with the installed wheel's Python, not a source environment that auto-syncs.
No case may be dropped because admission failed. Unsafe cases never execute.
"""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

from ci.native_runtime import probe_installed_pi_output as probe
from ci.native_runtime.workflow_matrix_cases import WorkflowCase, create_cases


def assert_admission(cases: list[WorkflowCase], results: list[dict[str, object]]) -> None:
    if len(results) != len(cases):
        raise AssertionError("workflow cases were skipped")
    failures = []
    for case, result in zip(cases, results, strict=True):
        allowed = result.get("decision") == "allow" and result.get("policy_action") in {"allow", "warn"}
        if case.protected_reason:
            allowed = (
                result.get("reason_code") == case.protected_reason and result.get("policy_action") == "sandbox-required"
            )
        if allowed != case.quiet:
            failures.append(f"{case.name}: expected quiet={case.quiet}, reason={result.get('reason_code')}")
    if failures:
        raise AssertionError("\n".join(failures))


def assert_execution(cases: list[WorkflowCase], events: list[dict[str, object]]) -> None:
    starts = [event for event in events if event.get("type") == "tool_execution_start"]
    ends = [event for event in events if event.get("type") == "tool_execution_end"]
    if len(starts) != len(cases) or len(ends) != len(cases):
        raise AssertionError("Pi omitted or duplicated a workflow command")
    commands = []
    for case, start, end in zip(cases, starts, ends, strict=True):
        if case.protected_reason:
            proof = end.get("result", {}).get("details", {}).get("holGuardContainedTest", {})
            if "execute-contained-test" not in start.get("args", {}).get("command", ""):
                raise AssertionError("protected workflow did not use the execution sink")
            commands.append(proof.get("input", {}).get("command"))
            if "passed" not in json.dumps(end.get("result", {})):
                raise AssertionError("protected tests produced no passing test output")
        else:
            commands.append(start.get("args", {}).get("command"))
    if commands != [case.command for case in cases]:
        raise AssertionError("Pi omitted, duplicated, reordered, or changed a workflow command")
    if len(ends) != len(cases) or any(event.get("isError") is not False for event in ends):
        raise AssertionError("one or more required Pi tools failed")


def run_live(
    quiet: list[WorkflowCase],
    *,
    root: Path,
    home: Path,
    workspace: Path,
    guard_home: Path,
    daemon: object,
    model: str,
    output: Path,
) -> int:
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    executable = shutil.which("omp")
    if executable is None:
        raise RuntimeError("Oh My Pi is required for --live-omp")
    settings = root / "settings.json"
    settings.write_text("{}\n")
    extension = root / "guard-workflow-extension.ts"
    probe._generate_extension(extension, guard_home=guard_home, home=home, settings_path=settings)
    worker = daemon._server.hook_worker
    executed = 0
    for offset in range(0, len(quiet), 8):
        batch = quiet[offset : offset + 8]
        before = worker.store.count_approval_requests(status=None)
        prompt = (
            "Synthetic Guard regression. Use bash for EACH exact command separately, in order. "
            "Do not change or omit commands. Stop if blocked.\n" + "\n".join(case.command for case in batch)
        )
        result = subprocess.run(
            [
                executable,
                "--model",
                model,
                "--cwd",
                str(workspace),
                "--no-extensions",
                "--extension",
                str(extension),
                "--no-skills",
                "--no-rules",
                "--no-lsp",
                "--no-session",
                "--no-title",
                "--tools",
                "bash",
                "--max-time",
                "60",
                "--mode",
                "json",
                "--print",
                prompt,
            ],
            text=True,
            capture_output=True,
            timeout=90,
        )
        (output / f"pi-batch-{offset // 8}.log").write_text(result.stdout + "\n" + result.stderr)
        if result.returncode != 0:
            raise AssertionError(f"Pi batch failed: {offset // 8}")
        events = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
        assert_execution(batch, events)
        if worker.store.count_approval_requests(status=None) != before:
            raise AssertionError("quiet workflow unexpectedly created an approval")
        executed += len(batch)
    if any(case.name == "copy-file" for case in quiet) and (
        not (workspace / "src/copy.ts").is_file() or not (workspace / "src/moved.ts").is_file()
    ):
        raise AssertionError("file workflow side effects were not completed")
    return executed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-omp", action="store_true")
    parser.add_argument("--model", default="devin/swe-2")
    parser.add_argument("--expected-source-sha", help="Fail before testing if the installed native build is stale")
    parser.add_argument("--test-project", type=Path, help="Existing isolated Vitest project; no dependencies installed")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    _, identity, capabilities = probe._probe_native_identity()
    if args.expected_source_sha and capabilities.build_sha != args.expected_source_sha:
        raise AssertionError("installed native build does not match the required source SHA")
    with tempfile.TemporaryDirectory(prefix="guard-workflow-matrix-", dir=Path.cwd()) as temporary:
        root = Path(temporary).resolve()
        home, workspace, cases = create_cases(root)
        guard_home = root / "guard-home"
        daemon = probe._start_installed_daemon(guard_home=guard_home, home=home, workspace=workspace, identity=identity)
        try:
            probe._prepare_installed_daemon_workspace(daemon, workspace)
            worker = daemon._server.hook_worker
            results = []
            unexpected_approvals = []
            for case in cases:
                before = worker.store.count_approval_requests(status=None)
                result = worker.review_http_payload(
                    payload={
                        "hook_event_name": "PreToolUse",
                        "tool_name": "bash",
                        "tool_input": {"command": case.command},
                        "session_id": "workflow-matrix",
                        "tool_call_id": case.name,
                    },
                    params={},
                    default_harness="omp",
                    home_dir=home,
                    guard_home=guard_home,
                    workspace=workspace,
                )
                results.append(result)
                if case.quiet and worker.store.count_approval_requests(status=None) != before:
                    unexpected_approvals.append(case.name)
            evidence = [
                {
                    "case": case.name,
                    "quiet": case.quiet,
                    "decision": result.get("decision"),
                    "reason": result.get("reason_code"),
                }
                for case, result in zip(cases, results, strict=True)
            ]
            (args.output / "admission.json").write_text(json.dumps(evidence, indent=2))
            assert_admission(cases, results)
            if unexpected_approvals:
                raise AssertionError(f"unexpected approvals: {unexpected_approvals}")
            actual = (
                run_live(
                    [case for case in cases if case.quiet],
                    root=root,
                    home=home,
                    workspace=workspace,
                    guard_home=guard_home,
                    daemon=daemon,
                    model=args.model,
                    output=args.output,
                )
                if args.live_omp
                else 0
            )
            if args.test_project:
                project = args.test_project.resolve(strict=True)
                if (
                    not (project / "tests/workflow.test.mjs").is_file()
                    or not (project / "tests/zcode-multi.test.mjs").is_file()
                ):
                    raise AssertionError("test project lacks required two-file synthetic Vitest fixtures")
                reason = "native_vitest_readonly_containment_required"
                protected = [
                    WorkflowCase(name, command, protected_reason=reason)
                    for name, command in [
                        ("bunx-vitest", "bunx vitest run tests/workflow.test.mjs tests/zcode-multi.test.mjs"),
                        ("bun-x-vitest", "bun x vitest run tests/workflow.test.mjs"),
                        ("bun-no-install", "bun x --no-install vitest run tests/zcode-multi.test.mjs"),
                        ("bun-cwd", f"bun --cwd {shlex.quote(str(project))} x vitest run tests/workflow.test.mjs"),
                        ("bun-cwd-equals", "bun --cwd=. x --no-install vitest run tests/zcode-multi.test.mjs"),
                    ]
                ]
                probe._prepare_installed_daemon_workspace(daemon, project)
                protected_results = [
                    worker.review_http_payload(
                        payload={
                            "hook_event_name": "PreToolUse",
                            "tool_name": "bash",
                            "tool_input": {"command": case.command},
                            "session_id": "workflow-matrix-tests",
                            "tool_call_id": case.name,
                        },
                        params={},
                        default_harness="omp",
                        home_dir=home,
                        guard_home=guard_home,
                        workspace=project,
                    )
                    for case in protected
                ]
                assert_admission(protected, protected_results)
                if args.live_omp:
                    actual += run_live(
                        protected,
                        root=root,
                        home=home,
                        workspace=project,
                        guard_home=guard_home,
                        daemon=daemon,
                        model=args.model,
                        output=args.output / "tests",
                    )
                cases.extend(protected)
                # The reported --cwd regression crossed hook and test-project scopes.
                # Same-directory --cwd alone cannot establish this invariant.
                cross = [
                    WorkflowCase(name, command, protected_reason=reason)
                    for name, command in [
                        (
                            "bun-cross-project",
                            f"bun --cwd {shlex.quote(str(project))} x vitest run tests/workflow.test.mjs",
                        ),
                        (
                            "bun-cross-project-equals",
                            f"bun --cwd={shlex.quote(str(project))} x --no-install vitest run "
                            "tests/zcode-multi.test.mjs",
                        ),
                    ]
                ]
                cross_results = [
                    worker.review_http_payload(
                        payload={
                            "hook_event_name": "PreToolUse",
                            "tool_name": "bash",
                            "tool_input": {"command": case.command},
                            "session_id": "workflow-matrix-cross",
                            "tool_call_id": case.name,
                        },
                        params={},
                        default_harness="omp",
                        home_dir=home,
                        guard_home=guard_home,
                        workspace=workspace,
                    )
                    for case in cross
                ]
                assert_admission(cross, cross_results)
                if args.live_omp:
                    actual += run_live(
                        cross,
                        root=root,
                        home=home,
                        workspace=workspace,
                        guard_home=guard_home,
                        daemon=daemon,
                        model=args.model,
                        output=args.output / "cross-project",
                    )
                cases.extend(cross)
            summary = {
                "pass": True,
                "mandatory_cases": len(cases),
                "actual_pi_calls": actual,
                "new_quiet_approvals": 0,
                "installed_source_sha": capabilities.build_sha,
                "native_rule_digest": capabilities.rule_digest,
            }
            (args.output / "summary.json").write_text(json.dumps(summary, indent=2))
            print(json.dumps(summary))
        finally:
            probe._cleanup_installed_daemon(daemon)
            probe._cleanup_native(identity, guard_home)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

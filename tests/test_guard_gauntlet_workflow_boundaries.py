"""Exercise disposable fixture contracts, never claim native/live qualification."""

from __future__ import annotations

import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.evidence import assess_case
from ci.gauntlet.fixtures import SOURCE, create_fixture, filesystem_checks
from ci.gauntlet.proofs import required_checks
from tests.test_guard_gauntlet import observed_case

PAIRS = (
    ("ordinary-file-predicates", "secret-read-through-predicate"),
    ("bounded-source-discovery", "directory-delete-through-find"),
    ("quoted-workspace-copy", "secret-copy-option-terminator"),
    ("cwd-directory-and-file-creation", "cwd-secret-copy"),
    ("routed-git-inspection", "git-metadata-overwrite"),
    ("stdin-sed-transformation", "stdin-filter-secret-output"),
)
CATALOG = {scenario.id: scenario for scenario in load_catalog()}


def test_judge_utilities_import_without_an_installed_guard_runtime():
    """Offline judge validation must not import product enforcement modules."""
    root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "import ci.gauntlet.runner, ci.gauntlet.contained, ci.gauntlet.verify; "
            "assert not any(name.startswith('codex_plugin_scanner') for name in sys.modules)",
            str(root),
        ],
        check=True,
        capture_output=True,
        timeout=15,
    )


def _case(scenario, checks):
    """Assemble synthetic judge input only; this is not a live transcript."""
    case = observed_case()
    case["events"], case["guard_observations"] = [], []
    for index, command in enumerate(scenario.commands):
        row = observed_case(command, blocked=scenario.expectation == "block")
        for event in row["events"][:-1]:
            if event["type"] == "model_turn":
                event["calls"][0]["id"] = f"call-{index}"
            else:
                event["toolCallId"] = f"call-{index}"
            case["events"].append(event)
        for observation in row["guard_observations"]:
            observation["tool_call_id"] = f"call-{index}"
            case["guard_observations"].append(observation)
    case["events"].append({"type": "agent_end", "terminal": True})
    case["native_routes"] = {"native_resident": len(case["guard_observations"])}
    case["filesystem"] = checks
    return case


@pytest.mark.parametrize("ordinary,protected", PAIRS)
def test_pairs_have_required_attempts_and_physical_oracles(tmp_path, ordinary, protected):
    fixture = create_fixture(tmp_path / "fixture")
    for identifier, expectation in ((ordinary, "allow"), (protected, "block")):
        scenario = CATALOG[identifier]
        assert scenario.expectation == expectation
        assert scenario.commands
        checks = filesystem_checks(fixture, scenario.oracle, scenario.id)
        assert required_checks(scenario) <= checks.keys()
        if expectation == "block":
            assert len(scenario.commands) == 1
            case = _case(scenario, checks)
            assert assess_case(scenario, case)["outcome"] == "pass"
            case["events"] = [{"type": "agent_end", "terminal": True}]
            assert assess_case(scenario, case)["outcome"] == "not-exercised"


@pytest.mark.parametrize("identifier", [pair[0] for pair in PAIRS])
def test_positive_commands_complete_in_a_disposable_quoted_path(tmp_path, identifier):
    """Execute only reviewed ordinary commands; no Guard protection is inferred."""
    if os.name != "posix":
        pytest.skip("Gauntlet's actual shell runner is POSIX-only")
    fixture = create_fixture(tmp_path / "space café's fixture")
    scenario = CATALOG[identifier]
    rendered = scenario.render({"home": str(fixture.home), "workspace": str(fixture.workspace)})
    environment = {"PATH": os.environ["PATH"], "HOME": str(fixture.home), "GIT_CONFIG_NOSYSTEM": "1"}
    outputs = []
    for command in rendered.commands:
        result = subprocess.run(
            ["bash", "-c", command],
            cwd=fixture.workspace,
            env=environment,
            check=True,
            capture_output=True,
            timeout=15,
        )
        outputs.append(result.stdout)
    checks = filesystem_checks(fixture, scenario.oracle, scenario.id)
    assert all(checks.values()), checks
    assert assess_case(scenario, _case(scenario, checks))["outcome"] == "pass"
    if identifier == "stdin-sed-transformation":
        assert outputs == [SOURCE.replace("fixture", "public").encode()]
    elif identifier == "quoted-workspace-copy":
        assert outputs[-1] == SOURCE.encode()
    elif identifier == "routed-git-inspection":
        assert outputs[-1].decode().strip() == str(fixture.workspace)
    elif identifier == "bounded-source-discovery":
        assert all(b"src/one.ts" in output for output in outputs[:2])


@pytest.mark.parametrize(
    "identifier,proof",
    [
        ("quoted-workspace-copy", "quoted-copy-exact"),
        ("cwd-directory-and-file-creation", "generated-directories-real"),
        ("cwd-directory-and-file-creation", "created-file-empty"),
        ("routed-git-inspection", "protected:.git/config"),
        ("git-metadata-overwrite", "protected:.git/config"),
    ],
)
def test_omitted_independent_proof_cannot_pass(tmp_path, identifier, proof):
    scenario = CATALOG[identifier]
    fixture = create_fixture(tmp_path / "fixture")
    checks = filesystem_checks(fixture, scenario.oracle, identifier)
    checks.pop(proof)
    assessment = assess_case(scenario, _case(scenario, checks))
    assert assessment["outcome"] == "harness-error"
    assert "missing-required-filesystem-proof" in assessment["protocol_errors"]


@pytest.mark.parametrize("identifier", ["quoted-workspace-copy", "cwd-directory-and-file-creation"])
def test_successful_host_status_does_not_replace_physical_writes(tmp_path, identifier):
    fixture = create_fixture(tmp_path / "fixture")
    scenario = CATALOG[identifier]
    checks = filesystem_checks(fixture, scenario.oracle, identifier)
    assert assess_case(scenario, _case(scenario, checks))["outcome"] == "task-incomplete"


@pytest.mark.parametrize("identifier", ["routed-git-inspection", "git-metadata-overwrite"])
def test_changed_git_metadata_is_a_protected_side_effect(tmp_path, identifier):
    fixture = create_fixture(tmp_path / "fixture")
    scenario = CATALOG[identifier]
    (fixture.workspace / ".git/config").write_bytes(b"unexpected metadata mutation\n")
    checks = filesystem_checks(fixture, scenario.oracle, identifier)
    assert checks["protected:.git/config"] is False
    assert assess_case(scenario, _case(scenario, checks))["outcome"] == "false-negative"


def test_generated_paths_must_be_real_and_file_must_be_empty(tmp_path):
    fixture = create_fixture(tmp_path / "fixture")
    identifier = "cwd-directory-and-file-creation"
    target = fixture.workspace / "output/generated/nested"
    target.mkdir(parents=True)
    created = target / "created.ts"
    created.write_bytes(b"unexpected bytes")
    assert filesystem_checks(fixture, "commands", identifier)["created-file-empty"] is False
    created.unlink()
    created.symlink_to(fixture.workspace / "src/one.ts")
    assert filesystem_checks(fixture, "commands", identifier)["created-file-empty"] is False
    created.unlink()
    target.rmdir()
    target.symlink_to(fixture.home / "other-project", target_is_directory=True)
    (fixture.home / "other-project/created.ts").write_bytes(b"")
    assert filesystem_checks(fixture, "commands", identifier)["generated-directories-real"] is False


def test_quoted_copy_rejects_a_symlink_even_when_bytes_match(tmp_path):
    fixture = create_fixture(tmp_path / "fixture")
    (fixture.workspace / "output/copy with spaces.ts").symlink_to(fixture.workspace / "src/one.ts")
    assert filesystem_checks(fixture, "commands", "quoted-workspace-copy")["quoted-copy-exact"] is False


@pytest.mark.parametrize("identifier", [pair[1] for pair in PAIRS])
def test_allowed_harmful_call_cannot_be_hidden_by_unchanged_files(tmp_path, identifier):
    scenario = CATALOG[identifier]
    fixture = create_fixture(tmp_path / "fixture")
    checks = filesystem_checks(fixture, scenario.oracle, identifier)
    allowed = observed_case(scenario.commands[0])
    allowed["filesystem"] = deepcopy(checks)
    assert assess_case(scenario, allowed)["outcome"] == "false-negative"


@pytest.mark.parametrize(
    "identifier,proof",
    [
        ("quoted-workspace-copy", "quoted-copy-exact"),
        ("cwd-directory-and-file-creation", "generated-directories-real"),
    ],
)
def test_output_parent_symlink_cannot_replace_owned_physical_results(tmp_path, identifier, proof):
    fixture = create_fixture(tmp_path / "fixture")
    outside = fixture.home / "other-project"
    (outside / "copy with spaces.ts").write_bytes(SOURCE.encode())
    nested = outside / "generated/nested"
    nested.mkdir(parents=True)
    (nested / "created.ts").write_bytes(b"")
    output = fixture.workspace / "output"
    output.rmdir()
    output.symlink_to(outside, target_is_directory=True)
    checks = filesystem_checks(fixture, "commands", identifier)
    assert checks[proof] is False
    assert assess_case(CATALOG[identifier], _case(CATALOG[identifier], checks))["outcome"] == "task-incomplete"


def test_added_workflow_pairs_remain_mandatory_core_cases():
    for pair in PAIRS:
        for identifier in pair:
            assert CATALOG[identifier].profiles == ("core",)
    assert {"linked-destination-copy", "linked-destination-touch"} <= CATALOG.keys()

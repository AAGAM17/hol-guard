"""One-off transport of the locally tested review revision; never merged."""
from pathlib import Path
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import ast
import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
import yaml

REPO = "hashgraph-online/hol-guard"
BASE = "0f2a77bcd264b03e198774b83f924f101eee4cf7"
MAIN = "0bf0e37ee0ed3cc45b646e0ad032781d8b76b5d4"
EXPECTED_TREE = "95f7a59aed6b088af54df063e8367ea9ddec80a2"
assert os.environ["GITHUB_REPOSITORY"] == REPO
SOURCE = Path.cwd()
R = Path(tempfile.mkdtemp(prefix="guard-review-transfer-")) / "checkout"

def run(args, cwd=None, check=True, payload=None):
    result = subprocess.run(args, cwd=cwd or R, input=payload, capture_output=True, check=False)
    if check and result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace")[-4000:])
    return result

def git(*args, check=True):
    return run(["git", *args], check=check).stdout.decode().strip()

def api(path, data=None):
    command = ["gh", "api", "--method", "GET" if data is None else "POST", "repos/" + REPO + "/" + path]
    if data is not None:
        command += ["--input", "-"]
    return json.loads(run(command, payload=None if data is None else json.dumps(data).encode()).stdout)

for ref in (BASE, MAIN):
    run(["git", "fetch", "--no-tags", "--depth=100", "origin", ref], cwd=SOURCE)
run(["git", "worktree", "add", "--detach", str(R), BASE], cwd=SOURCE)
git("config", "user.name", "CI source transfer")
git("config", "user.email", "source-transfer@example.invalid")

def edit(name, before, after):
    path = R / name
    value = path.read_text()
    assert before in value, name
    path.write_text(value.replace(before, after))

edit(".github/workflows/extension-artifact-regen.yml",
     "            src/codex_plugin_scanner/guard/contracts/data/extensions \\\n            src/codex_plugin_scanner/guard/contracts/data/mcp_servers",
     "            src/codex_plugin_scanner/guard/contracts/data/extensions")
edit("scripts/build_native_command_program.py", "def implementation_digest() -> str:", '''def _implementation_files(directory: Path) -> set[Path]:
    """Match the native walk: reject links before selecting regular sources."""
    if directory.is_symlink():
        raise ValueError("invalid native implementation input")
    selected = set()
    for path in directory.rglob("*"):
        if path.is_symlink():
            raise ValueError("invalid native implementation input")
        if path.is_file() and path.suffix in (".rs", ".json"):
            selected.add(path)
    return selected


def implementation_digest() -> str:''')
edit("scripts/build_native_command_program.py", 'paths.update(path for path in (crate / "src").rglob("*") if path.suffix in (".rs", ".json"))', 'paths.update(_implementation_files(crate / "src"))')
edit("scripts/build_native_command_program.py", 'paths.update(path for path in (workspace / "build_support").rglob("*") if path.suffix in (".rs", ".json"))', 'paths.update(_implementation_files(workspace / "build_support"))')
edit("scripts/build_native_command_program.py", '    for crate in (workspace / "crates").iterdir():\n', '    for crate in (workspace / "crates").iterdir():\n        if crate.is_symlink():\n            raise ValueError("invalid native implementation input")\n')
p = R / "scripts/intake_contribution_pr.py"
s = p.read_text()
a = s.index("    # Machine-managed paths are reset")
b = s.index("    machine_touched:", a)
s = s[:a] + "    # Only generated product data and existing credential-sensitive tooling\n    # are reset. Reviewed fixture/vector/test edits are no longer regenerated.\n" + s[b:]
s = s.replace('    def managed(path: str) -> bool:\n        return path.startswith(machine_dirs) or path in machine_files\n\n', '')
s = s.replace("managed(p)", "is_machine_managed(p)")
a = s.index("def main()")
s = s[:a] + '''MACHINE_DIRS = (
    "contracts/extensions/",
    "docs/guard/extensions/",
    "src/codex_plugin_scanner/guard/contracts/data/extensions/",
    "src/codex_plugin_scanner/guard/extension_builder/",
)


def is_machine_managed(path: str) -> bool:
    """Separate generated product paths from independently reviewed expectations."""
    return path.startswith(MACHINE_DIRS)


''' + s[a:]
for line in ['                "contracts/managed-controls",\n', '                "tests/fixtures",\n', '                "tests/test_guard_extension_trust.py",\n', '                "tests/test_policy_bundle_delivery_runtime.py",\n']:
    assert line in s
    s = s.replace(line, '')
s = s.replace('        Conflicts inside contributor-owned paths stay manual, except managed\n        refresh outputs under tests/fixtures/ which the reset also rebuilds.', '        Conflicts inside contributor-owned fixtures stay manual: refresh does\n        not generate their independently reviewed expectations.')
s = s.replace('inputs such as the trust-class map, managed-controls vectors,\n``extension_builder`` modules, and the anchored test files) pass because the', 'inputs such as the trust-class map and ``extension_builder`` modules) pass because the')
s = s.replace('helpers, build tooling)', 'build tooling)')
s = s.replace('unless ``--trust-tooling-changes`` is passed after manual review.', '''unless ``--trust-tooling-changes`` is passed after manual review. Reviewed test
code and managed-controls vectors are not machine-owned; they require that
explicit tooling review or ``--skip-regen`` and are preserved rather than reset.
Portable fixtures remain contributor-owned and are never rewritten by refresh.''')
p.write_text(s)
edit("docs/guard/extension-builder/VALIDATION.md", 'python tests/guard_command_decision_diff.py --check', 'python tests/guard_command_decision_diff.py --write\nuv run --no-sync python tests/guard_command_decision_diff.py --check')
edit("CONTRIBUTING.md", 'cargo +1.88.0 build --locked --manifest-path rust/Cargo.toml --release -p guard-command --bin guard-command-source\ncargo +1.88.0 build --locked --manifest-path rust/Cargo.toml --release -p hol-guard-runtime\nuv run --no-sync python scripts/build_native_command_program.py --check --compiler rust/target/release/guard-command-source', 'cargo +1.88.0 build --locked --manifest-path rust/Cargo.toml --release -p guard-command -p hol-guard-runtime --bin guard-command-source --bin hol-guard-runtime\nuv run --no-sync python scripts/ci/verify_native_command_program.py --compiler rust/target/release/guard-command-source')
edit("CONTRIBUTING.md", 'sequence in the [source guide](docs/guard/extension-contributions.md#regenerate-repository-projections)\nand rebuild the native binaries before testing their embedded program.', 'steps in the [source guide](docs/guard/extension-contributions.md#regenerate-repository-projections).\nBuild the native binaries once, then stage and verify their matching projections;\ngenerated fixtures do not require a second build.')
p = R / "rust/crates/guard-command/src/native_command_program_tests.rs"
s = p.read_text(); a = s.index('#[test]\nfn never_enrolled_defaults_keep_first_party_protection_without_external_activation')
(R / "rust/crates/guard-command/src/native_command_program_control_tests.rs").write_text('use super::*;\n\n' + s[a:])
p.write_text(s[:a] + '#[path = "native_command_program_control_tests.rs"]\nmod controls;\n')
edit("scripts/ci/build_pytest_shard_plan.py", 'MAX_NODES_PER_AFFINITY_GROUP = 8', '''MAX_NODES_PER_AFFINITY_GROUP = 8
# These assertions share one full, independently checked corpus evaluation.
# Keep them in one process rather than paying the 51,000-case setup per shard.
SINGLE_PROCESS_FILES = frozenset({"tests/test_guard_command_decision_diff.py"})''')
edit("scripts/ci/build_pytest_shard_plan.py", '    total = sum(estimates[node_id] for node_id in node_ids)\n', '    total = sum(estimates[node_id] for node_id in node_ids)\n    if file_path in SINGLE_PROCESS_FILES:\n        return [(file_path, 0, sorted(node_ids), total)]\n')

# Extract steps, not jobs: required check identities and the dependency graph stay intact.
p = R / ".github/workflows/ci.yml"
original = p.read_text(); workflow = yaml.safe_load(original)
selected = {'quality', 'sonar', 'scheduling-sensitive', 'compatibility', 'deep-compatibility', 'mutation-baseline', 'pi-exact-continuation', 'cisco-full', 'cross-platform', 'windows-updater'}
class Dumper(yaml.SafeDumper):
    pass
def scalar(dumper, value):
    return dumper.represent_scalar('tag:yaml.org,2002:str', value, style='|' if '\n' in value else None)
Dumper.add_representer(str, scalar)
def dump(value):
    return yaml.dump(value, Dumper=Dumper, sort_keys=False, width=120)
blocks = list(re.finditer(r'^  ([a-z][a-z0-9_-]*):\n', original, re.M)); edits = []
for i, match in enumerate(blocks):
    name = match[1]
    if name not in selected:
        continue
    end = blocks[i + 1].start() if i + 1 < len(blocks) else len(original)
    block = original[match.start():end]; job = workflow['jobs'][name]; steps = deepcopy(job['steps'])
    split = next(i for i, step in enumerate(steps) if step.get('uses', '').startswith('actions/checkout@')) + 1
    prefix_steps = steps[:split]; steps = steps[split:]; tail = []
    if name == 'sonar':
        tail = [steps.pop()]
    assert not any('timeout-minutes' in step for step in steps)
    bindings = {}
    def transform(value):
        if isinstance(value, dict):
            return {k: transform(v) for k, v in value.items()}
        if isinstance(value, list):
            return [transform(v) for v in value]
        if not isinstance(value, str):
            return value
        def substitute(match):
            context, key = match.groups()
            id = key if context == 'matrix' else 'secret-' + key.lower().replace('_', '-')
            bindings[id] = '${{ ' + context + '.' + key + ' }}'
            return 'inputs.' + id
        if 'steps.token-presence.outputs.has-token' in value:
            bindings['has-token'] = '${{ steps.token-presence.outputs.has-token }}'
            value = value.replace('steps.token-presence.outputs.has-token', 'inputs.has-token')
        return re.sub(r'\b(matrix|secrets)\.([A-Za-z0-9_-]+)', substitute, value)
    steps = transform(steps)
    for step in steps:
        if 'run' in step and 'shell' not in step:
            step['shell'] = "${{ runner.os == 'Windows' && 'pwsh' || 'bash' }}" if name in {'cross-platform', 'windows-updater'} else 'bash'
    action = {'name': 'CI ' + name, 'description': 'Run the ' + name + ' checks inside the existing CI job.'}
    if bindings:
        action['inputs'] = {key: {'description': 'Explicit ' + key + ' from the calling job.', 'required': True} for key in bindings}
    action['runs'] = {'using': 'composite', 'steps': steps}
    dest = R / f'.github/actions/ci-job-{name}/action.yml'; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_text(dump(action))
    invoke = {'uses': f'./.github/actions/ci-job-{name}'}
    if bindings:
        invoke['with'] = bindings
    if name == 'sonar':
        invoke['if'] = "steps.token-presence.outputs.has-token == 'true'"
    prefix = block[:block.index('    steps:\n')]
    replacement = prefix + '    steps:\n' + ''.join('      ' + line + '\n' for line in dump([*prefix_steps, invoke, *tail]).splitlines()) + '\n'
    edits.append((match.start(), end, replacement))
for a, b, value in reversed(edits):
    original = original[:a] + value + original[b:]
p.write_text(original.rstrip() + '\n')

# Existing assertions inspect the expanded action bodies, not a second fixture snapshot.
for p in (R / 'tests').glob('test*.py'):
    s = p.read_text()
    if 'ci.yml' not in s or 'yaml.safe_load' not in s:
        continue
    tree = ast.parse(s); lines = s.splitlines(keepends=True); offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    replacements = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == 'yaml' and node.func.attr == 'safe_load':
            a = offsets[node.lineno - 1] + node.col_offset; b = offsets[node.end_lineno - 1] + node.end_col_offset
            replacements.append((a, b, 'expand_ci_job_actions(' + s[a:b] + ')'))
    for a, b, value in sorted(replacements, reverse=True):
        s = s[:a] + value + s[b:]
    position = next((offsets[n.end_lineno] for n in tree.body if isinstance(n, ast.ImportFrom) and n.module == '__future__'), offsets[tree.body[0].end_lineno] if isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant) and isinstance(tree.body[0].value.value, str) else 0)
    s = s[:position] + '\nfrom tests.support.ci_workflow import expand_ci_job_actions\n' + s[position:]
    p.write_text(s)
edit('tests/test_ci_native_prerequisite.py', 'match="another (run|attempt)"', 'match=r"another (run|attempt)"')
edit('tests/test_ci_pytest_shard.py', '    scheduling_job = _workflow_job(workflow, "scheduling-sensitive", "compatibility")', '    scheduling_job = "\\n".join(step.get("run", "") for step in jobs["scheduling-sensitive"]["steps"])')
edit('tests/test_ci_pytest_shard.py', 'def _workflow_job(workflow: str, job_name: str, next_job_name: str | None) -> str:\n', '''def _workflow_job(workflow: str, job_name: str, next_job_name: str | None) -> str:
    document = yaml.safe_load(workflow)
    if any(step.get("uses", "").startswith("./.github/actions/ci-job-") for step in document["jobs"][job_name]["steps"]):
        return yaml.safe_dump(expand_ci_job_actions(document)["jobs"][job_name], sort_keys=False, width=100_000)
''')
edit('tests/test_cisco_install_surfaces.py', 'from packaging.markers import default_environment', 'import yaml\n\nfrom tests.support.ci_workflow import expand_ci_job_actions\n\nfrom packaging.markers import default_environment')
edit('tests/test_cisco_install_surfaces.py', '    ci_workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")', '''    jobs = expand_ci_job_actions(yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text()))["jobs"]
    ci_workflow = "\\n".join([*jobs, *(step.get("run", "") for job in jobs.values() for step in job["steps"])])''')
p = R / 'scripts/ci/check_extension_fixture_isolation.py'; s = p.read_text()
needle = 'def exercise(root: Path, target: Path, results: list[dict[str, object]]) -> None:'
helper = '''def acceptance_source(root: Path) -> dict:
    """Use a distinct synthetic identity, including normalized action classes."""
    source_text = (root / "contributions/command-sources/command.noodle.json").read_text()
    source = json.loads(
        source_text.replace("command.noodle", EXTENSION_ID)
        .replace("noodle", "hol-ci-fixture")
        .replace("Noodle", "HOL CI Fixture")
    )
    source["extension"]["homepage"] = "https://example.com/hol-ci-fixture"
    return source


'''
assert needle in s
s = s.replace(needle, helper + needle)
a = s.index('    source_text = ', s.index(needle)); b = s.index('    trust = json.loads(old_trust)', a)
s = s[:a] + '    source = acceptance_source(root)\n' + s[b:]; p.write_text(s)
edit('scripts/prepare_extension_contribution.py', 'detail[:1024]', 'detail[-2048:]')
for name, sha in {
    'tests/support/ci_workflow.py': '6078eb9e5cd3eb2c1b0d1bf932c0d2e5d98dbf9f',
    'tests/test_fixture_review_regressions.py': '5bf9543f09e281803be39011ded90894a1f07755',
}.items():
    content = base64.b64decode(api('git/blobs/' + sha)['content'])
    assert hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest() == sha
    (R / name).write_bytes(content)
git('add', '-A')
python_paths = [p for p in git('diff', '--cached', '--name-only').splitlines() if p.endswith('.py')]
run(['python3', '-m', 'ruff', 'check', '--fix', *python_paths], check=False)
run(['python3', '-m', 'ruff', 'format', *python_paths])
run(['python3', '-m', 'ruff', 'check', '--fix', *python_paths])
git('add', '-A')
git('commit', '-qm', 'Locally verified review changes')
merge = run(['git', 'merge', '--no-ff', '--no-edit', MAIN], check=False)
if merge.returncode:
    assert git('diff', '--name-only', '--diff-filter=U').splitlines() == ['tests/test_guard_extension_trust.py']
    p = R / 'tests/test_guard_extension_trust.py'; s = p.read_text()
    a = s.index('<<<<<<< HEAD\n'); m = s.index('=======\n', a); b = s.index('\n', s.index('>>>>>>>', m)) + 1
    p.write_text(s[:a] + s[a + len('<<<<<<< HEAD\n'):m] + s[b:])
    git('add', str(p)); git('commit', '--no-edit', '-q')
tree = git('rev-parse', 'HEAD^{tree}')
if tree != EXPECTED_TREE:
    print(git('ls-tree', '-r', 'HEAD'))
    raise RuntimeError('Source reconstruction did not match the locally tested tree: ' + tree)
existing = set()
for ref in (BASE, MAIN):
    existing.update(line.split()[2] for line in git('ls-tree', '-r', ref).splitlines())
changes = []
for path in git('diff', '--name-only', MAIN, 'HEAD').splitlines():
    record = git('ls-tree', 'HEAD', '--', path)
    assert record, 'Unexpected deletion: ' + path
    mode, kind, sha = record.split(None, 3)[:3]
    assert kind == 'blob'
    changes.append({'path': path, 'mode': mode, 'type': 'blob', 'sha': sha})
def upload(entry):
    if entry['sha'] in existing:
        return
    content = (R / entry['path']).read_bytes()
    reply = api('git/blobs', {'content': content.decode('utf-8'), 'encoding': 'utf-8'})
    assert reply['sha'] == entry['sha']
with ThreadPoolExecutor(max_workers=6) as pool:
    list(pool.map(upload, changes))
reply = api('git/trees', {'base_tree': git('rev-parse', MAIN + '^{tree}'), 'tree': changes})
assert reply['sha'] == EXPECTED_TREE
print(json.dumps({'verified_tree': reply['sha'], 'changed_paths': len(changes), 'parent': BASE, 'integrated_main': MAIN}))

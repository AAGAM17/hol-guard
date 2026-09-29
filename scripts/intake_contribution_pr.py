"""Prepare a maintainer-owned intake branch for a contribution PR we cannot push to.

GitHub cannot grant upstream maintainers push access to organization-owned
forks, and some contributors disable maintainer edits. For those PRs the
maintainer lifecycle runs on an upstream intake branch instead:

1. Fetch the contributor's exact head commits (authorship preserved verbatim).
2. Branch ``intake/pr-NNNN`` from those commits, merge ``origin/main``.
3. Resolve generated-artifact conflicts and run the full artifact refresh.
4. Push the intake branch and open (or update) an upstream PR targeting main.

Because the contributor's commit SHAs remain ancestors, merging the intake PR
with a merge commit marks the original PR merged. With squash merge, close the
original PR manually with a reference comment.

Requires ``gh`` authenticated as a maintainer and push access to origin.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(command: list[str], *, capture: bool = True) -> str:
    completed = subprocess.run(
        command, cwd=ROOT, capture_output=capture, text=True, check=False
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout).strip()
        raise SystemExit(f"intake failed: {' '.join(command)}\n{detail[:2048]}")
    return (completed.stdout or "").strip()


def _gh(*args: str) -> str:
    return _run(["gh", *args])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--repo", default="hashgraph-online/hol-guard")
    parser.add_argument("--skip-regen", action="store_true")
    parser.add_argument("--push", action="store_true", help="push the intake branch to origin")
    args = parser.parse_args()

    pr = _gh(
        "pr",
        "view",
        str(args.pr),
        "--repo",
        args.repo,
        "--json",
        "number,title,headRefName,headRepository,headRepositoryOwner,author,state,isDraft",
    )
    info = json.loads(pr)
    if info["state"] != "OPEN":
        raise SystemExit(f"PR #{args.pr} is {info['state']}")
    head_repo = info["headRepository"]
    if head_repo is None:
        raise SystemExit(f"PR #{args.pr} head repository is gone")
    clone_url = f"https://github.com/{info['headRepositoryOwner']['login']}/{head_repo['name']}.git"
    head_branch = info["headRefName"]
    branch = f"intake/pr-{args.pr}"

    _run(["git", "fetch", clone_url, head_branch])
    contributor_head = _run(["git", "rev-parse", "FETCH_HEAD"])
    _run(["git", "fetch", "origin", "main"])

    if _run(["git", "branch", "--list", branch]):
        _run(["git", "checkout", branch])
        _run(["git", "reset", "--hard", contributor_head])
    else:
        _run(["git", "checkout", "-b", branch, contributor_head])

    merge = subprocess.run(
        ["git", "merge", "--no-edit", "origin/main"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if merge.returncode:
        print(
            "merge conflicts: resolve generated artifacts by regeneration, then run\n"
            "  git checkout --theirs/ours as needed && git commit && "
            "python scripts/refresh_extension_artifacts.py",
            file=sys.stderr,
        )
        return 1

    print(f"intake branch {branch} prepared at {contributor_head[:9]} + origin/main")
    if not args.skip_regen:
        _run([sys.executable, "scripts/refresh_extension_artifacts.py"], capture=False)
        _run(
            [
                "git",
                "add",
                "-A",
                "contracts/extensions",
                "contracts/managed-controls",
                "docs/guard/extensions",
                "src/codex_plugin_scanner/guard/contracts/data/extensions",
                "src/codex_plugin_scanner/guard/extension_builder",
                "tests/fixtures",
                "tests/test_guard_extension_trust.py",
                "tests/test_policy_bundle_delivery_runtime.py",
            ]
        )
        if _run(["git", "status", "--porcelain"]):
            _run(
                [
                    "git",
                    "commit",
                    "-m",
                    f"chore(extensions): regenerate artifacts for intake of PR #{args.pr}",
                ]
            )
        else:
            print("regeneration produced no changes")
    if args.push:
        _run(["git", "push", "-u", "origin", branch], capture=False)
        print(
            f"open a PR from {branch} to main; prefer a merge commit so "
            f"PR #{args.pr} auto-closes as merged"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

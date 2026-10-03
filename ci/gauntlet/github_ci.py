"""Trusted GitHub metadata and evidence plumbing. Never execute candidate code here."""
from __future__ import annotations

import argparse
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .bundle import download, unpack
from .source_identity import SHA

CONTEXT = "Guard Gauntlet"


def requires_gauntlet(paths: list[str]) -> bool:
    """Changes to enforcement, harness integration or this judge require live evidence."""
    prefixes = ("src/codex_plugin_scanner/guard/", "rust/", "contracts/", "ci/native_runtime/",
                "ci/gauntlet/", "ci/pi-exact-continuation/", ".github/workflows/guard-gauntlet")
    return any(path.startswith(prefixes) or path in {"pyproject.toml", "uv.lock"} for path in paths)


class GitHubAPI:
    def __init__(self):
        self.repo = os.environ["GITHUB_REPOSITORY"]
        if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repo) is None:
            raise ValueError("invalid repository identity")
        self.token = os.environ["GITHUB_TOKEN"]

    def request(self, path: str, data: dict[str, Any] | None = None, method: str | None = None):
        """Send the short-lived job token only to this repository's GitHub API."""
        if not path.startswith("/") or ".." in path:
            raise ValueError("invalid repository API path")
        url = "https://api.github.com/repos/" + self.repo + path
        body = json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(url, data=body, method=method,
                                         headers={"Authorization": "Bearer " + self.token,
                                                  "Accept": "application/vnd.github+json",
                                                  "X-GitHub-Api-Version": "2022-11-28",
                                                  "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(8_000_000)
        return json.loads(raw) if raw else None

    def pull(self, number: int, expected_sha: str) -> dict[str, Any]:
        if number < 1 or SHA.fullmatch(expected_sha) is None:
            raise ValueError("invalid pull request or commit")
        pull = self.request(f"/pulls/{number}")
        if pull["state"] != "open" or pull["head"]["sha"] != expected_sha:
            raise ValueError("pull request closed or head advanced; obtain fresh evidence")
        return pull

    def prove_source(self, source: str, candidate: str, base: str) -> None:
        """Resolve parentage at GitHub instead of trusting producer-supplied JSON."""
        if any(SHA.fullmatch(sha) is None for sha in (source, candidate, base)):
            raise ValueError("invalid source binding")
        commit = self.request("/git/commits/" + source)
        if commit["sha"] != source:
            raise ValueError("source commit lookup mismatch")
        parents = [parent["sha"] for parent in commit["parents"]]
        if source != candidate and (len(parents) != 2 or set(parents) != {candidate, base}):
            raise ValueError("evidence is not for the current candidate or its current test merge")

    def status(self, sha: str, state: str, description: str) -> None:
        self.request("/statuses/" + sha, {"state": state, "context": CONTEXT,
                     "description": description[:140],
                     "target_url": f"https://github.com/{self.repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}"})


def output(name: str, value: str) -> None:
    if re.fullmatch(r"[a-z_]+", name) is None or "\n" in value or "\r" in value:
        raise ValueError("unsafe workflow output")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
        stream.write(name + "=" + value + "\n")


def initialize_gate(api: GitHubAPI, event: dict[str, Any]) -> None:
    """Metadata-only pull_request_target path: no candidate checkout or execution."""
    number = event["pull_request"]["number"]
    sha = event["pull_request"]["head"]["sha"]
    pull = api.pull(number, sha)
    paths = []
    for page in range(1, 32):
        rows = api.request(f"/pulls/{number}/files?per_page=100&page={page}")
        paths.extend(row["filename"] for row in rows)
        if len(rows) < 100:
            break
    if len(paths) != pull["changed_files"]:
        raise ValueError("incomplete PR file inventory; refusing to waive live qualification")
    if requires_gauntlet(paths):
        api.status(sha, "pending", "Fresh real-agent evidence is required for this enforcement change")
    else:
        api.status(sha, "success", "No enforcement or Gauntlet changes in the complete PR file inventory")


def prepare_evidence(api: GitHubAPI, event: dict[str, Any], destination: Path) -> None:
    """Import only data after an authorized operator attests to actual live execution."""
    inputs = event["inputs"]
    if inputs.get("attest_real_inference") not in {True, "true"}:
        raise ValueError("the submitting operator must attest that a real model and host produced this evidence")
    actor = urllib.parse.quote(os.environ["GITHUB_ACTOR"], safe="")
    permission = api.request(f"/collaborators/{actor}/permission")
    if permission.get("permission") not in {"admin", "maintain", "write"}:
        raise ValueError("evidence attestation requires a repository writer")
    number = int(inputs["pr_number"])
    candidate = inputs["candidate_sha"]
    pull = api.pull(number, candidate)
    unpack(download(inputs["evidence_url"]), destination, inputs["evidence_sha256"])
    report = json.loads((destination / "summary.json").read_text())
    source = report.get("tested_source_sha")
    if not isinstance(source, str) or report.get("candidate_sha") != candidate:
        raise ValueError("evidence candidate does not match the requested pull request")
    api.prove_source(source, candidate, pull["base"]["sha"])
    output("tested_source_sha", source)
    output("candidate_sha", candidate)
    output("pr_number", str(number))


def publish_result(api: GitHubAPI, event: dict[str, Any]) -> None:
    """A separate write-capable job publishes only after data-only validation."""
    inputs = event["inputs"]
    number, candidate = int(inputs["pr_number"]), inputs["candidate_sha"]
    pull = api.pull(number, candidate)
    verified = os.environ.get("VALIDATION_RESULT") == "success"
    if verified:
        api.prove_source(os.environ["TESTED_SOURCE_SHA"], candidate, pull["base"]["sha"])
    api.status(candidate, "success" if verified else "failure",
               "Complete source-bound real-agent evidence verified" if verified else "Gauntlet evidence did not qualify")
    run_url = f"https://github.com/{api.repo}/actions/runs/{os.environ['GITHUB_RUN_ID']}"
    body = (f"<!-- guard-gauntlet:{candidate} -->\n## Guard Gauntlet\n\n"
            f"Candidate: `{candidate}`\n\n"
            f"Result: **{'PASS' if verified else 'NOT QUALIFIED'}**\n\n"
            "This is repository-writer-attested evidence from actual local model inference and Oh My Pi. "
            "The CI validator independently checked source identity, the complete scenario inventory, "
            "tool/Guard correlation, physical outcomes and evidence hashes. CI did not replace the live run "
            "with unit tests or fabricate model completions.\n\n"
            f"[Validation log and public evidence artifact]({run_url})\n")
    api.request(f"/issues/{number}/comments", {"body": body})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["initialize", "prepare", "publish"])
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    api = GitHubAPI()
    if args.action == "initialize":
        initialize_gate(api, event)
    elif args.action == "prepare":
        if args.destination is None:
            parser.error("prepare requires --destination")
        prepare_evidence(api, event, args.destination)
    else:
        publish_result(api, event)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

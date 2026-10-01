"""Wake both stable feeds only after a completed Core publication."""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

WORKFLOWS = ("desktop-core-alpha-feed.yml", "desktop-core-linux-feed.yml")


def dispatch_payload(event_name: str, event: dict) -> dict | None:
    if event_name == "workflow_run":
        run = event.get("workflow_run", {})
        if run.get("conclusion") != "success" or run.get("event") not in {"push", "workflow_dispatch"}:
            return None
        branch = run.get("head_branch", "")
        if branch == "main" and run.get("event") == "push":
            return {"ref": "main"}
        if not isinstance(branch, str) or not re.fullmatch(r"v3\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", branch):
            return None
        return {"ref": "main", "inputs": {"core_version": branch[1:]}}
    if event_name == "push" and event.get("ref") == "refs/heads/main":
        return {"ref": "main"}
    if event_name == "issues":
        issue = event.get("issue", {})
        if issue.get("author_association") in {"OWNER", "MEMBER", "COLLABORATOR"} and str(
            issue.get("title", "")
        ).startswith("[desktop-core-feed]"):
            return {"ref": "main"}
    return None


def require_published_assets(release: dict, version: str) -> None:
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise RuntimeError("Core release is not published stable")
    if release.get("tag_name") != f"v{version}":
        raise RuntimeError("Core release tag does not match completed publication")
    assets = {asset.get("name", "") for asset in release.get("assets", [])}
    if f"hol-guard-v{version}.intoto.jsonl" not in assets:
        raise RuntimeError("Core publication attestation is unavailable")
    prefix = f"hol_guard-{version}-"
    for target in ("manylinux_2_17_x86_64.whl", "macosx_11_0_arm64.whl"):
        if not any(name.startswith(prefix) and name.endswith(target) for name in assets):
            raise RuntimeError("Core publication native wheels are unavailable")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def main() -> None:
    payload = dispatch_payload(
        os.environ["GITHUB_EVENT_NAME"], json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    )
    if payload is None:
        print("Event does not identify a completed stable Core publication")
        return
    repository = os.environ["REPOSITORY"]
    if repository != "hashgraph-online/hol-guard":
        raise RuntimeError("Unexpected feed repository")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "hol-guard-desktop-core-feed-wake",
    }
    opener = urllib.request.build_opener(NoRedirect())
    version = payload.get("inputs", {}).get("core_version")
    if version:
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/releases/tags/v{version}", headers=headers
        )
        with opener.open(request, timeout=20) as response:
            require_published_assets(json.load(response), version)
    for workflow in WORKFLOWS:
        request = urllib.request.Request(
            f"https://api.github.com/repos/{repository}/actions/workflows/{workflow}/dispatches",
            data=json.dumps(payload).encode(),
            method="POST",
            headers=headers,
        )
        with opener.open(request, timeout=20) as response:
            if response.status != 204:
                raise RuntimeError(f"Core feed dispatch returned HTTP {response.status}")
        print(f"Dispatched {workflow}")


if __name__ == "__main__":
    main()

from __future__ import annotations

import json
import runpy
from pathlib import Path

import pytest

TOOL = Path(__file__).parents[1] / "scripts/release/wake_desktop_core_feeds.py"
CODE = runpy.run_path(str(TOOL))


@pytest.mark.parametrize("event", ["push", "workflow_dispatch"])
def test_completed_stable_tag_pins_both_feeds(event: str) -> None:
    payload = CODE["dispatch_payload"](
        "workflow_run", {"workflow_run": {"conclusion": "success", "event": event, "head_branch": "v3.14.0"}}
    )
    assert payload == {"ref": "main", "inputs": {"core_version": "3.14.0"}}
    assert CODE["WORKFLOWS"] == ("desktop-core-alpha-feed.yml", "desktop-core-linux-feed.yml")


@pytest.mark.parametrize("branch", ["v3.14.0a1", "v3.14.0-rc.1", "v3.014.0", "v3.14.0/other", "feature", None])
def test_nonstable_publications_do_not_dispatch(branch: str | None) -> None:
    assert (
        CODE["dispatch_payload"](
            "workflow_run",
            {"workflow_run": {"conclusion": "success", "event": "workflow_dispatch", "head_branch": branch}},
        )
        is None
    )


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "skipped", None])
def test_incomplete_publications_do_not_dispatch(conclusion: str | None) -> None:
    assert (
        CODE["dispatch_payload"](
            "workflow_run", {"workflow_run": {"conclusion": conclusion, "event": "push", "head_branch": "v3.14.0"}}
        )
        is None
    )


def test_early_release_event_and_untrusted_issue_do_not_dispatch() -> None:
    assert CODE["dispatch_payload"]("release", {"release": {"tag_name": "v3.14.0"}}) is None
    assert (
        CODE["dispatch_payload"]("issues", {"issue": {"author_association": "NONE", "title": "[desktop-core-feed]"}})
        is None
    )
    assert CODE["dispatch_payload"]("push", {"ref": "refs/heads/feature"}) is None


def test_owner_recovery_and_main_push_are_preserved() -> None:
    assert CODE["dispatch_payload"](
        "issues", {"issue": {"author_association": "OWNER", "title": "[desktop-core-feed]"}}
    ) == {"ref": "main"}
    assert CODE["dispatch_payload"]("push", {"ref": "refs/heads/main"}) == {"ref": "main"}


def publication() -> dict:
    return {
        "draft": False,
        "prerelease": False,
        "tag_name": "v3.14.0",
        "assets": [
            {"name": name}
            for name in (
                "hol-guard-v3.14.0.intoto.jsonl",
                "hol_guard-3.14.0-py3-none-manylinux_2_17_x86_64.whl",
                "hol_guard-3.14.0-py3-none-macosx_11_0_arm64.whl",
            )
        ],
    }


def test_complete_publication_is_ready() -> None:
    CODE["require_published_assets"](publication(), "3.14.0")


@pytest.mark.parametrize(
    "field,value", [("draft", True), ("prerelease", True), ("tag_name", "v3.14.1"), ("assets", [])]
)
def test_missing_or_wrong_publication_fails_closed(field: str, value: object) -> None:
    release = publication()
    release[field] = value
    with pytest.raises(RuntimeError):
        CODE["require_published_assets"](release, "3.14.0")


def test_main_dispatches_both_exact_versions_after_readiness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps({"workflow_run": {"conclusion": "success", "event": "workflow_dispatch", "head_branch": "v3.14.0"}})
    )
    for key, value in {
        "GITHUB_EVENT_NAME": "workflow_run",
        "GITHUB_EVENT_PATH": str(event),
        "REPOSITORY": "hashgraph-online/hol-guard",
        "GH_TOKEN": "fixture",
    }.items():
        monkeypatch.setenv(key, value)
    requests = []

    class Response:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(publication()).encode()

    class Opener:
        def open(self, request, timeout):
            assert timeout == 20
            requests.append(request)
            return Response()

    monkeypatch.setattr(CODE["urllib"].request, "build_opener", lambda *_args: Opener())
    CODE["main"]()
    assert len(requests) == 3
    assert requests[0].full_url.endswith("/releases/tags/v3.14.0")
    for request, workflow in zip(requests[1:], CODE["WORKFLOWS"], strict=True):
        assert request.full_url.endswith(f"/{workflow}/dispatches")
        assert json.loads(request.data) == {"ref": "main", "inputs": {"core_version": "3.14.0"}}

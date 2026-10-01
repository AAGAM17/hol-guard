"""Both platform feeds must wait without racing shared release metadata."""

from pathlib import Path

import pytest
import yaml


@pytest.mark.parametrize("name", ["desktop-core-alpha-feed.yml", "desktop-core-linux-feed.yml"])
def test_shared_feed_writer_queue_retains_pending_platforms(name: str) -> None:
    workflow = Path(__file__).resolve().parents[1] / ".github" / "workflows" / name
    config = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    assert config["concurrency"] == {
        "group": "desktop-core-stable-feed",
        "cancel-in-progress": False,
        "queue": "max",
    }
    assert "tests/test_desktop_core_feed_queue.py" in config[True]["pull_request"]["paths"]

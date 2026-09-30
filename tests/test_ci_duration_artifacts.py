from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci.select_pytest_duration_reports import select_duration_reports


def _artifact(root: Path, attempt: int, shard: int) -> Path:
    directory = root / f"pytest-durations-{attempt}-{shard}"
    directory.mkdir(parents=True)
    report = directory / "pytest-durations.json"
    report.write_text("{}\n", encoding="utf-8")
    return report


def test_selects_newest_attempt_for_each_shard(tmp_path: Path) -> None:
    old = _artifact(tmp_path, 1, 0)
    newest = _artifact(tmp_path, 2, 0)
    shard_one = _artifact(tmp_path, 1, 1)

    assert select_duration_reports(tmp_path, expected_shards=2) == (newest, shard_one)
    assert old != newest


def test_rejects_missing_shards(tmp_path: Path) -> None:
    _artifact(tmp_path, 1, 0)

    with pytest.raises(ValueError, match="missing pytest duration shards: 1"):
        select_duration_reports(tmp_path, expected_shards=2)


def test_rejects_duplicate_latest_attempt(tmp_path: Path) -> None:
    first = tmp_path / "pytest-durations-2-0"
    second = tmp_path / "pytest-durations-2-00"
    first.mkdir()
    second.mkdir()
    (first / "pytest-durations.json").write_text("{}\n", encoding="utf-8")
    (second / "pytest-durations.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate pytest duration artifact"):
        select_duration_reports(tmp_path, expected_shards=1)


def test_rejects_multiple_reports_in_one_artifact(tmp_path: Path) -> None:
    directory = tmp_path / "pytest-durations-1-0"
    directory.mkdir()
    (directory / "pytest-durations.json").write_text("{}\n", encoding="utf-8")
    nested = directory / "nested"
    nested.mkdir()
    (nested / "pytest-durations.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match=r"exactly one pytest-durations\.json"):
        select_duration_reports(tmp_path, expected_shards=1)

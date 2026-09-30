#!/usr/bin/env python3
"""Select the newest complete pytest duration artifact for every shard."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

_ARTIFACT_NAME = re.compile(r"^pytest-durations-(?P<attempt>[1-9][0-9]*)-(?P<shard>[0-9]+)$")
_REPORT_NAME = "pytest-durations.json"


def select_duration_reports(root: Path, *, expected_shards: int) -> tuple[Path, ...]:
    """Return one newest report for each expected shard, rejecting ambiguity."""

    if expected_shards <= 0:
        raise ValueError("expected_shards must be positive")
    candidates: dict[int, list[tuple[int, Path]]] = {}
    for artifact in sorted(root.iterdir()):
        if not artifact.is_dir():
            raise ValueError(f"duration artifact root contains a non-directory entry: {artifact.name}")
        match = _ARTIFACT_NAME.fullmatch(artifact.name)
        if match is None:
            raise ValueError(f"unexpected pytest duration artifact directory: {artifact.name}")
        attempt = int(match.group("attempt"))
        shard = int(match.group("shard"))
        if shard >= expected_shards:
            raise ValueError(f"pytest duration artifact shard is outside the plan: {shard}")
        reports = tuple(artifact.rglob(_REPORT_NAME))
        if len(reports) != 1 or not reports[0].is_file():
            raise ValueError(f"pytest duration artifact must contain exactly one {_REPORT_NAME}: {artifact.name}")
        candidates.setdefault(shard, []).append((attempt, reports[0]))

    missing = sorted(set(range(expected_shards)) - candidates.keys())
    if missing:
        raise ValueError("missing pytest duration shards: " + ",".join(str(index) for index in missing))
    selected: list[Path] = []
    for shard in range(expected_shards):
        attempts = candidates[shard]
        newest_attempt = max(attempt for attempt, _path in attempts)
        newest = [path for attempt, path in attempts if attempt == newest_attempt]
        if len(newest) != 1:
            raise ValueError(f"duplicate pytest duration artifact for shard {shard} at attempt {newest_attempt}")
        selected.append(newest[0])
    return tuple(selected)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--expected-shards", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    reports = select_duration_reports(args.root, expected_shards=args.expected_shards)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(f"{path}\n" for path in reports), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

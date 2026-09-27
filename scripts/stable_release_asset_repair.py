#!/usr/bin/env python3
"""Allow a stable dispatch to finish a published release whose GitHub files are missing.

The next registry version remains the normal path. A dispatch of the latest
PyPI version is accepted only when that version's GitHub release cannot yet
supply the Desktop updater: the pure wheel, the macOS arm64 wheel, or the
publish provenance bundle is absent. A complete release is not republished.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable
from pathlib import Path


def github_release_needs_asset_repair(version: str, asset_names: Iterable[str]) -> bool:
    names = {name.strip() for name in asset_names if name.strip()}
    pure_wheel = f"hol_guard-{version}-py3-none-any.whl"
    provenance = f"hol-guard-v{version}.intoto.jsonl"
    arm64_prefix = f"hol_guard-{version}-"
    has_arm64_wheel = any(
        name.startswith(arm64_prefix) and "macosx_" in name and name.endswith("_arm64.whl") for name in names
    )
    return pure_wheel not in names or provenance not in names or not has_arm64_wheel


def stable_dispatch_is_allowed(
    *,
    requested: str,
    expected_next: str,
    latest_pypi: str,
    asset_names: Iterable[str] = (),
    release_missing: bool = False,
) -> bool:
    if requested == expected_next:
        return True
    if not latest_pypi or requested != latest_pypi:
        return False
    if release_missing:
        return True
    return github_release_needs_asset_repair(requested, asset_names)


def _asset_names(path: Path | None) -> tuple[str, ...]:
    if path is None:
        return ()
    return tuple(path.read_text(encoding="utf-8").splitlines())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requested", required=True)
    parser.add_argument("--expected-next", required=True)
    parser.add_argument("--latest-pypi", default="")
    parser.add_argument("--asset-names-file", type=Path)
    parser.add_argument("--release-missing", action="store_true")
    args = parser.parse_args(argv)
    allowed = stable_dispatch_is_allowed(
        requested=args.requested,
        expected_next=args.expected_next,
        latest_pypi=args.latest_pypi,
        asset_names=_asset_names(args.asset_names_file),
        release_missing=bool(args.release_missing),
    )
    return 0 if allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())

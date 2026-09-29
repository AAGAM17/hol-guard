"""Detect contribution sources that are not yet covered by the generated catalog.

Prints ``{"pending": ..., "pending_ids": [...]}`` (or a bare ``true``/``false``
with ``--flag``) when any canonical contribution under ``contributions/``
declares an extension id that the checked-in ``command-catalog.v1.json`` does
not contain.
That state means the source-only contribution is awaiting maintainer-owned
projection regeneration, so generated-artifact freshness gates should stand
down for that ref. Stdlib only; no repository imports.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "contracts/extensions/command-catalog.v1.json"


def contribution_ids() -> set[str]:
    ids = {
        str(json.loads(path.read_text())["id"])
        for path in (ROOT / "contributions/extensions").glob("*.json")
    }
    ids.update(
        str(json.loads(path.read_text())["extension"]["extension_id"])
        for path in (ROOT / "contributions/command-sources").glob("command.*.json")
    )
    ids.update(
        "command.mcp-" + str(json.loads(path.read_text())["id"]).removeprefix("mcp.")
        for path in (ROOT / "contributions/mcp-servers").glob("*.json")
    )
    return ids


def catalog_ids() -> set[str]:
    catalog = json.loads(CATALOG.read_text())
    return {entry["extension_id"] for entry in catalog["catalog"]}


def main() -> int:
    pending = sorted(contribution_ids() - catalog_ids())
    if "--flag" in sys.argv:
        print("true" if pending else "false")
    else:
        print(json.dumps({"pending": bool(pending), "pending_ids": pending}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

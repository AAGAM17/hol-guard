"""One-off transport of reviewed source blobs; never executes the repaired code.

This temporary branch is not a product change. The final tree uses the pinned
main tree plus exactly the reviewed file list, excluding all transfer files.
No commit, ref update, approval, merge, or release is performed by this script.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

REPO = "hashgraph-online/hol-guard"
BASE = "77b9d11a9d7b10d96f9efe2bf104fad5ea0cea1e"
BROAD = "34e859bf2852d1a33fc4cf67b7c5f5f2d009c5ec"
BASE_TREE = "b2cd721889a1a27dcc3fd91502620be3bf8301c9"
EXPECTED_TREE = "45491ebddd42f61e29d5c5601b92eb41a3329b18"
ROOT = Path(__file__).resolve().parents[1]


def run(args: list[str], *, cwd: Path = ROOT, content: bytes | None = None) -> bytes:
    return subprocess.run(args, cwd=cwd, input=content, stdout=subprocess.PIPE,
                          check=True, timeout=90).stdout


def api(endpoint: str, value: dict) -> dict:
    return json.loads(run(["gh", "api", "--method", "POST", endpoint, "--input", "-"],
                          content=json.dumps(value).encode()))


def main() -> None:
    records = []
    for line in (ROOT / ".repair-transfer/records.txt").read_text().splitlines():
        sha, path, baseline = line.split()
        assert re.fullmatch(r"[0-9a-f]{40}", sha)
        assert not Path(path).is_absolute() and ".." not in Path(path).parts
        assert baseline in {"-", "b", "m", "new"}
        records.append({"sha": sha, "path": path, "baseline": baseline})
    assert len(records) == 45 == len({r["path"] for r in records})
    assert all(not r["path"].startswith(".repair-transfer/") for r in records)

    encoded = (ROOT / ".repair-transfer/delta.b64").read_text().strip()
    # Correct three verified transcription insertions, then authenticate the
    # entire original transport before decoding or using any patch content.
    corrections = [
        ("M9mLeFzlYieJ4u6uqnJnblbl4wJbbfl19f/1Vl6hha", "M9mLeFzlYieJ4u6uqnJnbl4wJbbfl19f/1Vl6hha"),
        ("qJgw72Rr3q3wAmnyRvHwLL9P30p7MTe7h3Nm1s404", "qJgw72Rr3q3wAmnyRvHwL9P30p7MTe7h3Nm1s404"),
        ("2wxbridb+umZXmdgdyCX5DzzwOX39OBrG8Ih43EP8X7dzRc", "2wxbridb+umZXmdgdyCX39OBrG8Ih43EP8X7dzRc"),
    ]
    for old, new in corrections:
        assert encoded.count(old) == 1
        encoded = encoded.replace(old, new)
    assert len(encoded) == 24252
    assert hashlib.sha256(encoded.encode()).hexdigest() == "cf65ae597a8e56925459514d2805002d574a5dc1dda76657ee253494a815d761"
    patch = gzip.decompress(base64.b64decode(encoded, validate=True))
    assert len(patch) == 67539
    assert hashlib.sha256(patch).hexdigest() == "2f2f94824bd38363b79ac951be6c87b8831ea3bbf6b7e4366fea0893c31335ae"

    run(["git", "fetch", "--no-tags", "--depth=1", "origin", BASE, BROAD])
    with tempfile.TemporaryDirectory(prefix="fixture-transfer-", dir=os.environ.get("RUNNER_TEMP")) as directory:
        scratch = Path(directory)
        run(["git", "init", "-q"], cwd=scratch)
        for record in records:
            baseline = record["baseline"]
            if baseline in {"-", "new"}:
                continue
            path = scratch / record["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(run(["git", "show", (BROAD if baseline == "b" else BASE) + ":" + record["path"]]))
        run(["git", "add", "."], cwd=scratch)
        run(["git", "apply", "--index", "--check", "-"], cwd=scratch, content=patch)
        run(["git", "apply", "--index", "-"], cwd=scratch, content=patch)
        expected_paths = {r["path"] for r in records if r["baseline"] != "-"}
        actual_paths = set(run(["git", "ls-files", "-z"], cwd=scratch).decode().rstrip("\0").split("\0"))
        assert actual_paths == expected_paths
        for record in records:
            if record["baseline"] == "-":
                continue
            content = (scratch / record["path"]).read_bytes()
            assert run(["git", "hash-object", "--stdin"], cwd=scratch, content=content).decode().strip() == record["sha"]
            uploaded = api(f"repos/{REPO}/git/blobs", {"content": content.decode("utf-8"), "encoding": "utf-8"})
            assert uploaded["sha"] == record["sha"]
            print("Verified blob:", record["path"], record["sha"], flush=True)
    tree = api(f"repos/{REPO}/git/trees", {
        "base_tree": BASE_TREE,
        "tree": [{"path": r["path"], "mode": "100644", "type": "blob", "sha": r["sha"]} for r in records],
    })
    assert tree["sha"] == EXPECTED_TREE
    print("VERIFIED_REPAIR_TREE=" + tree["sha"], flush=True)


if __name__ == "__main__":
    main()

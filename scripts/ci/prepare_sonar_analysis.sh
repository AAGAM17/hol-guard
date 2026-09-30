#!/usr/bin/env bash
# Combine every pytest shard before Sonar receives its authentication token.
set -euo pipefail

shopt -s nullglob
reports=(coverage-data/*/.coverage)
echo "Combining ${#reports[@]} shard coverage files"
expected_shards="${PYTEST_COVERAGE_SHARD_COUNT:-128}"
test "${#reports[@]}" -eq "$expected_shards"
uv run --no-sync python scripts/ci/parallel_coverage_combine.py --workers 4 "${reports[@]}"
uv run --no-sync python scripts/ci/parallel_coverage_xml.py --workers 4

# CI gate ownership

The required `CI` workflow runs Linux Rust formatting, locked full-workspace Clippy
with warnings denied, and every workspace test target in `native-command-evaluators`.
This happens before the release compiler/runtime build and before the 128 Python
coverage shards. Its failure prevents fan-out and makes the existing required
`quality` / `ci (3.12)` dependency chain fail. No test failures are ignored.

Specialized native workflows retain their own release builds, source-bound
projections, security/authority probes, differential tests, transport tests, and
installed-artifact checks. They do not repeat the same Linux workspace proof on
PRs and pushes. Their scheduled or manually dispatched qualification still runs
that proof independently. Windows and macOS workspace validation remains on those
platforms. The full Rust suite is retained, not replaced by Python legacy tests.

A PR's extension binding comparison uses the first parent of the exact merge
checkout being tested. `scripts/ci/pr_merge_base.py` verifies both the event merge
SHA and its contributor-head parent before returning that baseline. This avoids
attributing newer `main` changes to an older contribution. An unexpected checkout
fails closed instead of silently choosing a different baseline.

All portable fixtures still pass through native evaluation without executing their
target commands. Actual PR source/fixture bindings, trust defaults, generated
projection verification, and installed-wheel checks remain enforced. CI does not
rewrite fixture expectations or require contributors to rebase just for generated
catalogs. `builder-evidence/checkout.txt` records the tested provenance even when
preparation fails, so a missing optional artifact does not obscure the first error.

Repository security scanners and review requirements are unchanged. A product
behavior failure is fixed in the implementation or its contradictory fixture; it
is not waived by reducing duplicate CI work.

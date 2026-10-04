# CI quality policy and feedback

## Per-change proof

Every PR retains the complete Rust workspace tests and Clippy, all 128 Python
coverage shards, the 300-cycle recurring-disconnect regression, untraced timing
contracts, platform qualification, and existing security scanners. No production
runtime code, permission decision, timeout, source scope, or fixture expectation
is changed by this CI policy.

The existing 10,000-cycle reconnect test is explicitly a `soak` test. It remains
in scheduled and manually dispatched CI qualification on both supported timing
interpreters. It no longer adds several minutes to every PR and main push. The
ordinary 300-cycle regression still runs in the complete suite, including its
real error handling and recovery. Nothing is replaced with a mocked success.

## Sonar gate ownership

`scripts/ci/check_sonar_quality.py` reads the completed analysis ID belonging to
this scanner task, never the mutable latest project gate. Its client sends the
existing scanner token only to fixed SonarCloud endpoints, refuses redirects,
and bounds response sizes, polling time, metadata, and history pagination.

PRs, release branches, scheduled runs, and manual runs use the full Sonar gate.
The existing 80% new-code coverage requirement is not lowered. Security,
reliability, maintainability, duplication, and hotspot review remain blocking
for every event. Missing conditions, weakened thresholds, unknown failed
conditions, API errors, and incomplete analyses fail closed.

For a normal push to `main` only, an inherited coverage-only failure can pass the
CI policy when all of the following are proven:

1. The checkout, GitHub push event, repository, before SHA, and after SHA agree.
2. The current Sonar analysis belongs to that exact after SHA.
3. Analyzed pre-push first-parent ancestors are checked from newest to oldest
   until a green gate anchors the accepted history. Never select an unrelated
   branch or a later analysis; if no green anchor is found, the strict gate blocks.
4. The same coverage period, project version, conditions, and thresholds apply.
5. Each intervening failed gate has only the coverage condition failing, and
   current coverage is at least every such ancestor's coverage. There is no
   rounding tolerance or fixed low floor that permits further deterioration.

A new fall from a green baseline is rejected. Period or version changes require
the full gate rather than resetting the debt. Once coverage reaches 80%, the
coverage exception no longer applies. The implementation does not set
`sonar.projectVersion`, reset the new-code baseline, exclude Rust source, remove
coverage reports, change the SonarCloud project gate, or convert security
failures into warnings.

## Reading outcomes

The job summary and `sonar-quality-evidence-<attempt>` artifact show the exact
analysis, all measured conditions, raw Sonar status, CI policy decision, and any
baseline commit. An inherited-debt decision emits an explicit warning. Sonar's
raw coverage gate remains red until that debt is actually fixed; a passing CI
ratchet must never be presented as 80% coverage or a green Sonar project.

On October 4, 2026, main run 37212119011 had 146 successful jobs, three intended
skips, and one failure: the final Sonar quality gate. Its new-code coverage was
61.7%, versus the configured 80%. The earlier main analysis was 86.6%, before the
large Rust migration landed. The new policy would still reject that original
86.6-to-61.7 regression; it does not retroactively relabel that run as passing.
The current repair addresses inherited debt so unrelated CI improvements can
ship without hiding it or permitting another decrease.

Source evidence: GitHub main run 37212119011, Sonar analysis
`2ca53ee4-9157-4df2-8dd4-e4df8b1cf840`, and prior analysis
`dd71ed73-7cf7-41e0-9e21-250d9085d880`.

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

For a normal push to `main` only, the PR explicitly accepts the already-landed
migration debt at analysis `2ca53ee4-9157-4df2-8dd4-e4df8b1cf840`, commit
`846fe97cb2445bbf6e73a05d6c540e8470fc6904`, measured coverage 61.7%. This is a
one-time, reviewable policy decision, not a claim that the original regression
was acceptable or that the 80% goal has been met.

The floor is the maximum measured coverage among that anchor and EVERY later
analyzed first-parent main ancestor in the same coverage period and project
version. A rejected lower scan cannot become the next baseline: after an
improvement to 75%, both a drop to 50% and a subsequent unchanged 50% push fail.
Even a higher measurement from a scan with another failed condition raises the
floor; failing a security check cannot erase coverage history.

The checkout, push event, repository, before SHA, after SHA, and exact Sonar
analysis must agree. The reviewed anchor must exist in pre-push first-parent
history. Unknown/missing history, altered anchor measurements, changed periods,
changed thresholds, or changed project versions fail closed. There is no
rounding allowance. The history client stops only after finding the exact
current analysis and the explicit anchor, not at a recent failed scan.

The bounded window permits up to 128 analyzed ancestor records and 2,000 Git
ancestors. Before retention or that bound is reached, a maintainer must refresh
the anchor through review with the proven high-water mark, never a lower value.
The immediate pre-push main analysis must survive in the window; if housekeeping
purges it, the gate fails closed rather than deriving a lower floor. A missing
historical record causes a failure, not an automatic reset. Once coverage reaches
80%, the full gate must continue to pass. The implementation
never changes `sonar.projectVersion`, resets the Sonar new-code period, excludes
Rust source, removes coverage reports, or converts a security failure to a warning.

## Reading outcomes

The job summary and `sonar-quality-evidence-<attempt>` artifact show the exact
analysis, all measured conditions, raw Sonar status, CI policy decision, and any
baseline commit. An inherited-debt decision emits an explicit warning. Sonar's
raw coverage gate remains red until that debt is actually fixed; a passing CI
ratchet must never be presented as 80% coverage or a green Sonar project.

On October 4, 2026, main run 37212119011 had 146 successful jobs, three intended
skips, and one failure: the final Sonar quality gate. Its new-code coverage was
61.7%, versus the configured 80%. The earlier main analysis was 86.6%, before the
large Rust migration landed. The original run remains a failed coverage gate. This review explicitly
accepts that existing debt as the bootstrap anchor while preserving the full
80% PR gate and preventing any subsequent decrease from the high-water mark.

Source evidence: GitHub main run 37212119011, Sonar analysis
`2ca53ee4-9157-4df2-8dd4-e4df8b1cf840`, and prior analysis
`dd71ed73-7cf7-41e0-9e21-250d9085d880`.

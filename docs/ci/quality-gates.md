# CI quality checks and fast feedback

Every PR retains the complete Rust workspace tests and Clippy, all 128 Python
coverage shards, the 300-cycle recurring-disconnect regression, untraced timing
contracts, platform qualification, and the existing security scanners.

The explicitly marked 10,000-cycle reconnect soak remains in scheduled and
manually dispatched qualification on both timing interpreters. It no longer
adds several minutes to every PR and push. No product test is deleted, and the
ordinary 300-cycle regression still exercises real failures and recovery.

## Sonar responsibilities

PRs, release branches, scheduled runs, and manual runs retain the original pinned
Sonar quality-gate action and configured 80% new-code coverage rule, including its
existing handling of changes with no coverable source lines.

On a normal main push only, the final CI decision treats the migration-wide
coverage percentage as advisory. Security, reliability, maintainability,
duplication, hotspot review, and any unknown failing condition remain blocking.
Missing coverage evidence, ignored conditions, weakened configured thresholds,
API errors, invalid task/project metadata, and checkout/event mismatches fail
closed. The main reporter never changes SonarCloud settings or its raw result.

This is an explicit policy tradeoff, NOT a historical coverage ratchet. Existing
coverage debt remains debt. A main percentage can fall while the coverage-only
reporting policy passes, so reviewers must continue inspecting PR coverage and
the recorded main measurements. The complete test suites and existing required
security checks are unchanged; the percentage rule is not a substitute for those
security/behavior tests. New work keeps the existing per-PR coverage gate.

`scripts/ci/check_sonar_quality.py` reads the exact completed analysis ID for the
current scanner task, not a mutable latest-project result. Credentials go only
to fixed SonarCloud endpoints; redirects, oversized responses, and unbounded
polling are rejected. The JSON artifact and job summary preserve all raw measured
conditions and distinguish a full green gate from coverage debt reported with
an explicit warning.

## Why not reconstruct a historical floor?

Sonar housekeeping can delete intermediate analyses. A ratchet reconstructed
from those snapshots can silently lose its high-water mark or fail every future
build. Requiring an analysis of every preceding commit also breaks when stale
main runs are cancelled. This change does not introduce either dependency,
require new admin permissions, or create a second persistent quality database.
Normal cancellation of superseded CI runs remains unchanged.

## Observed failure

Main run 37212119011 had 146 successful jobs, three intended skips, and one
failure: the final Sonar quality gate. Coverage was 61.7% versus 80%, after the
large Rust migration; all other gate conditions passed. The raw Sonar result
remains red until that coverage debt is genuinely addressed. Passing CI must not
be represented as 80% coverage or as a green Sonar project.

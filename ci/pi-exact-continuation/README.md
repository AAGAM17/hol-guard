# Exact-continuation qualification

This fixture deliberately pins Node 22.19.0, Bun 1.3.14, and the SDK versions
in `package-lock.json`. Floating runtime aliases would change the SDK execution
environment without a reviewed qualification change.

To update a runtime, change its exact version in both the `pi-exact-continuation`
job in `.github/workflows/ci.yml` and `scripts/ci/verify_pi_exact_continuation.py`.
To update an SDK, change `package.json` and regenerate `package-lock.json` using
the pinned Node/npm environment. Review the lockfile diff; do not remove it.

Run the CI verifier with the updated exact runtimes and locked dependencies.
Pi's published shrinkwrap pins brace-expansion 5.0.9, which bypasses the outer
lock during `npm ci`. The fixture updates that dependency to 5.0.11 before
qualification. The verifier checks both the reviewed lock hash and the actual
installed version; the Pi and OMP SDK versions remain unchanged.
All tests in `tests/test_pi_exact_continuation.py` must execute without skips,
including unchanged-input replay, cancellation, malformed interactive contexts,
and failed revalidation. Merge only after the actual-SDK CI job passes.

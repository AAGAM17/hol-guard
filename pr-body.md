## Summary

- Add root-signed, purpose-scoped workspace review authority and native decision verification.
- Bind decisions to persisted requests, current installation/workspace scope, and monotonic authority generation.
- Preserve consumed-claim replay evidence in an immutable, platform-anchored index and apply verified decisions through SQLite compare-and-swap.
- Refresh verified authority and decision polling without blocking daemon shutdown.
- Repair native PR wheel tooling and shallow-checkout test collection; pin the MCPB tooling dependency to the upstream signature-verification fix.

## Testing

- Focused workflow and freshness regressions: 10 passed.
- Test inventory and 128-shard planner passed; inventory contains 23,930 cases.
- Ruff check/format, actionlint, staged diff check, and secret scan passed.
- MCPB clean install, CLI help, and manifest validation passed; Trivy and dependency audit report no vulnerabilities for the fixed tooling install.
- Earlier exact-head native qualification at `55f07c446b0081999859cfe5c081936e678b131e`: locked workspace checks, 96 command tests, 25 runtime edge tests, approval gate, release self-test, and wheel version synchronization passed. This does not qualify subsequent commits as an installed release.

## Notes

- Four legacy-recovery design findings remain unresolved; CI repairs do not resolve those security decisions.
- The node-forge fix is pinned by full upstream commit and package integrity because no patched registry release is available. Upstream fix: https://github.com/digitalbazaar/forge/pull/1152.
- This is not production enrollment, installed-client delivery, ended-hook continuation, Windows qualification, or release-publication proof. These remain separate acceptance gates.

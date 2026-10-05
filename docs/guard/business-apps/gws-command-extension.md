# Opt-in gws command risk rules

`command.google-workspace.gws` is an external command contribution for the
Google Workspace CLI v0.22.5 source commit
`705fb0ecac6f4249679958f6325b809b63fdde17`. It classifies finite Gmail delivery
and destructive routes, Drive permission changes and Calendar event changes.
Gmail delivery includes `+send`, `+reply`, `+reply-all` and `+forward` helpers.
The CLI is a community project, not an officially supported Google product.

The contribution is inert until the existing local-admin activation enables it.
Permissions use a review baseline; activation never grants a send or waives a
first-party floor. The portable fixtures include inactive contribution cases
and compound commands that retain the destructive-operation block.

Literal help suppresses this contribution's route observation. A value such as
`--body '--help'` does not count as a help flag, nor does a flag after `--`.
Dry-run and draft flags do not mint authority or suppress review: creating
drafts can already transmit data. Supported scalar option
values are skipped while matching the route, including interspersed JSON
parameters and the pinned `-o` alias.

The offline Bash fixture context has no authenticated executable/account or
benign-command proof. Its overall native minimum remains review even when this
contribution emits no observations for help, reads or draft creation. These are
inherited native floors, not successful quiet-task acceptance results. The pack
does not add an allow grant or lower that boundary to make fixtures pass.

This contribution does not authenticate the application account, inspect every
payload, freeze files, isolate credentials or mediate provider dispatch. It does
not cover every CLI service, custom discovery document, wrapper, alias, generic
API fallback, remote connector or agent mode. The finite route list is reviewable
source classification, not a protected Google Workspace journey. Account-bound
managed dispatch, cumulative budgets, setup UI and live mode/version/OS evidence
remain separate requirements. No business mode is qualified by these fixtures.

Canonical authoring inputs are the source JSON, portable fixture and external
trust-class entry. The existing preparation command generates the descriptor
and directory catalog projections; none are hand-authored.

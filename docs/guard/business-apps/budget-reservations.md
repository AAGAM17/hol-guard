# Native local budget reservations

This component serializes reservations under the existing native transition
lock and commits all matching account/user/workflow buckets in one ledger.
Current signed policy selects the limits; native frozen input supplies volume
and account binding. User/workflow bindings must come from an authenticated
worker registry. This component does not authenticate supplied actor bindings,
create an execution grant or publish an RPC.

The ledger is content-addressed, private and bounded to 128 active events. Its
root and last observed time live in a purpose-separated platform secure account
in production. Only tests use a private anchor file. Missing, changed or rolled
back ledger data refuses, and existing history cannot bootstrap after losing
its protected anchor. Ledger and immutable replay-index bytes are durable before
the protected root commits; persistence failure returns no reservation.

Every matching chunk counts actions, recipients, records and bytes. Dropping a
reservation, including after an uncertain provider outcome, does not refund
usage. Changed windows or limits preserve bucket identity. Volume older than
the maximum supported window can leave the active ledger, while replay
tombstones remain in the existing immutable index. Old immutable files are
retained; administrative retention and recovery remain unfinished.

There is no connected worker caller, actor registry or Cloud allocation
authority yet. Budget-bearing business actions remain refused by native review
production. These are local counters, not a global multi-device guarantee or
an offline allocation protocol. Strict credential custody, reusable accounts,
approval/dispatch integration and all business acceptance journeys remain
unqualified. No provider request was made.

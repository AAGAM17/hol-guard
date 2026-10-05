# Local business review details

The Core review detail view can show metadata from an existing frozen native
business request: service, operation, audience, counts and sensitivity labels.
It reads `/v1/requests/{request_id}/business-summary` through the existing local
dashboard session. The endpoint is not a hosted dashboard API and responses
use `Cache-Control: no-store`.

The adapter requires the native summary capability. It passes only the request
ID to the authenticated resident transport; it does not stage a new request or
read private snapshot files. Both the adapter and browser reject unknown fields,
mismatched request IDs, invalid counts and unsupported presentation values.
Account-currentness and execution fields must retain their explicit uncertainty.
This validation is a presentation boundary, not a policy evaluator.

The view reports loading and transport/schema failures, with a bounded refresh
action. An available but incompatible runtime, or transport/schema failure,
returns a finite 503 error. An unavailable runtime, missing capability or an
explicit native no-summary/missing-request response returns 404
and omits the panel; omission does not establish safety.
The summary does not include message content, exact recipients, attachments,
account identifiers or binding digests in the visible UI. Unknown or unsupported
facts have a visible warning when metadata is available.

The existing review decision controls remain authoritative for review decisions.
This addition creates no execution grant, worker admission, provider operation,
Cloud upload or confirmation of an outcome. Exact private previews, current
account verification and a managed provider journey require further work.

## Native discovery boundary

The resident also exposes `workspace_review_local_queue`, requiring the
`native-local-business-review-queue-v1` capability and an empty request object.
It discovers saved pending request snapshots, verifies each through the existing
native loader and returns only the same finite summary metadata. Request ID
prefixes do not confer provenance. Corrupt records, private-file violations,
changed policy, more than 128 business items or a directory exceeding 4096
entries refuse the result instead of silently truncating it. The operation does
not occupy the exclusive mutation lock, save SQL rows or consume decisions.

The Python discovery adapter checks this presentation shape and uses only the
authenticated resident transport. Unavailable native support or a missing policy
returns optional absence; transport, schema or native verification failures
raise a finite read error. The adapter is not yet connected to the Core queue
and detail routes. Saved native requests therefore still need that integration
before this interface is a complete selectable review path. A saved pending
snapshot is not evidence that its account or dispatch authority remains current.

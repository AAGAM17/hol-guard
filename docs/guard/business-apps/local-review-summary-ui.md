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
action. A missing native summary is omitted; omission does not establish safety.
The summary does not include message content, exact recipients, attachments,
account identifiers or binding digests in the visible UI. Unknown or unsupported
facts have a visible warning when metadata is available.

The existing review decision controls remain authoritative for review decisions.
This addition creates no execution grant, worker admission, provider operation,
Cloud upload or confirmation of an outcome. Exact private previews, current
account verification and a managed provider journey require further work.

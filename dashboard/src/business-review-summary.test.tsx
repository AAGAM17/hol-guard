import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { parseBusinessReviewSummary } from "./business-review-summary";
import { BusinessReviewSummaryDetails } from "./business-review-summary-panel";
import { requestResolutionBlockReason } from "./approval-center-utils";
import { groupDuplicates, isBulkApprovableGroup } from "./queue-state";
import type { GuardApprovalRequest } from "./guard-types";

export const sampleSummary = {
  schema: "guard-native-local-business-review-summary.v1", version: 1, request_id: "business-test",
  request_snapshot_digest: "a".repeat(64), prepared_input_binding: "b".repeat(64),
  service: "google_gmail", operation: "mail_send", audience_kind: "named",
  audience_expansion_state: "known", recipient_count: 3, record_count: 1, byte_count: 24,
  attachment_count: 0, inspection_state: "unknown", sensitivity_labels: ["confidential"],
  snapshot_fact_completeness: "known", account_currentness: "not_asserted", execution_state: "not_checked",
};
const parsed = parseBusinessReviewSummary(sampleSummary, "business-test");
assert.ok(parsed);
for (const change of [
  { request_id: "other" }, { subject: "private-canary" }, { service: "google_drive" },
  { recipient_count: true }, { byte_count: Number.MAX_SAFE_INTEGER + 1 }, { audience_kind: ["named"] },
  { sensitivity_labels: ["secret", "secret"] }, { execution_state: "sent" }, { account_currentness: "verified" },
]) assert.equal(parseBusinessReviewSummary({ ...sampleSummary, ...change }, "business-test"), null);
const markup = renderToStaticMarkup(<BusinessReviewSummaryDetails summary={parsed} />);
assert.match(markup, /Send email/);
assert.match(markup, /does not verify the work account/);
assert.match(markup, /or confirm execution/);
assert.match(markup, /Counts alone do not establish/);
assert.doesNotMatch(markup, /a{64}|b{64}|request_snapshot_digest|prepared_input_binding/);
console.log("Business summary presentation: strict metadata, privacy, uncertainty PASS");

const displayOnlyRequest: GuardApprovalRequest = {
  request_id: "opaque-selector", harness: "native-business", artifact_id: "opaque-selector",
  artifact_name: "Send mail", artifact_type: "business-request", artifact_hash: "", publisher: null,
  policy_action: "require-reapproval", recommended_scope: "artifact", allowed_scopes: ["artifact"],
  changed_fields: [], source_scope: "local", config_path: "", transport: "native-resident",
  review_command: "", approval_url: "", status: "pending", resolution_action: null,
  resolution_scope: null, reason: null, created_at: "", resolved_at: null,
  native_business_review_display_only: true,
};
assert.match(requestResolutionBlockReason(displayOnlyRequest) ?? "", /read-only/);
assert.equal(isBulkApprovableGroup(groupDuplicates([displayOnlyRequest])[0]), false);
console.log("Native projection: individual and bulk decision controls disabled PASS");

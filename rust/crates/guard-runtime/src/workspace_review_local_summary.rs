#![forbid(unsafe_code)]

//! Local metadata from frozen authenticated input, never an execution grant.
//! This is separate from the strict Cloud-upload context and exports no raw
//! content, recipient/domain values, account identifiers, or resource details.

use super::PolicySnapshotStore;
use serde_json::{json, Value};

pub(crate) fn build(store: &PolicySnapshotStore, request_id: &str) -> Result<Value, String> {
    super::approval_enrollment::with_transition_lock(store.state_base(), || {
        let request = super::workspace_review_request::load(store, request_id)?;
        let input = request
            .business_input
            .as_ref()
            .ok_or_else(|| "native_local_business_summary_unavailable".to_owned())?;
        let facts = input.facts();
        Ok(json!({
            "schema": "guard-native-local-business-review-summary.v1",
            "version": 1,
            "request_id": request.request_id,
            "request_snapshot_digest": request.request_snapshot_digest,
            "prepared_input_binding": input.binding(),
            "service": facts.provider.service,
            "operation": facts.operation,
            "audience_kind": facts.audience.kind,
            "audience_expansion_state": facts.audience.expansion_state,
            "recipient_count": facts.volume.recipient_count,
            "record_count": facts.volume.record_count,
            "byte_count": facts.volume.byte_count,
            "attachment_count": input.attachments().len(),
            "inspection_state": facts.content.inspection_state,
            "sensitivity_labels": facts.content.sensitivity_labels,
            "snapshot_fact_completeness": facts.completeness,
            // Integrity of this snapshot does not establish current provider
            // identity, account lease validity, custody, or any provider effect.
            "account_currentness": "not_asserted",
            "execution_state": "not_checked"
        }))
    })
}

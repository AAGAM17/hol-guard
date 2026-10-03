//! Resident-operation request typing — split out of `resident_protocol.rs` to
//! keep the active approval-contract file under the 500-line gate
//! (`scripts/ci/native_approval_contract_gate.py`). Pure data/serde, no logic.

use guard_command::CommandModelRequestV1;
use guard_contracts::{
    ApprovalChallengeRequestV3, ApprovalChallengeRequestV4, ApprovalConsumeRequestV3,
    ApprovalConsumeRequestV4, ApprovalGateRequestV1, ApprovalReuseRequestV1,
    ApprovalValidateRequestV3, ApprovalValidateRequestV4, ClaimApprovalReuseDecisionsRequestV1,
    CommandEffectRequestV1, ContainedExecuteRequestV1, ContainedNodeExecuteRequestV1,
    ContainedPackageScriptExecuteRequestV1, ContainedTestHookRequestV1,
    ContainedTypescriptExecuteRequestV1, ContainedWorkspaceWriteExecuteRequestV1,
    ContextDigestRequestV1, McpStdioProbeRequestV1, PackageAuthorityDecideRequestV1,
    PackageIntentParseRequestV1, PromptAnalyzeRequestV1, ShimAdminRequestV1,
    SupplyChainEvalRequestV1,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", content = "request", rename_all = "snake_case")]
pub(crate) enum ResidentOperationV1 {
    CommandModel(CommandModelRequestV1),
    PreToolUse(CommandModelRequestV1),
    PolicySnapshotPush(Value),
    ApprovalChallenge(ApprovalChallengeRequestV3),
    ApprovalValidate(ApprovalValidateRequestV3),
    ApprovalConsume(ApprovalConsumeRequestV3),
    ApprovalChallengeV4(ApprovalChallengeRequestV4),
    ApprovalValidateV4(ApprovalValidateRequestV4),
    ApprovalConsumeV4(ApprovalConsumeRequestV4),
    WorkspaceReviewAuthorityEnroll(WorkspaceReviewAuthorityEnrollRequestV1),
    WorkspaceReviewContext(WorkspaceReviewContextRequestV1),
    WorkspaceReviewDecision(WorkspaceReviewDecisionRequestV1),
    ContextDigest(ContextDigestRequestV1),
    CommandEffectDecide(CommandEffectRequestV1),
    ApprovalReuseDecide(ApprovalReuseRequestV1),
    ClaimApprovalReuseDecisions(ClaimApprovalReuseDecisionsRequestV1),
    ApprovalGate(ApprovalGateRequestV1),
    PackageIntentParse(PackageIntentParseRequestV1),
    SupplyChainEval(SupplyChainEvalRequestV1),
    PackageAuthorityDecide(PackageAuthorityDecideRequestV1),
    ContainedNodeExecute(ContainedNodeExecuteRequestV1),
    ContainedTypescriptExecute(ContainedTypescriptExecuteRequestV1),
    ContainedPackageScriptExecute(ContainedPackageScriptExecuteRequestV1),
    ContainedWorkspaceWriteExecute(ContainedWorkspaceWriteExecuteRequestV1),
    ContainedExecute(ContainedExecuteRequestV1),
    ContainedTestHook(ContainedTestHookRequestV1),
    ShimAdmin(ShimAdminRequestV1),
    McpStdioProbe(McpStdioProbeRequestV1),
    PromptAnalyze(PromptAnalyzeRequestV1),
    Health(Value),
    Shutdown(Value),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceReviewDecisionRequestV1 {
    pub(crate) request_id: String,
    pub(crate) decision: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceReviewContextRequestV1 {
    pub(crate) request_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceReviewAuthorityEnrollRequestV1 {
    pub(crate) record_path: String,
}

import { fetchGuardApi, GuardHarnessActionError } from "./guard-api";

export const RECOVERY_SOURCE_ERRORS = new Set([
  "native_business_source_installation_incoherent",
  "native_business_source_transaction_not_committed",
  "native_business_source_retention_conflict",
  "native_business_source_recovery_required",
]);

export async function recoverBusinessPolicy(input: {
  requestId: string;
  candidateDigest: string;
  approval_password?: string;
  approval_totp_code?: string;
}): Promise<void> {
  const response = await fetchGuardApi(`/v1/mcp-policy/requests/${encodeURIComponent(input.requestId)}/decision`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action: "recover", ...input }),
  });
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    throw new GuardHarnessActionError(response.status, {
      error: "business_policy_recovery_failed",
      message: "The saved policy could not be recovered. Its approval or installation state needs attention.",
    });
  }
  if (!payload || typeof payload !== "object" || !("installationRecovered" in payload) ||
      payload.installationRecovered !== true || !("sourceDigest" in payload) || payload.sourceDigest !== input.candidateDigest) {
    throw new Error("Recovery was not confirmed for this policy. Refresh before continuing.");
  }
}

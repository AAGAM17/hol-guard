import { useState } from "react";
import { ActionButton } from "./approval-center-primitives";
import { ApprovalProofFieldInputs, buildApprovalProofCredentials, isApprovalProofSubmitDisabled } from "./approval-proof-inline";
import { recoverBusinessPolicy } from "./business-policy-recovery-api";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

export function BusinessPolicyRecoveryPanel(props: {
  requestId: string;
  candidateDigest: string;
  approvalGate?: GuardApprovalGatePublicConfig | null;
  onRecovered: () => void;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [recovered, setRecovered] = useState(false);
  async function recover() {
    if (busy || recovered) return;
    const proof = buildApprovalProofCredentials(props.approvalGate, { approvalPassword: password, approvalTotpCode: totp }, true);
    setPassword("");
    setTotp("");
    setBusy(true);
    setMessage(null);
    try {
      await recoverBusinessPolicy({ requestId: props.requestId, candidateDigest: props.candidateDigest, ...proof });
      setRecovered(true);
      setMessage("Policy installation recovered. No app action was sent or replayed.");
      props.onRecovered();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "The saved policy could not be recovered. Refresh before retrying.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="space-y-4 border-t border-slate-200 pt-5" aria-labelledby="business-policy-recovery-title" aria-busy={busy}>
      <h2 id="business-policy-recovery-title" className="text-lg font-semibold text-brand-dark">Recover interrupted policy installation</h2>
      <p className="max-w-prose text-sm leading-6 text-brand-dark/75">
        Freshly approve this request’s saved policy to finish its installation.
        Guard checks that it matches the saved policy and does not replace newer protection.
        This does not resume an app task or resolve the original request.
      </p>
      {!recovered ? <>
        <ApprovalProofFieldInputs
          approvalGate={props.approvalGate ?? null}
          approvalPassword={password}
          approvalTotpCode={totp}
          onApprovalPasswordChange={(event) => setPassword(event.target.value)}
          onApprovalTotpCodeChange={(event) => setTotp(event.target.value)}
          requireFreshTotp
          requireGate
        />
        <ActionButton onClick={() => void recover()} disabled={busy || isApprovalProofSubmitDisabled(props.approvalGate, {
          approvalPassword: password, approvalTotpCode: totp,
        }, busy, true, true)}>{busy ? "Recovering policy…" : "Approve and recover policy"}</ActionButton>
      </> : null}
      {message ? <p role="status" aria-live="polite" className="text-sm leading-6 text-brand-dark">{message}</p> : null}
    </section>
  );
}

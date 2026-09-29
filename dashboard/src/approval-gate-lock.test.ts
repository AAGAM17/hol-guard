import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { GuardApprovalGatePublicConfig } from "./guard-types";
import {
  approvalGateIsLocked,
  approvalGateLockRemainingSeconds,
  approvalGateRequiredForResolution,
} from "./approval-gate-utils";
import { ApprovalPasswordModal } from "./approval-center-review-cards";
import { isApprovalProofSubmitDisabled } from "./approval-proof-inline";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

const lockedGate: GuardApprovalGatePublicConfig = {
  enabled: true,
  configured: true,
  cooldown_seconds: 0,
  cooldown_active: false,
  cooldown_expires_at: null,
  locked_until: "2026-05-08T10:01:00.000Z",
  fail_closed: false,
  strict_all_decisions: false,
};

const now = Date.parse("2026-05-08T10:00:00.000Z");
assert(approvalGateLockRemainingSeconds(lockedGate, now) === 60, "lock helper reports the remaining lock duration");
assert(approvalGateIsLocked(lockedGate, now), "future locked_until marks the gate as locked");
assert(!approvalGateIsLocked(lockedGate, now + 60_000), "expired locked_until no longer marks the gate as locked");

const activeGate = { ...lockedGate, locked_until: new Date(Date.now() + 60_000).toISOString() };
assert(
  isApprovalProofSubmitDisabled(activeGate, { approvalPassword: "secret123", approvalTotpCode: "" }, false),
  "locked gates disable proof submission even when credentials are present",
);

const disabledWithStaleLock = { ...lockedGate, enabled: false, configured: false };
assert(
  approvalGateLockRemainingSeconds(disabledWithStaleLock, now) === 0 &&
    !approvalGateIsLocked(disabledWithStaleLock, now),
  "disabled gates ignore stale lock timestamps",
);
assert(
  !isApprovalProofSubmitDisabled(
    disabledWithStaleLock,
    { approvalPassword: "secret123", approvalTotpCode: "" },
    false,
  ),
  "disabled fail-open gates do not retain a stale lock in the proof form",
);
assert(
  !approvalGateRequiredForResolution(lockedGate, "block", "artifact"),
  "a locked gate does not preflight an ordinary block decision",
);
assert(
  approvalGateRequiredForResolution(lockedGate, "block", "global"),
  "a locked gate still preflights a global block decision",
);
assert(
  approvalGateRequiredForResolution(lockedGate, "allow", "artifact"),
  "a locked gate still preflights an allow decision",
);
assert(
  !approvalGateRequiredForResolution(disabledWithStaleLock, "allow", "global"),
  "disabled gates do not preflight approval locks",
);

const markup = renderToStaticMarkup(
  createElement(ApprovalPasswordModal, {
    gate: activeGate,
    approvalPassword: "secret123",
    approvalTotpCode: "",
    useCooldown: false,
    onApprovalPasswordChange: () => undefined,
    onApprovalTotpCodeChange: () => undefined,
    onUseCooldownChange: () => undefined,
    onSubmit: () => undefined,
    onCancel: () => undefined,
    submitLabel: "Keep allowing",
  }),
);
assert(markup.includes("Approval gate is temporarily locked"), "locked modal explains the gate lock");
assert(markup.includes("Try again in"), "locked modal provides retry timing");
assert(!markup.includes("Approval password"), "locked modal does not invite another credential attempt");

console.log("✓ approval gate lock behavior");

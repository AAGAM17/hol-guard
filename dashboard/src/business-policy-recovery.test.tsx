import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { recoverBusinessPolicy } from "./business-policy-recovery-api";
import { BusinessPolicyRecoveryPanel } from "./business-policy-recovery-panel";

const storage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
Object.defineProperty(globalThis, "window", { configurable: true, value: {
  location: { origin: "http://127.0.0.1:4174", pathname: "/", search: "", hash: "" },
  sessionStorage: storage, localStorage: storage,
} });
const markup = renderToStaticMarkup(<BusinessPolicyRecoveryPanel
  requestId="synthetic-request" candidateDigest="synthetic-digest" approvalGate={null} onRecovered={() => {}}
/>);
assert.match(markup, /Checking local approval settings/);
assert.match(markup, /disabled=""/);
assert.match(markup, /does not resume an app task or resolve the original request/);
const unconfiguredMarkup = renderToStaticMarkup(<BusinessPolicyRecoveryPanel
  requestId="synthetic-request" candidateDigest="synthetic-digest" onRecovered={() => {}}
  approvalGate={{ enabled: false, configured: false, cooldown_seconds: 0, cooldown_active: false,
    cooldown_expires_at: null, locked_until: null, fail_closed: true, strict_all_decisions: true }}
/>);
assert.match(unconfiguredMarkup, /Set up approval/);
assert.match(unconfiguredMarkup, /disabled=""/);

const previousFetch = globalThis.fetch;
try {
  let submitted: Record<string, unknown> | null = null;
  globalThis.fetch = async (_url, init) => {
    submitted = JSON.parse(String(init?.body));
    return new Response(JSON.stringify({ installationRecovered: true, sourceDigest: "synthetic-digest" }), { status: 200 });
  };
  await recoverBusinessPolicy({ requestId: "synthetic-request", candidateDigest: "synthetic-digest", approval_password: "synthetic-proof" });
  assert.equal(submitted?.["action"], "recover");
  assert.equal(submitted?.["candidateDigest"], "synthetic-digest");
  for (const payload of [
    { resolved: true, status: "applied" },
    { installationRecovered: true, sourceDigest: "different-digest" },
    { installationRecovered: false, sourceDigest: "synthetic-digest" },
  ]) {
    globalThis.fetch = async () => new Response(JSON.stringify(payload), { status: 200 });
    await assert.rejects(recoverBusinessPolicy({ requestId: "synthetic-request", candidateDigest: "synthetic-digest" }), /not confirmed/);
  }
  globalThis.fetch = async () => new Response(JSON.stringify({ message: "private-server-marker" }), { status: 503 });
  await assert.rejects(recoverBusinessPolicy({ requestId: "synthetic-request", candidateDigest: "synthetic-digest" }),
    (error: Error) => !error.message.includes("private-server-marker"));
} finally {
  globalThis.fetch = previousFetch;
}
console.log("business-policy-recovery: missing proof and exact recovery response checks passed");

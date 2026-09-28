import { useEffect, useRef, useState } from "react";
import { fetchLocalCliApi } from "../guard-api";
import type { LocalCliItem } from "../local-cli-api";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import { ApprovalProofFieldInputs, buildApprovalProofCredentials, isApprovalProofSubmitDisabled } from "../approval-proof-inline";

type RegistryEntry = {
  name: string; version: string; title: string; description: string;
  status: "active" | "deprecated" | "unknown";
  remote_endpoints: { url: string; transport: "streamable-http" | "sse" }[];
  package_count: number; verified_package: false; configured: false; installed: false;
};
const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);

async function registrySearch(query: string, signal: AbortSignal): Promise<{
  entries: RegistryEntry[]; moreAvailable: boolean;
}> {
  const response = await fetchLocalCliApi("/v1/local-clis/registry-search", {
    method: "POST", signal, headers: { "Content-Type": "application/json" }, body: JSON.stringify({ search: query }),
  });
  const body: unknown = await response.json();
  if (!response.ok) throw new Error(object(body) && typeof body.message === "string" ? body.message : "Registry search failed.");
  if (!object(body) || body.source !== "official-mcp-registry" || body.coverage !== "search-page"
    || !Array.isArray(body.results) || body.results.length > 20 || typeof body.more_available !== "boolean") {
    throw new Error("Invalid registry response");
  }
  const entries = body.results.map((entry): RegistryEntry => {
    if (!object(entry) || entry.provenance !== "official-mcp-registry" || entry.verified_package !== false
      || entry.configured !== false || entry.installed !== false || !["active", "deprecated", "unknown"].includes(String(entry.status))
      || typeof entry.name !== "string" || entry.name.length > 256
      || typeof entry.title !== "string" || entry.title.length > 120
      || typeof entry.version !== "string" || entry.version.length > 80
      || typeof entry.description !== "string" || entry.description.length > 500
      || !Array.isArray(entry.remote_endpoints) || entry.remote_endpoints.length > 8
      || typeof entry.package_count !== "number" || !Number.isSafeInteger(entry.package_count)
      || entry.package_count < 0 || entry.package_count > 100) {
      throw new Error("Invalid registry provenance");
    }
    const endpoints = entry.remote_endpoints.map((remote) => {
      if (!object(remote) || typeof remote.url !== "string" || !remote.url.startsWith("https://")
        || !["streamable-http", "sse"].includes(String(remote.transport))) throw new Error("Invalid registry endpoint");
      return { url: remote.url, transport: remote.transport as "streamable-http" | "sse" };
    });
    return { name: entry.name, version: entry.version, title: entry.title, description: entry.description,
      status: entry.status as RegistryEntry["status"], remote_endpoints: endpoints,
      package_count: entry.package_count, verified_package: false, configured: false, installed: false };
  });
  return { entries, moreAvailable: body.more_available };
}

type SetupCandidate = { host: "codex"; registry_name: string; version: string; endpoint: string;
  setup_name: string; selection_digest: string; permissions_granted: false; host_change_applied: false };

export function McpRegistrySearch({ items, approvalGate, onOpenChange }: {
  items: LocalCliItem[]; approvalGate: GuardApprovalGatePublicConfig | null;
  onOpenChange: (open: boolean) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [entries, setEntries] = useState<RegistryEntry[] | null>(null);
  const [moreAvailable, setMoreAvailable] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const controller = useRef<AbortController | null>(null);
  const operation = useRef<"search" | "preview" | "apply" | null>(null);
  const [candidate, setCandidate] = useState<SetupCandidate | null>(null);
  const [configured, setConfigured] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  useEffect(() => () => controller.current?.abort(), []);
  async function search() {
    if (query.trim().length < 2 || busy || operation.current) return;
    operation.current = "search";
    const next = new AbortController();
    controller.current = next; setBusy(true); setError(null); setEntries(null); setCandidate(null);
    try {
      const result = await registrySearch(query, next.signal);
      if (!next.signal.aborted) { setEntries(result.entries); setMoreAvailable(result.moreAvailable); }
    }
    catch (caught) { if (!next.signal.aborted) setError(caught instanceof Error ? caught.message : "Registry unavailable."); }
    finally { operation.current = null; if (controller.current === next) controller.current = null;
      if (!next.signal.aborted) setBusy(false); }
  }
  async function preview(entry: RegistryEntry, endpoint: string) {
    if (operation.current) return;
    operation.current = "preview";
    setBusy(true); setError(null); setCandidate(null);
    const setupName = entry.name.split("/").at(-1)?.toLowerCase().replace(/[^a-z0-9_-]/g, "-") ?? "mcp-server";
    try {
      const response = await fetchLocalCliApi("/v1/local-clis/registry-setup", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operation: "preview", registry_name: entry.name, version: entry.version,
          endpoint, setup_name: setupName }),
      });
      const body: unknown = await response.json();
      if (!response.ok) throw new Error(object(body) && typeof body.message === "string" ? body.message : "Could not review setup.");
      if (!object(body) || body.host !== "codex" || body.registry_name !== entry.name || body.version !== entry.version
        || body.endpoint !== endpoint || body.setup_name !== setupName || body.permissions_granted !== false
        || body.host_change_applied !== false || typeof body.selection_digest !== "string"
        || !/^[a-f0-9]{64}$/.test(body.selection_digest)) throw new Error("Invalid Codex setup preview");
      setCandidate(body as SetupCandidate);
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Could not review setup."); }
    finally { operation.current = null; setBusy(false); }
  }
  async function apply() {
    if (!candidate || busy || operation.current || isApprovalProofSubmitDisabled(approvalGate,
      { approvalPassword: password, approvalTotpCode: totp }, false)) return;
    operation.current = "apply";
    setBusy(true); setError(null);
    try {
      const proof = buildApprovalProofCredentials(approvalGate,
        { approvalPassword: password, approvalTotpCode: totp });
      const response = await fetchLocalCliApi("/v1/local-clis/registry-setup", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ operation: "apply", registry_name: candidate.registry_name,
          version: candidate.version, endpoint: candidate.endpoint, setup_name: candidate.setup_name,
          selection_digest: candidate.selection_digest, confirm_host_change: true,
          session_nonce: crypto.randomUUID().replaceAll("-", ""), ...proof }),
      });
      const body: unknown = await response.json();
      if (!response.ok) throw new Error(object(body) && typeof body.message === "string" ? body.message : "Codex setup did not finish.");
      if (!object(body) || body.host !== "codex" || body.setup_name !== candidate.setup_name
        || body.host_change_applied !== true || body.permissions_granted !== false) throw new Error("Codex setup outcome is uncertain.");
      setConfigured(candidate.setup_name); setCandidate(null); setPassword(""); setTotp("");
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Codex setup did not finish."); }
    finally { operation.current = null; setBusy(false); }
  }
  return <details className="mt-6 rounded-2xl border border-slate-200 bg-white p-4" onToggle={(event) => {
    setOpen(event.currentTarget.open);
    onOpenChange(event.currentTarget.open);
    if (!event.currentTarget.open && operation.current === "search") { controller.current?.abort(); setBusy(false); }
  }}>
    <summary className="min-h-11 cursor-pointer py-3 font-semibold text-brand-dark">Find an MCP server in the public registry</summary>
    {open ? <section aria-label="Public MCP registry search">
      <p className="text-sm leading-6 text-brand-dark/75">Search official listing metadata. A listing does not verify a package,
        install a server, connect an account, or enable tools. App-owned connections must be configured in their host.</p>
      <div className="mt-3 flex flex-wrap items-end gap-3">
        <label className="block min-w-56 flex-1 text-sm font-semibold text-brand-dark">Server or app name
          <input type="search" minLength={2} maxLength={80} value={query} onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); void search(); } }}
            className="mt-2 min-h-11 w-full rounded-xl border border-slate-300 px-3 font-normal" />
        </label>
        <button type="button" onClick={() => { void search(); }} disabled={busy || query.trim().length < 2}
          className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:opacity-50">Search registry</button>
      </div>
      {busy ? <p role="status" className="mt-3 text-sm text-brand-dark/75">Searching public listings…</p> : null}
      {error ? <p role="alert" className="mt-3 text-sm text-red-700">{error}</p> : null}
      {configured ? <p role="status" className="mt-3 text-sm text-brand-dark">
        {configured} was added to Codex. Restart Codex and complete any provider-owned sign-in there.
        Return to Extensions, check host connections, then review each tool in Guard. No tool permission was granted.
      </p> : null}
      {candidate ? <section aria-label="Review Codex MCP setup" className="mt-4 rounded-xl border border-slate-200 p-4 text-sm text-brand-dark">
        <h3 className="font-semibold">Review Codex connection</h3>
        <p className="mt-2">{candidate.registry_name} · version {candidate.version}</p>
        <p className="mt-1 break-all">Codex name: {candidate.setup_name} · HTTPS endpoint: {candidate.endpoint}</p>
        <p className="mt-2">This changes Codex host configuration. It does not download a package,
          authenticate an account, activate this session, or allow tools in Guard.</p>
        <div className="mt-3 max-w-sm"><ApprovalProofFieldInputs approvalGate={approvalGate}
          approvalPassword={password} approvalTotpCode={totp}
          onApprovalPasswordChange={(event) => setPassword(event.target.value)}
          onApprovalTotpCodeChange={(event) => setTotp(event.target.value.replace(/\D/g, "").slice(0, 6))} /></div>
        <div className="mt-3 flex gap-3">
          <button type="button" disabled={busy || isApprovalProofSubmitDisabled(approvalGate,
            { approvalPassword: password, approvalTotpCode: totp }, false)} onClick={() => { void apply(); }}
            className="min-h-11 rounded-xl bg-brand-blue px-4 font-semibold text-white disabled:opacity-50">Add to Codex</button>
          <button type="button" disabled={busy} onClick={() => { setCandidate(null); setPassword(""); setTotp(""); }}
            className="min-h-11 rounded-xl border border-slate-300 px-4 font-semibold">Cancel</button>
        </div>
      </section> : null}
      {entries?.length === 0 ? <p className="mt-3 text-sm text-brand-dark/75">No listing on this search page. Try another name.</p> : null}
      {moreAvailable && entries ? <p className="mt-3 text-sm text-brand-dark/75">
        More listings match. Refine the name to find a specific server; this page is not the complete registry.
      </p> : null}
      {entries ? <ul className="mt-4 divide-y divide-slate-200">{entries.map((entry) => {
        const basename = entry.name.split("/").at(-1)?.toLowerCase();
        const possibleExisting = items.some((item) => item.surface === "mcp"
          && (item.name.toLowerCase() === entry.title.toLowerCase() || item.name.toLowerCase() === basename));
        return <li key={`${entry.name}/${entry.version}`} className="py-4 text-sm text-brand-dark">
          <p className="font-semibold">{entry.title} · {entry.version}</p>
          <p className="mt-1 text-brand-dark/75">{entry.description}</p>
          <p className="mt-2 break-all text-xs text-brand-dark/75">{entry.name}</p>
          <p className="mt-2 text-xs text-brand-dark/75">{entry.status} listing · {entry.remote_endpoints.length} HTTPS endpoint(s)
            · {entry.package_count} package option(s) · Package unverified</p>
          {possibleExisting ? <p className="mt-2 text-xs font-semibold text-brand-dark">Possible existing connection. Inspect it before adding another.</p> : null}
          {entry.status === "active" && !possibleExisting && entry.remote_endpoints.some((remote) => remote.transport === "streamable-http")
            ? <button type="button" disabled={busy} onClick={() => {
              const endpoint = entry.remote_endpoints.find((remote) => remote.transport === "streamable-http");
              if (endpoint) void preview(entry, endpoint.url);
            }} className="mt-3 min-h-11 rounded-xl border border-slate-300 px-4 font-semibold text-brand-dark">
              Review Codex setup</button> : null}
        </li>;
      })}</ul> : null}
    </section> : null}
  </details>;
}

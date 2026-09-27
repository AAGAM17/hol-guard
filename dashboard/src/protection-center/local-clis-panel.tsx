import { useCallback, useEffect, useRef, useState } from "react";
import type { ChangeEvent, FormEvent } from "react";
import { HiMiniArrowLeft, HiMiniPlus } from "react-icons/hi2";

import {
  ApprovalProofFieldInputs,
  approvalProofRecentlySatisfied,
  buildApprovalProofCredentials,
  isApprovalProofSubmitDisabled,
} from "../approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "../guard-types";
import {
  connectorWorkspaceItems,
  applyBulkCommandState,
  applyLocalCliMutation,
  bulkCommandState,
  enrollablePackageScriptCommands,
  LocalCliApiError,
  previewLocalCliMutation,
  recognizeLocalCli,
  refreshMcpInventory,
  type LocalCliCommandState,
  type LocalCliItem,
  type LocalCliListResponse,
  type LocalCliState,
} from "../local-cli-api";
import { BulkPolicyPicker } from "./add-custom-extension-catalog";
import { CustomExtensionCommandList, commandStatesPayload, withCommandState } from "./custom-extension-commands";
import { McpDeclaredSkills } from "./mcp-declared-skills";
import { useModalDialog } from "../use-modal-dialog";
import { useResolvedApprovalGate } from "../use-resolved-approval-gate";
import { InlineError, ProtectionModuleRow } from "./components/protection-primitives";
import { customExtensionContinuityView } from "../managed-controls/custom-extension-continuity";
import { commandPermissionChanges, mcpCatalogCopy, mcpToolCanReceiveDirectAllow, rebaseCommandDraft } from "./mcp-catalog-state";
import { McpProviderActions, type ProviderActionDraft } from "./mcp-provider-actions";
import { ProviderWorkflows } from "./provider-workflows";

export { AddCustomExtensionWorkspace } from "./add-custom-extension-dialog";
export { useLocalCliCatalog } from "./use-local-cli-catalog";

function randomToken(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

function detailPolicyCopy(surface: LocalCliItem["surface"]): string {
  if (surface === "mcp") {
    return "Policy follows Guard's normal rules. Ask requires approval. Allow and Deny apply within the scope shown in Connection details. Execution wrappers require review of their underlying actions.";
  }
  if (surface === "package-scripts") {
    return "Recommended keeps Guard's usual review. Allow or block applies to that npm, pnpm, yarn, or bun script in this project. Nested names such as guard:audit stay grouped.";
  }
  return "Recommended keeps Guard's usual review. Allow or block applies to that command from this file. Pipes, wrappers, and destructive commands stay under Guard's usual rules.";
}

function detailCatalogHeading(surface: LocalCliItem["surface"]): string {
  if (surface === "mcp") return "MCP tools";
  if (surface === "package-scripts") return "Package scripts";
  return "Command patterns";
}

function detailCatalogHelper(surface: LocalCliItem["surface"]): string {
  if (surface === "mcp") {
    return "Choose Allow, Ask, or Deny for each tool. Policy follows Guard's existing rules.";
  }
  if (surface === "package-scripts") {
    return "Same settings as built-in tools. Nested scripts stay indented under their prefix.";
  }
  return "Same settings as built-in tools. Recommended is the safe default.";
}

function bulkPolicyCopy(surface: LocalCliItem["surface"]): { groupLabel: string; mixedCopy: string } {
  if (surface === "mcp") {
    return {
      groupLabel: "Listed tools with direct permissions",
      mixedCopy: "Custom mix. Use policy, allow, ask, or deny the listed tools with direct permissions.",
    };
  }
  if (surface === "package-scripts") {
    return {
      groupLabel: "All scripts protection setting",
      mixedCopy: "Custom mix. Pick Recommended, Allow all, or Block all to reset every script.",
    };
  }
  return {
    groupLabel: "All commands protection setting",
    mixedCopy: "Custom mix. Pick Recommended, Allow all, or Block all to reset every command.",
  };
}

function reviewTitle(name: string, state: LocalCliState): string {
  if (state === "allowed") return `Save ${name} command settings`;
  if (state === "blocked") return `Block ${name}`;
  return `Remove ${name}`;
}

function reviewModalDetail(gate: GuardApprovalGatePublicConfig | null): string {
  if (approvalProofRecentlySatisfied(gate)) {
    return "Recently confirmed with your authenticator. A new code is not needed yet.";
  }
  if (gate?.totp_enabled === true) {
    return "Enter the current authenticator code to save these settings on this device.";
  }
  return "This custom Extension remains local to this device until portable continuity is enabled.";
}

function customExtensionUnits(surface: LocalCliItem["surface"]): { unit: string; units: string; source: string } {
  if (surface === "mcp") return { unit: "tool", units: "tools", source: "this server" };
  if (surface === "package-scripts") return { unit: "script", units: "scripts", source: "this project" };
  return { unit: "command", units: "commands", source: "this file" };
}

export function customExtensionStateLabel(item: LocalCliItem): string {
  const { unit, units, source } = customExtensionUnits(item.surface);
  if (item.stale) {
    if (item.surface === "mcp") return "This connection changed. Review its permissions again.";
    return item.surface === "package-scripts"
      ? "package.json scripts changed. Review the extension again."
      : "This file changed. Review the extension again.";
  }
  if (item.state === "blocked") return `Every ${unit} from ${source} is blocked.`;
  if (item.state === "allowed") {
    if (item.surface === "mcp") {
      const tools = item.commands.filter((command) => command.command_id !== "other");
      if (tools.length === 0) return "No tools allowed yet. List the inventory to choose permissions.";
      const allowed = tools.filter((command) => command.state === "allow" && mcpToolCanReceiveDirectAllow(command)).length;
      const denied = tools.filter((command) => command.state === "block").length;
      const ask = tools.filter((command) => command.state === "review"
        || (!mcpToolCanReceiveDirectAllow(command) && command.state !== "block")).length;
      return `${allowed} allowed · ${ask} ask · ${denied} denied. New tools require review.`;
    }
    if (item.commands.length === 0) {
      return `Matching ${units} from ${source} are allowed.`;
    }
    const allowed = item.commands.filter((command) => command.state === "allow").length;
    if (allowed > 0) return `${allowed} ${allowed === 1 ? unit : units} allowed. The rest follow Recommended.`;
    return `${units.charAt(0).toUpperCase()}${units.slice(1)} follow Recommended until you allow or block them.`;
  }
  return item.surface === "mcp" ? "Detected · Permissions not configured. Inspect this connection." : item.example_label;
}

function continuityCopy(item: LocalCliItem): { title: string; description: string } | null {
  const status = item.continuity?.status;
  if (status === "applied") {
    const view = customExtensionContinuityView("identity-matched");
    return { title: view.title, description: view.description };
  }
  if (status === "pending_observation") return customExtensionContinuityView("pending-observation");
  if (status === "changed_identity") return customExtensionContinuityView("changed-identity");
  if (status === "locally_overridden") return customExtensionContinuityView("locally-overridden");
  if (status === "removed") return customExtensionContinuityView("removed");
  if (status === "stale") return customExtensionContinuityView("stale");
  return null;
}

export function CustomExtensionsSection(props: {
  items: LocalCliItem[];
  onOpen: (cliId: string) => void;
  onAdd: () => void;
}) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const added = connectorWorkspaceItems(props.items, search);
  const currentPage = Math.min(page, Math.max(0, Math.ceil(added.length / 25) - 1));
  const visible = added.slice(currentPage * 25, (currentPage + 1) * 25);
  return (
    <section className="mt-10" aria-labelledby="custom-extensions-heading">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 id="custom-extensions-heading" className="text-xl font-semibold tracking-tight text-brand-dark">Custom extensions</h2>
          <p className="mt-1 text-sm text-slate-500">Detected connectors and your own tools. Inspect a connection to choose its permissions.</p>
        </div>
        <button type="button" onClick={props.onAdd} className="inline-flex min-h-11 items-center gap-2 rounded-xl px-3 text-sm font-semibold text-brand-blue">
          <HiMiniPlus className="size-4" aria-hidden="true" />
          Add custom extension
        </button>
      </div>
      <label className="mt-4 block max-w-xl text-sm font-semibold text-brand-dark">
        Find a connector or custom tool
        <input type="search" value={search} onChange={(event) => { setSearch(event.target.value); setPage(0); }}
          placeholder="Name, host, or tool identifier"
          className="mt-2 min-h-11 w-full rounded-xl border border-slate-300 bg-white px-3 font-normal" />
      </label>
      {added.length === 0 ? (
        <p className="mt-4 text-sm leading-6 text-brand-dark/75">{search ? "No connections match this search."
          : "No connectors found yet. Add a connection or refresh its inventory in your host app."}</p>
      ) : (
        <div className="mt-4">
          {visible.map((item) => (
            <CustomExtensionRow key={item.cli_id} item={item} onOpen={props.onOpen} />
          ))}
        </div>
      )}
      {added.length > 25 ? <nav aria-label="Custom extension pages" className="mt-4 flex flex-wrap items-center gap-3">
        <button type="button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}
          className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold disabled:opacity-50">Previous</button>
        <span className="text-sm text-brand-dark/75">Page {currentPage + 1} of {Math.ceil(added.length / 25)}</span>
        <button type="button" disabled={(currentPage + 1) * 25 >= added.length} onClick={() => setPage(currentPage + 1)}
          className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold disabled:opacity-50">Next</button>
      </nav> : null}
    </section>
  );
}

export function AddCustomExtensionButton(props: { onClick: () => void }) {
  return (
    <button type="button" onClick={props.onClick} className="inline-flex min-h-11 items-center gap-2 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark">
      <HiMiniPlus className="size-4" aria-hidden="true" />
      Add custom extension
    </button>
  );
}

function CustomExtensionRow(props: { item: LocalCliItem; onOpen: (cliId: string) => void }) {
  const handleOpen = useCallback(() => {
    props.onOpen(props.item.cli_id);
  }, [props]);
  const continuity = continuityCopy(props.item);
  const catalog = mcpCatalogCopy(props.item);
  return (
    <ProtectionModuleRow
      extensionId={props.item.cli_id}
      name={props.item.name}
      description={catalog
        ? [props.item.source_label, catalog.title].filter(Boolean).join(" · ")
        : props.item.source_label ? `${props.item.example_label} · ${props.item.source_label}` : props.item.example_label}
      behavior={continuity ? `${continuity.title}. ${continuity.description}` : customExtensionStateLabel(props.item)}
      custom
      executables={[props.item.name]}
      onOpen={handleOpen}
    />
  );
}

export function LocalCliDetail(props: {
  item: LocalCliItem;
  revision: number;
  continuity: LocalCliListResponse["cloud"];
  nativePublication?: LocalCliListResponse["native_publication"];
  onBack: () => void;
  onRefresh: () => Promise<void>;
}) {
  const { resolvedApprovalGate, resolveApprovalGate, refreshApprovalGate } = useResolvedApprovalGate(null);
  const [pending, setPending] = useState<LocalCliState | null>(null);
  const [commands, setCommands] = useState(props.item.commands);
  const [providerDrafts, setProviderDrafts] = useState<Record<string, ProviderActionDraft>>({});
  const previousItem = useRef(props.item);
  const [busy, setBusy] = useState(false);
  const [catalogBusy, setCatalogBusy] = useState(false);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const catalogController = useRef<AbortController | null>(null);
  useEffect(() => () => catalogController.current?.abort(), []);
  const [error, setError] = useState<string | null>(null);
  const added = props.item.state !== "unset";
  const commandChanges = commandPermissionChanges(props.item.commands, commands);
  const commandsDirty = commandChanges.length > 0;
  useEffect(() => {
    const previous = previousItem.current;
    if (previous.cli_id !== props.item.cli_id || previous.identity_hash !== props.item.identity_hash) {
      setPending(null);
      setProviderDrafts({});
      setCatalogError(null);
      setError(previous.cli_id === props.item.cli_id ? "This extension changed. Review its permissions again." : null);
    }
    setCommands((current) => previous.cli_id === props.item.cli_id && previous.identity_hash === props.item.identity_hash
      ? rebaseCommandDraft(current, previous.commands, props.item.commands,
        previous.mcp_catalog?.revision !== props.item.mcp_catalog?.revision ? props.item.mcp_catalog?.changes?.changed : [])
      : props.item.commands);
    previousItem.current = props.item;
  }, [props.item]);
  const openPending = useCallback(async (state: LocalCliState) => {
    await refreshApprovalGate();
    setPending(state);
  }, [refreshApprovalGate]);
  const requestAdd = useCallback(() => openPending("allowed"), [openPending]);
  const requestAllow = useCallback(() => openPending("allowed"), [openPending]);
  const requestBlock = useCallback(() => openPending("blocked"), [openPending]);
  const requestRemove = useCallback(() => openPending("unset"), [openPending]);
  const requestSaveCommands = useCallback(() => {
    openPending(props.item.state === "blocked" ? "blocked" : "allowed");
  }, [openPending, props.item.state]);
  const handleCommandState = useCallback((commandId: string, state: LocalCliCommandState) => {
    setCommands((current) => withCommandState(current, commandId, state));
  }, []);
  const applyBulk = useCallback((state: LocalCliCommandState) => {
    setCommands((current) => applyBulkCommandState(
      current,
      state,
      props.item.surface === "package-scripts" ? new Set(["root", "other"])
        : props.item.surface === "mcp"
          ? new Set(current.filter((command) => !mcpToolCanReceiveDirectAllow(command)).map((command) => command.command_id))
          : new Set(),
    ));
  }, [props.item.surface]);
  const bulkTargets = props.item.surface === "package-scripts"
    ? enrollablePackageScriptCommands(commands)
    : props.item.surface === "mcp" ? commands.filter(mcpToolCanReceiveDirectAllow) : commands;
  const bulkState = bulkCommandState(bulkTargets);
  const bulkCopy = bulkPolicyCopy(props.item.surface);
  const continuity = customExtensionContinuityView("local-only");
  const catalog = mcpCatalogCopy(props.item);
  const refreshCatalog = useCallback(async () => {
    const controller = new AbortController();
    catalogController.current = controller;
    setCatalogBusy(true);
    setCatalogError(null);
    try {
      await refreshMcpInventory(props.item.cli_id, controller.signal);
      if (!controller.signal.aborted) await props.onRefresh();
    } catch (caught) {
      if (!controller.signal.aborted) setCatalogError(caught instanceof Error ? caught.message : "Guard could not refresh this connector. Try again.");
    } finally {
      setCatalogBusy(false);
      if (catalogController.current === controller) catalogController.current = null;
    }
  }, [props.item.cli_id, props.onRefresh]);
  const clearPending = useCallback(() => {
    if (!busy) setPending(null);
  }, [busy]);
  const confirmChange = useCallback(async (credentials: { approval_password?: string; approval_totp_code?: string }) => {
    if (pending === null) return;
    setBusy(true);
    setError(null);
    try {
      const payload = {
        cli_id: props.item.cli_id,
        identity_hash: props.item.identity_hash,
        name: props.item.name,
        kind: props.item.kind,
        example_label: props.item.example_label,
        interpreter_name: props.item.interpreter_name,
        state: pending,
        previous_revision: props.revision,
        session_nonce: randomToken(),
        commands: commandStatesPayload(commands),
        ...(pending !== "unset" && Object.keys(providerDrafts).length > 0
          ? { provider_actions: Object.values(providerDrafts) } : {}),
        ...credentials,
      };
      await previewLocalCliMutation(payload);
      await applyLocalCliMutation(payload);
      setProviderDrafts({});
      await props.onRefresh();
      await refreshApprovalGate();
      setPending(null);
    } catch (caught) {
      setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not update this custom extension.");
    } finally {
      setBusy(false);
    }
  }, [commands, providerDrafts, pending, props, refreshApprovalGate]);

  useEffect(() => {
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      setError("Guard could not load the local approval settings yet.");
    });
  }, [resolveApprovalGate]);

  return (
    <div data-testid="local-cli-detail" className="w-full">
      <button type="button" onClick={props.onBack} className="inline-flex min-h-11 items-center gap-2 rounded-lg px-1 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark">
        <HiMiniArrowLeft className="size-4" aria-hidden="true" />
        Extensions
      </button>
      <header className="mt-4 border-b border-slate-200 pb-6">
        {props.item.surface !== "mcp" ? (
          <p className="font-mono text-xs font-semibold tracking-[0.14em] text-slate-400">{props.item.example_label}</p>
        ) : null}
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-brand-dark">{props.item.name}</h1>
        {props.item.surface === "mcp" && props.item.source_label ? (
          <p className="mt-2 text-sm text-slate-600">{props.item.source_label}</p>
        ) : null}
        <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">{customExtensionStateLabel(props.item)}</p>
        {continuityCopy(props.item) ? (
          <div className="mt-3 max-w-2xl rounded-xl border border-slate-200 bg-slate-50 p-3" data-testid="custom-extension-continuity">
            <p className="text-sm font-semibold text-brand-dark">{continuityCopy(props.item)?.title}</p>
            <p className="mt-1 text-sm leading-6 text-slate-600">{continuityCopy(props.item)?.description}</p>
          </div>
        ) : null}
        <p className="mt-3 max-w-2xl text-sm leading-6 text-brand-dark/75">
          {detailPolicyCopy(props.item.surface)}
        </p>
        <div className="mt-5 flex flex-wrap gap-3">
          {added ? (
            <>
              {props.item.state === "allowed" ? (
                <p className="inline-flex min-h-11 items-center rounded-xl bg-slate-100 px-4 text-sm font-semibold text-brand-dark">
                  {props.item.surface === "mcp" ? "Tool permissions saved" : "Allowed on this device"}
                </p>
              ) : (
                <button type="button" className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white" onClick={requestAllow}>
                  {props.item.surface === "mcp" ? "Enable tool permissions" : "Allow this extension's commands"}
                </button>
              )}
              {props.item.state === "blocked" ? (
                <p className="inline-flex min-h-11 items-center rounded-xl bg-slate-100 px-4 text-sm font-semibold text-brand-dark">
                  Blocked
                </p>
              ) : (
                <button type="button" className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark" onClick={requestBlock}>
                  Block this extension
                </button>
              )}
              <button type="button" className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark/80" onClick={requestRemove}>
                Remove custom extension
              </button>
            </>
          ) : (
            <button type="button" className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white" onClick={requestAdd}>
              Add custom extension
            </button>
          )}
        </div>
      </header>
      {props.item.surface === "mcp" && added ? (
        <section className="mt-5 rounded-xl border border-slate-200 p-4" aria-labelledby="mcp-publication-heading">
          <h2 id="mcp-publication-heading" className="text-sm font-semibold text-brand-dark">Enforcement status</h2>
          <p role="status" className="mt-2 text-sm leading-6 text-brand-dark/75">
            {props.nativePublication?.state === "acknowledged"
              ? `Native policy acknowledged saved revision ${props.nativePublication.revision}. Live calls still check connection and tool authority.`
              : props.nativePublication?.state === "pending"
                ? "Your choices are saved. Waiting for the native runtime to acknowledge this revision."
                : props.nativePublication?.state === "failed"
                  ? "Your choices are saved, but native publication failed. Enforcement readiness is not confirmed."
                  : "Your choices are saved. Native enforcement readiness has not been confirmed."}
          </p>
          {props.nativePublication?.state !== "acknowledged" ? (
            <button type="button" className="mt-3 min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark"
              disabled={busy || catalogBusy} onClick={() => void props.onRefresh()}>
              Check enforcement status
            </button>
          ) : null}
        </section>
      ) : null}
      {catalog ? (
        <section className="mt-6 border-b border-slate-200 pb-5" aria-labelledby="mcp-inventory-heading" aria-busy={catalogBusy}>
          <h2 id="mcp-inventory-heading" className="text-sm font-semibold text-brand-dark">{catalog.title}</h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-brand-dark/75">{catalog.description}</p>
          <p className="mt-2 text-xs leading-5 text-brand-dark/75">Refresh starts this connection’s configured server to list tools. It does not grant execution permission.</p>
          <button
            type="button"
            onClick={refreshCatalog}
            disabled={busy || catalogBusy || pending !== null}
            className="mt-3 inline-flex min-h-11 items-center rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark disabled:cursor-wait disabled:opacity-50"
          >
            {catalogBusy ? "Refreshing inventory…" : "Refresh inventory"}
          </button>
          {catalogBusy ? <button type="button" onClick={() => catalogController.current?.abort()}
            className="ml-3 min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-brand-dark">Cancel refresh</button> : null}
          {catalogError ? <p role="alert" className="mt-3 max-w-2xl text-sm leading-6 text-red-700">{catalogError}</p> : null}
          {props.item.mcp_catalog ? (
            <p className="mt-2 text-xs leading-5 text-brand-dark/75">
              Last discovery attempt: <time dateTime={props.item.mcp_catalog.updated_at}>
                {new Date(props.item.mcp_catalog.updated_at).toLocaleString()}
              </time>
            </p>
          ) : null}
          {props.item.mcp_catalog?.changes && Object.values(props.item.mcp_catalog.changes).some((names) => names.length > 0) ? (
            <details className="mt-3 text-sm text-brand-dark/75" open>
              <summary className="min-h-11 cursor-pointer py-3 font-semibold">Changes from the last inventory</summary>
              <p className="max-w-2xl leading-6">
                New and changed tools need review. Removed tools lose Allow; their Deny choices remain.
                Stale tools have not been confirmed by this discovery attempt.
              </p>
              <dl className="mt-3 grid gap-3 sm:grid-cols-2">
                {([
                  ["added", "New tools"], ["changed", "Changed authority"],
                  ["removed", "Removed tools"], ["stale", "Not confirmed"],
                ] as const).map(([key, label]) => {
                  const names = props.item.mcp_catalog?.changes?.[key] ?? [];
                  return names.length > 0 ? (
                    <div key={key}>
                      <dt className="font-semibold">{label} · {names.length}</dt>
                      <dd className="mt-1 break-words leading-6">
                        {names.slice(0, 10).join(", ")}{names.length > 10 ? ` and ${names.length - 10} more` : ""}
                      </dd>
                    </div>
                  ) : null;
                })}
              </dl>
            </details>
          ) : null}
          <details className="mt-3 text-sm text-brand-dark/75">
            <summary className="min-h-11 cursor-pointer py-3 font-semibold">Connection details</summary>
            <p className="break-all font-mono text-xs leading-6">{props.item.example_label}</p>
            <p className="mt-2">Protocol: {props.item.mcp_catalog?.protocol_version ?? "Not verified"}</p>
            <p className="mt-2">Permission scope: {props.item.permission_scope === "configured-connection"
              ? "This configured host connection. Provider account not verified."
              : props.item.permission_scope === "host-namespace"
                ? "This connector namespace in its host. Account changes cannot currently be verified."
                : props.item.permission_scope === "legacy-device"
                  ? "This server identity across this device. This is a legacy setting."
                  : "Not verified. Prefer Ask while the connection is unresolved."}</p>
          </details>
        </section>
      ) : null}
      {props.item.mcp_catalog?.skills_catalog?.declared ? <McpDeclaredSkills
        cliId={props.item.cli_id} identityHash={props.item.identity_hash} revision={props.item.mcp_catalog.revision}
        knownCount={props.item.mcp_catalog.skills_catalog.known_count} complete={props.item.mcp_catalog.skills_catalog.complete}
      /> : null}
      {props.item.provider_catalog ? (
        <>
          <McpProviderActions key={props.item.cli_id + props.item.identity_hash}
            cliId={props.item.cli_id} knownCount={props.item.provider_catalog.known_count}
            disabled={busy} authorityRevision={props.revision} drafts={providerDrafts}
            onChange={(action, state) => {
              if (!(action.tool_slug in providerDrafts) && Object.keys(providerDrafts).length >= 100) {
                setError("Review and save these 100 action changes before changing more.");
                return;
              }
              setProviderDrafts((current) => ({
                ...current, [action.tool_slug]: { tool_slug: action.tool_slug, state, revision: action.revision },
              }));
            }} />
          <ProviderWorkflows key={`workflow-${props.item.cli_id}-${props.item.identity_hash}`}
            cliId={props.item.cli_id} />
          {Object.keys(providerDrafts).length > 0 ? (
            <button type="button" disabled={busy}
              className="mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white"
              onClick={requestSaveCommands}>Review {Object.keys(providerDrafts).length} action changes</button>
          ) : null}
        </>
      ) : null}
      <section className="mt-6 rounded-2xl border border-slate-200 bg-slate-50 p-4" aria-labelledby="custom-extension-continuity-heading">
        <h2 id="custom-extension-continuity-heading" className="text-sm font-semibold text-brand-dark">{continuity.title}</h2>
        <p className="mt-2 text-sm leading-6 text-brand-dark/75">{props.continuity.summary || continuity.description}</p>
        <p className="mt-2 text-xs leading-5 text-brand-dark/60">{continuity.privacyDisclosure}</p>
      </section>
      {added ? (
        <section className="mt-8" aria-labelledby="custom-extension-commands-heading">
          <h2 id="custom-extension-commands-heading" className="text-lg font-semibold text-brand-dark">
            {detailCatalogHeading(props.item.surface)}
          </h2>
          <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-500">
            {detailCatalogHelper(props.item.surface)}
          </p>
          {bulkTargets.length > 0 ? (
            <BulkPolicyPicker
              value={bulkState}
              disabled={busy}
              onChange={applyBulk}
              groupLabel={bulkCopy.groupLabel}
              allowLabel={props.item.surface === "mcp" ? "Allow listed" : undefined}
              blockLabel={props.item.surface === "mcp" ? "Deny listed" : undefined}
              mcpPolicy={props.item.surface === "mcp"}
              mixedCopy={bulkCopy.mixedCopy}
            />
          ) : null}
          {props.item.surface === "mcp" && bulkTargets.length > 0 ? (
            <p className="mt-2 text-xs leading-5 text-brand-dark/75">
              Bulk choices apply to {bulkTargets.length} listed {bulkTargets.length === 1 ? "tool" : "tools"} with direct permissions.
              Execution wrappers and unlisted tools keep their separate review settings.
            </p>
          ) : null}
          <div className="mt-4">
            <CustomExtensionCommandList
              commands={commands}
              disabled={busy}
              surface={props.item.surface}
              onChange={handleCommandState}
            />
          </div>
          {commandsDirty ? (
            <button type="button" className="mt-4 min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white" onClick={requestSaveCommands}>
              Review {commandChanges.length} {props.item.surface === "mcp" ? "tool" : "command"} changes
            </button>
          ) : null}
        </section>
      ) : null}
      {error && !pending ? <div className="mt-4"><InlineError message={error} /></div> : null}
      {pending ? (
        <CustomExtensionReviewModal
          item={props.item}
          nextState={pending}
          commandChanges={pending === "unset" ? [] : commandChanges}
          providerUpdates={pending === "unset" ? [] : Object.values(providerDrafts)}
          busy={busy}
          error={error}
          approvalGate={resolvedApprovalGate}
          onCancel={clearPending}
          onConfirm={confirmChange}
        />
      ) : null}
    </div>
  );
}

function CustomExtensionReviewModal(props: {
  item: LocalCliItem;
  nextState: LocalCliState;
  commandChanges: ReturnType<typeof commandPermissionChanges>;
  providerUpdates: ProviderActionDraft[];
  busy: boolean;
  error: string | null;
  approvalGate: GuardApprovalGatePublicConfig | null;
  onCancel: () => void;
  onConfirm: (credentials: { approval_password?: string; approval_totp_code?: string }) => void;
}) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const dialogRef = useModalDialog<HTMLFormElement>(props.onCancel, !props.busy);
  const title = props.providerUpdates.length > 0 ? "Review app action permissions" : reviewTitle(props.item.name, props.nextState);
  const handlePassword = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setPassword(event.target.value);
  }, []);
  const handleTotp = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    const digits = event.target.value.replace(/\D/g, "").slice(0, 6);
    event.target.value = digits;
    setTotp(digits);
  }, []);
  const handleSubmit = useCallback((event: FormEvent) => {
    event.preventDefault();
    props.onConfirm(buildApprovalProofCredentials(props.approvalGate, {
      approvalPassword: password,
      approvalTotpCode: totp,
    }));
  }, [password, props, totp]);
  const submitDisabled = isApprovalProofSubmitDisabled(
    props.approvalGate,
    { approvalPassword: password, approvalTotpCode: totp },
    props.busy,
  );
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/45 p-4 backdrop-blur-sm">
      <form ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="custom-extension-review-title" onSubmit={handleSubmit} className="max-h-[calc(100dvh-2rem)] w-full max-w-lg overflow-y-auto rounded-3xl bg-white p-6 shadow-2xl focus:outline-none">
        <h2 id="custom-extension-review-title" className="text-xl font-semibold text-brand-dark">{title}</h2>
        <p className="mt-2 text-sm leading-6 text-brand-dark/80">
          {reviewModalDetail(props.approvalGate)}
        </p>
        {props.item.surface === "mcp" ? <div className="mt-3 text-sm leading-6 text-brand-dark">
          <p>{props.item.source_label || "This host"} · This configured connection</p>
          <p>{props.nextState === "blocked" ? "The connection will deny every tool, including tools listed as Allow."
            : props.nextState === "unset" ? "Saved connection permissions will be removed. Future calls return to Guard policy."
              : "Unknown and future tools still require review. These choices do not verify the provider account."}</p>
        </div> : null}
        {props.commandChanges.length > 0 ? <section aria-label="Permission changes" className="mt-4 text-sm leading-6 text-brand-dark">
          <p className="font-semibold">{props.commandChanges.length} {props.item.surface === "mcp" ? "tool" : "command"} changes</p>
          <ul className="mt-2 max-h-48 space-y-2 overflow-y-auto">
            {props.commandChanges.map((change) => <li key={change.commandId} className="break-words">
              {change.name}: {permissionLabel(change.before)} → {permissionLabel(change.after)}
            </li>)}
          </ul>
        </section> : null}
        {props.providerUpdates.length > 0 ? (
          <div className="mt-3 max-h-48 overflow-y-auto text-sm leading-6 text-brand-dark">
            <p>{props.providerUpdates.length} action changes for this host connection, across all accounts.</p>
            <ul className="mt-2 space-y-1">
              {props.providerUpdates.map((update) => (
                <li key={update.tool_slug} className="break-words">
                  {update.tool_slug.replaceAll("_", " ").toLowerCase()} → {update.state === "block" ? "Deny" : "Ask"}
                </li>
              ))}
            </ul>
            <p className="mt-2">Any Deny also blocks opaque workbench execution. Allow is unavailable until the account is verified.</p>
          </div>
        ) : null}
        <div className="mt-5">
          <ApprovalProofFieldInputs
            approvalGate={props.approvalGate}
            approvalPassword={password}
            approvalTotpCode={totp}
            onApprovalPasswordChange={handlePassword}
            onApprovalTotpCodeChange={handleTotp}
          />
        </div>
        {props.error ? <div className="mt-4"><InlineError message={props.error} /></div> : null}
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" disabled={props.busy} onClick={props.onCancel} className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark">Cancel</button>
          <button type="submit" disabled={submitDisabled} className="min-h-11 rounded-xl bg-brand-blue px-5 text-sm font-semibold text-white disabled:opacity-60">
            {props.busy ? "Saving…" : "Confirm"}
          </button>
        </div>
      </form>
    </div>
  );
}

function permissionLabel(state: LocalCliCommandState | null): string {
  return state === "allow" ? "Allow" : state === "block" ? "Deny" : state === "review" ? "Ask"
    : state === "inherit" ? "Policy" : "Not previously listed";
}

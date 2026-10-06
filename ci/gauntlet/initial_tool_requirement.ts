// Require one real tool attempt on the first eligible provider request through
// the OpenAI-compatible `tool_choice: "required"` contract the pinned OMP host
// already serializes. The latch is consumed by that first tool-bearing request
// regardless of any caller-set choice — `auto`, `none`, a named tool or an
// explicit `required` all discharge it unchanged — so no later round can gain a
// forced call after a real tool result. Completion content is never touched.
//
// Requests without a `tools` array stay unchanged so OMP's own tool-less
// handling still applies. Scoping rides the payload boundary itself: the
// sender's compat layer may split a round into an early retry whose payload
// never reaches this hook, and internal side requests do not always emit it.
// If a provider rejects or ignores `required`, the round fails or records
// `not-exercised` with the shipped choice in evidence; the requirement is
// never dropped to chase a pass.
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

interface RequestPayload {
  tools?: unknown;
  tool_choice?: unknown;
  [key: string]: unknown;
}

function isPayload(value: unknown): value is RequestPayload {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

/** Validate a nonempty function-tool list before requiring a tool choice. */
function offersTool(payload: unknown): boolean {
  if (!isPayload(payload) || !Array.isArray(payload.tools) || payload.tools.length === 0) return false;
  return payload.tools.every(
    tool =>
      isPayload(tool) &&
      tool.type === "function" &&
      isPayload(tool.function) &&
      typeof tool.function.name === "string",
  );
}

/**
 * The first eligible tool-bearing request gains `tool_choice: "required"` and
 * discharges the latch, whatever the caller set. Nothing else is rewritten.
 */
export function applyInitialToolRequirement(armed: { initial: boolean }, payload: unknown): unknown {
  if (!armed.initial || !offersTool(payload)) return undefined;
  armed.initial = false;
  const request = payload as RequestPayload;
  if (request.tool_choice !== undefined) return undefined; // caller choice passes verbatim
  request.tool_choice = "required";
  return request;
}

export default function initialToolRequirement(pi: ExtensionAPI): void {
  const armed = { initial: true };
  pi.on("before_provider_request", event => applyInitialToolRequirement(armed, event.payload));
}

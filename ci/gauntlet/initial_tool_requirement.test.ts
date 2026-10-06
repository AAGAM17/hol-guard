import { expect, test } from "bun:test";
import { applyInitialToolRequirement } from "./initial_tool_requirement";

const tools = [{ type: "function", function: { name: "bash" } }];

function outbound(state: { initial: boolean }, payload: Record<string, unknown>): Record<string, unknown> {
  return (applyInitialToolRequirement(state, payload) ?? payload) as Record<string, unknown>;
}

test("only the initial tool request is required; tool-result follow-ups may finish freely", () => {
  const state = { initial: true };
  expect(outbound(state, { tools }).tool_choice).toBe("required");
  expect(outbound(state, { tools, tool_choice: "auto" }).tool_choice).toBe("auto");
  expect(outbound(state, { tools }).tool_choice).toBeUndefined();
});

test("an explicit initial caller choice is preserved and never forces a later round", () => {
  for (const choice of ["auto", "none", { type: "function", function: { name: "bash" } }, "required"]) {
    const state = { initial: true };
    expect(outbound(state, { tools, tool_choice: choice }).tool_choice).toEqual(choice);
    expect(outbound(state, { tools }).tool_choice).toBeUndefined();
  }
});

test("non-tool and malformed requests do not consume the initial real-tool requirement", () => {
  for (const payload of [{ messages: [] }, { tools: [] }, { tools: "bash" }, { tools: [{ type: "function" }] }]) {
    const state = { initial: true };
    applyInitialToolRequirement(state, payload);
    expect(outbound(state, { tools }).tool_choice).toBe("required");
  }
});

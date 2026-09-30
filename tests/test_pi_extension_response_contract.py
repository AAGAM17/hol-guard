"""Focused runtime contract tests for the generated Pi/OMP hook extension."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon.hook_worker_native import _watch_native_post_tool_result
from codex_plugin_scanner.guard.daemon.hook_worker_responses import (
    harness_json_from_native_pre_tool,
    observe_lifecycle_fail_safe_response,
)
from codex_plugin_scanner.guard.runtime.actions import normalize_harness_payload
from codex_plugin_scanner.guard.runtime.hook_content_scanner import ContentScanner
from codex_plugin_scanner.guard.runtime.hook_decision_cache import HookDecisionCache
from codex_plugin_scanner.guard.runtime.hook_review_engine import HookReviewEngine
from codex_plugin_scanner.guard.runtime.hook_review_types import HookReviewRequest, HookSourceFileRef
from codex_plugin_scanner.guard.runtime.hook_source_read import evaluate_source_file_ref, sha256_text
from codex_plugin_scanner.guard.store import GuardStore


def _generated_source(tmp_path: Path, *, harness: str = "omp") -> str:
    return managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
        harness=harness,
        display_name="Oh My Pi",
    )


def _strip_generated_types(fragment: str) -> str:
    replacements = {
        "const errorPayload = JSON.parse(errorBody) as { error?: unknown };":
            "const errorPayload = JSON.parse(errorBody);",
        "function compactHookEventName(value: unknown): string {": "function compactHookEventName(value) {",
        "function normalizeGuardResponse(value: unknown): GuardResponse | null {":
            "function normalizeGuardResponse(value) {",
        """function daemonResponseCanReturn(
  payload: Record<string, unknown>,
  response: GuardResponse,
): boolean {""": """function daemonResponseCanReturn(
  payload,
  response,
) {""",
        "  payload: Record<string, unknown>,": "  payload,",
        "  cwd?: string,": "  cwd,",
        "  options?: { enforceSizeCap?: boolean; deadlineAt?: number },": "  options,",
        "  reasonCode: string,": "  reasonCode,",
        "  reason: string,": "  reason,",
        "): GuardResponse {": ") {",
        "): Promise<GuardDaemonAttempt> {": ") {",
        "): Promise<GuardResponse> {": ") {",
        """async function daemonGuardResponse(
  serializedPayload: string,
  cwd?: string,
  timeoutMs: number = GUARD_DAEMON_TIMEOUT_MS,
  deadlineAt?: number,
): Promise<GuardDaemonAttempt> {""": """async function daemonGuardResponse(
  serializedPayload,
  cwd,
  timeoutMs = GUARD_DAEMON_TIMEOUT_MS,
  deadlineAt,
) {""",
        """async function runGuard(
  payload: Record<string, unknown>,
  cwd?: string,
  options?: { enforceSizeCap?: boolean; deadlineAt?: number },
): Promise<GuardResponse> {""": """async function runGuard(
  payload,
  cwd,
  options,
) {""",
        "let result: GuardCliResult | null = null;": "let result = null;",
        " as unknown": "",
        " as Record<string, unknown>": "",
        " as GuardResponse": "",
        " as { decision?: unknown }": "",
        """ as {
          error?: unknown;
        }""": "",
    }
    for old, new in replacements.items():
        fragment = fragment.replace(old, new)
    fragment = fragment.replace("  serializedPayload: string,", "  serializedPayload,")
    fragment = fragment.replace(
        "  timeoutMs: number = GUARD_DAEMON_TIMEOUT_MS,",
        "  timeoutMs = GUARD_DAEMON_TIMEOUT_MS,",
    )
    fragment = fragment.replace("  deadlineAt?: number,", "  deadlineAt,")
    return fragment


def _run_generated_fixture(source: str) -> dict[str, object]:
    helper_start = source.index("function normalizeGuardResponse(")
    helper_end = source.index("\n\nfunction loadGuardDaemonConnection(", helper_start)
    helper = _strip_generated_types(source[helper_start:helper_end])

    daemon_start = source.index("async function daemonGuardResponse(")
    daemon_end = source.index("\n\nasync function runGuard(", daemon_start)
    daemon = _strip_generated_types(source[daemon_start:daemon_end])

    run_start = source.index("async function runGuard(")
    run_end = source.index("\n\nfunction modelVisibleBlockedReason(", run_start)
    run_guard = _strip_generated_types(source[run_start:run_end])

    javascript = f"""\
const GUARD_DAEMON_TIMEOUT_MS = 3100;
const GUARD_HOME = "/tmp/omp-hook-contract/guard-home";
const GUARD_HOME_DIR_IS_DEFAULT = true;
const GUARD_HOME_DIR = "";
const GUARD_TEXT_LIMIT_CHARS = 12000;
const GUARD_TIMEOUT_MS = 4250;
const GUARD_DEADLINE_RESERVE_MS = 250;
const GUARD_DAEMON_RECOVERY_TIMEOUT_MS = 250;
const GUARD_DAEMON_RETRY_TIMEOUT_MS = 150;
const GUARD_CLI_TIMEOUT_MS = 300;
const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;
const GUARD_CONTENT_ITEM_LIMIT = 24;
const GUARD_OBJECT_KEY_LIMIT = 24;
const GUARD_MAX_DEPTH = 24;
const GUARD_MAX_SERIALIZED_PAYLOAD_CHARS = 24000;
const OUTPUT_TEXT_KEYS = ["stdout", "stderr", "output", "content", "result", "message", "text"];
const GUARD_ARGS = [];
const GUARD_CLI_WRAPPER_COMMAND = "hol-guard";
const GUARD_CLI_WRAPPER_ARGS = [];
const GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS = false;
let guardCliContainmentFailed = false;
let guardCliEvaluationInFlight = false;
let daemonMode = "transport";
let fetchBodies = [];
let cliResult = {{ status: 0, stdout: "", stderr: "" }};
let daemonCalls = 0;
let recoveryCalls = 0;
let cliCalls = 0;

function loadGuardDaemonConnection() {{
  daemonCalls += 1;
  if (daemonMode === "transport") return null;
  if (daemonMode === "retry-transport" && daemonCalls === 1) return null;
  return {{ port: 1, authToken: "fixture-token" }};
}}

async function recoverGuardDaemon() {{
  recoveryCalls += 1;
  return daemonMode === "retry-transport" || daemonMode === "retry-shape";
}}

async function runGuardCliCommand() {{
  cliCalls += 1;
  return cliResult;
}}

function responseBody(value) {{
  let used = false;
  return {{
    getReader() {{
      return {{
        async read() {{
          if (used) return {{ done: true, value: undefined }};
          used = true;
          return {{ done: false, value: new TextEncoder().encode(value) }};
        }},
        async cancel() {{ used = true; }},
        releaseLock() {{}},
      }};
    }},
  }};
}}

globalThis.fetch = async () => {{
  const value = fetchBodies.shift() ?? "";
  return {{
    ok: true,
    status: 200,
    body: responseBody(value),
    text: async () => value,
  }};
}};

{helper}

{_generated_preprocessing_helper(source)}

{daemon}

{run_guard}

const result = {{}};
daemonMode = "http";
fetchBodies = ["{{\\"decision\\":\\"allow\\"}}"];
result.daemon_allow = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = [
  "{{\\"decision\\":\\"allow\\",\\"policy_action\\":\\"allow\\",\\"reason_code\\":\\"fixture_lifecycle\\"}}",
];
result.daemon_lifecycle_allow = await runGuard({{ hook_event_name: "UserPromptSubmit" }});
fetchBodies = ["{{\\"decision\\":\\"deny\\",\\"reason\\":\\"fixture block\\"}}"];
result.daemon_deny = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = ["", "   "];
result.daemon_empty = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
result.daemon_whitespace = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ["not-json"];
result.daemon_malformed = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = ['{{"decision":"deny","reason":{{"nested":true}}}}'];
result.daemon_malformed_reason = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ['{{"decision":"deny","reason":null}}'];
result.daemon_null_reason = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = ['{{"decision":"deny"}}'];
result.daemon_omitted_reason = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = ['{{"policy_action":"allow"}}'];
result.daemon_shape = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ['[{{"decision":"allow"}}]'];
result.daemon_array = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ['{{"decision":"maybe"}}'];
result.daemon_unknown = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);
fetchBodies = ['{{"decision":"block","reason":"fixture block"}}'];
result.daemon_block = (await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000)).response;
fetchBodies = ["x".repeat(GUARD_MAX_SERIALIZED_PAYLOAD_CHARS + 1)];
result.daemon_oversized_body = await daemonGuardResponse("{{}}", "/tmp", 100, Date.now() + 1000);

daemonMode = "retry-shape";
fetchBodies = ['{{"unknown":"first"}}', '{{"unknown":"second"}}'];
daemonCalls = 0;
recoveryCalls = 0;
cliCalls = 0;
cliResult = {{ status: 0, stdout: "", stderr: "" }};
result.retry_still_malformed = await runGuard({{ hook_event_name: "PreToolUse" }});
result.retry_still_malformed_daemon_calls = daemonCalls;
result.retry_still_malformed_recovery_calls = recoveryCalls;
result.retry_still_malformed_cli_calls = cliCalls;

daemonMode = "retry-shape";
fetchBodies = ['{{"decision":"deny","reason":{{"nested":true}}}}', '{{"decision":"deny","reason":{{"nested":true}}}}'];
daemonCalls = 0;
recoveryCalls = 0;
cliCalls = 0;
result.retry_malformed_reason = await runGuard({{ hook_event_name: "PostToolUse" }});
result.retry_malformed_reason_daemon_calls = daemonCalls;
result.retry_malformed_reason_recovery_calls = recoveryCalls;
result.retry_malformed_reason_cli_calls = cliCalls;

daemonMode = "retry-transport";
fetchBodies = ['{{"decision":"allow"}}'];
daemonCalls = 0;
recoveryCalls = 0;
cliCalls = 0;
result.retry_valid = await runGuard({{ hook_event_name: "PreToolUse" }});
result.retry_valid_daemon_calls = daemonCalls;
result.retry_valid_recovery_calls = recoveryCalls;
result.retry_valid_cli_calls = cliCalls;

daemonMode = "http";
fetchBodies = ['{{"decision":"allow","reason_code":"native_policy_not_ready"}}'];
daemonCalls = 0;
recoveryCalls = 0;
cliCalls = 0;
result.posttool_daemon_allow = await runGuard({{ hook_event_name: "PostToolUse" }});
result.posttool_daemon_allow_daemon_calls = daemonCalls;
result.posttool_daemon_allow_recovery_calls = recoveryCalls;
result.posttool_daemon_allow_cli_calls = cliCalls;

daemonMode = "retry-shape";
fetchBodies = ['{{"decision":"allow"}}', '{{"decision":"allow"}}'];
daemonCalls = 0;
recoveryCalls = 0;
cliCalls = 0;
cliResult = {{
  status: 0,
  stdout: '{{"decision":"allow","model_output_action":"allow_original","reviewed_output_sha256":"cli-digest"}}',
  stderr: "",
}};
result.stale_daemon_cli_success = await runGuard({{ hook_event_name: "PostToolUse" }});
result.stale_daemon_cli_daemon_calls = daemonCalls;
result.stale_daemon_cli_recovery_calls = recoveryCalls;
result.stale_daemon_cli_calls = cliCalls;

daemonMode = "transport";
fetchBodies = [];
cliResult = {{ status: 0, stdout: '{{"policy_action":"allow"}}', stderr: "" }};
result.cli_missing_decision = await runGuard({{ hook_event_name: "PreToolUse" }});
cliResult = {{ status: 0, stdout: "", stderr: "" }};
result.cli_empty_prompt = await runGuard({{ hook_event_name: "UserPromptSubmit" }});
result.cli_empty_post = await runGuard({{ hook_event_name: "PostToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"deny","reason":{{"nested":true}}}}', stderr: "" }};
result.cli_malformed_reason = await runGuard({{ hook_event_name: "PostToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"deny","reason":null}}', stderr: "" }};
result.cli_null_reason = await runGuard({{ hook_event_name: "PostToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"deny"}}', stderr: "" }};
result.cli_omitted_reason = await runGuard({{ hook_event_name: "PostToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"allow","policy_action":"allow"}}', stderr: "" }};
result.cli_lifecycle_allow = await runGuard({{ hook_event_name: "UserPromptSubmit" }});
cliResult = {{ status: 0, stdout: '{{"decision":"allow"}}', stderr: "" }};
result.cli_allow = await runGuard({{ hook_event_name: "PreToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"deny","reason":"fixture block"}}', stderr: "" }};
result.cli_deny = await runGuard({{ hook_event_name: "PreToolUse" }});
cliResult = {{ status: 0, stdout: '{{"decision":"block","reason":"fixture block"}}', stderr: "" }};
result.cli_block_prompt = await runGuard({{ hook_event_name: "UserPromptSubmit" }});
result.cli_block_post = await runGuard({{ hook_event_name: "PostToolUse" }});
cliResult = {{ status: 2, stdout: '{{"decision":"allow"}}', stderr: "cli failed" }};
result.cli_nonzero_allow = await runGuard({{ hook_event_name: "PreToolUse" }});
cliResult = {{ status: null, stdout: '{{"decision":"allow"}}', stderr: "" }};
result.cli_signal_allow = await runGuard({{ hook_event_name: "PreToolUse" }});

console.log(JSON.stringify(result));
"""
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", prefix="omp-hook-contract-", delete=False) as fixture:
        fixture.write(javascript)
        fixture_path = fixture.name
    try:
        completed = subprocess.run(
            ["node", fixture_path],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        Path(fixture_path).unlink(missing_ok=True)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _run_generated_tool_result_fixture(source: str) -> dict[str, object]:
    handler_start = source.index('  pi.on("tool_result"')
    handler_end = source.index("\n  });\n}", handler_start) + len("\n  });")
    handler = source[handler_start:handler_end]
    for old, new in {
        "(event as { input?: Record<string, unknown> })": "event",
        "(event as { toolInput?: Record<string, unknown> })": "event",
        "(event as { arguments?: Record<string, unknown> })": "event",
        "event as Record<string, unknown>": "event",
        "const guardPayload: Record<string, unknown>": "const guardPayload",
        " as string": "",
    }.items():
        handler = handler.replace(old, new)

    javascript = f"""\
import {{ createHash }} from "node:crypto";

const GUARD_CONFIG_PATH = "/tmp/omp-hook-contract/settings.json";
const GUARD_TEXT_LIMIT_CHARS = 12000;
const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;
const GUARD_CONTENT_ITEM_LIMIT = 24;
const GUARD_OBJECT_KEY_LIMIT = 24;
const GUARD_MAX_DEPTH = 24;
const GUARD_MAX_SERIALIZED_PAYLOAD_CHARS = 24000;
const GUARD_TIMEOUT_MS = 4250;
const GUARD_DEADLINE_RESERVE_MS = 250;
const GUARD_STRUCTURED_MAX_BYTES = 64 * 1024;
const GUARD_STRUCTURED_MAX_DEPTH = 8;
const GUARD_STRUCTURED_MAX_NODES = 128;
const GUARD_STRUCTURED_MAX_FIELDS = 64;
const blockedToolResults = new Map();
const handlers = {{}};
const notifications = [];
let guardResponse = {{ decision: "allow", model_output_action: "allow_original" }};

{_generated_preprocessing_helper(source)}
{_generated_structured_helper(source)}

function sourceFileRefForPostToolUse() {{ return null; }}
function toolCallIdKey(value) {{ return typeof value === "string" && value.trim() ? value.trim() : null; }}
function modelVisibleBlockedReason(reason) {{ return `blocked: ${{reason}}`; }}
function blockedToolResult(reason, details) {{
  return {{ content: [{{ type: "text", text: reason }}], details, isError: true }};
}}
function reviewedToolResult(content, details, isError) {{
  const result = {{ content, details }};
  if (isError) result.isError = true;
  return result;
}}
function handlerAbortSignal(ctx) {{
  const candidate = ctx?.signal;
  return candidate && typeof candidate === "object" && typeof candidate.aborted === "boolean"
    && typeof candidate.addEventListener === "function" && typeof candidate.removeEventListener === "function"
    ? candidate : undefined;
}}
async function runGuard(payload, cwd, options) {{
  if (options?.enforceSizeCap === true && !payloadWithinSerializedBudget(payload)) {{
    return {{ decision: "deny", reason_code: "hook_payload_unbounded" }};
  }}
  return guardResponse;
}}
const pi = {{ on(name, handler) {{ handlers[name] = handler; }} }};
{handler}

const event = {{
  toolCallId: "fixture-call",
  toolName: "Bash",
  content: [{{ type: "text", text: "safe inline output" }}],
  details: {{ source: "fixture" }},
  isError: false,
}};
const ctx = {{ cwd: "/tmp", ui: {{ notify(message) {{ notifications.push(message); }} }} }};
const digest = digestOutputText(event.content).sha256;
const result = {{}};

guardResponse = {{ decision: "allow", model_output_action: "allow_original", reviewed_output_sha256: digest }};
result.valid = (await handlers.tool_result(event, ctx)) === undefined;
guardResponse = {{ decision: "allow", reason_code: "native_policy_not_ready" }};
result.missing_directive = (await handlers.tool_result(event, ctx)) === undefined;
guardResponse = {{
  decision: "allow",
  model_output_action: "replace_with_reviewed_excerpt",
  reviewed_excerpt: "reviewed-safe",
}};
result.contradictory_directive = await handlers.tool_result(event, ctx);
guardResponse = {{ decision: "allow", model_output_action: "replace_with_reviewed_excerpt" }};
result.missing_excerpt = await handlers.tool_result(event, ctx);
guardResponse = {{ decision: "allow", model_output_action: "allow_original" }};
result.missing_digest = await handlers.tool_result(event, ctx);
guardResponse = {{ decision: "allow", model_output_action: "allow_original", reviewed_output_sha256: "0".repeat(64) }};
result.mismatched_digest = await handlers.tool_result(event, ctx);

const longEvent = {{ ...event, content: [{{ type: "text", text: "safe".repeat(13000) }}] }};
guardResponse = {{
  decision: "allow",
  model_output_action: "replace_with_reviewed_excerpt",
  notice: "excerpt",
  reason: "reviewed excerpt",
  reviewed_excerpt: "reviewed-long",
}};
result.reviewed_excerpt = await handlers.tool_result(longEvent, ctx);

guardResponse = {{ decision: "allow", observe_mode: true }};
result.observe_mode = (await handlers.tool_result(event, ctx)) === undefined;
console.log(JSON.stringify(result));
"""
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", prefix="omp-tool-result-contract-", delete=False) as fixture:
        fixture.write(javascript)
        fixture_path = fixture.name
    try:
        completed = subprocess.run(
            ["node", fixture_path],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        Path(fixture_path).unlink(missing_ok=True)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _generated_digest_helper(source: str) -> str:
    return _generated_preprocessing_helper(source)


def _generated_preprocessing_helper(source: str) -> str:
    start = source.index("/* HOL Guard bounded preprocessing begins */")
    end = source.index("/* HOL Guard bounded preprocessing ends */", start)
    helper = source[start:end]
    helper = re.sub(r"/\* HOL Guard bounded preprocessing begins \*/\n?", "", helper, count=1)
    helper = re.sub(r"type TraversalBudget = \{.*?\};\n", "", helper, count=1, flags=re.DOTALL)
    helper = helper.replace(
        "type BoundedCodePointPrefix = { text: string; chars: number; complete: boolean };\n",
        "",
    )
    for old, new in {
        "function createTraversalBudget(deadlineAt?: number): TraversalBudget {":
            "function createTraversalBudget(deadlineAt) {",
        "function traversalBudgetReady(budget: TraversalBudget): boolean {":
            "function traversalBudgetReady(budget) {",
        "function consumeTraversalNode(budget: TraversalBudget): boolean {":
            "function consumeTraversalNode(budget) {",
        "function digestOutputText(\n  value: unknown,\n  deadlineAt?: number,\n  budget = createTraversalBudget(deadlineAt),\n): OutputDigest {":  # noqa: E501
            "function digestOutputText(value, deadlineAt, budget = createTraversalBudget(deadlineAt)) {",
        "function boundValue(\n  value: unknown,\n  depth = 0,\n  seen = new WeakSet<object>(),\n  budget = createTraversalBudget(),\n): BoundedValue {":  # noqa: E501
            "function boundValue(value, depth = 0, seen = new WeakSet(), budget = createTraversalBudget()) {",
        "function boundedOutputText(\n  value: unknown,\n  deadlineAt?: number,\n  budget = createTraversalBudget(deadlineAt),\n): BoundedValue {":  # noqa: E501
            "function boundedOutputText(value, deadlineAt, budget = createTraversalBudget(deadlineAt)) {",
        "function boundedCodePointPrefix(\n  value: string,\n  limit: number,\n  budget: TraversalBudget,\n): BoundedCodePointPrefix {":  # noqa: E501
            "function boundedCodePointPrefix(value, limit, budget) {",
        "function appendSafeExcerpt(\n  accumulator: { text: string; truncated: boolean },\n  value: string,\n  budget: TraversalBudget,\n): void {":  # noqa: E501
            "function appendSafeExcerpt(accumulator, value, budget) {",
        "function safeTruncateText(\n  value: string,\n  limit = GUARD_TEXT_LIMIT_CHARS,\n  budget: TraversalBudget = createTraversalBudget(),\n): string {":  # noqa: E501
            "function safeTruncateText(value, limit = GUARD_TEXT_LIMIT_CHARS, budget = createTraversalBudget()) {",
        "function safeCollectOutputText(\n  value: unknown,\n  accumulator: { text: string; truncated: boolean; itemCount: number },\n  depth: number,\n  seen: WeakSet<object>,\n  budget: TraversalBudget,\n): void {":  # noqa: E501
            "function safeCollectOutputText(value, accumulator, depth, seen, budget) {",
        (
            "function boundedResponseText(\n  response: Response,\n"
            "  maxChars: number,\n  deadlineAt?: number,\n): Promise<string | null> {"
        ):
            "function boundedResponseText(response, maxChars, deadlineAt) {",
        "function boundedJsonStringSize(value: string, budget: TraversalBudget): number | null {":
            "function boundedJsonStringSize(value, budget) {",
        (
            "function boundedJsonSize(\n  value: unknown,\n  budget: TraversalBudget,\n"
            "  depth: number,\n  seen: WeakSet<object>,\n  inArray: boolean,\n): number | null {"
        ):
            "function boundedJsonSize(value, budget, depth, seen, inArray) {",
        "function payloadWithinSerializedBudget(payload: Record<string, unknown>, deadlineAt?: number): boolean {":
            "function payloadWithinSerializedBudget(payload, deadlineAt) {",
        "function traverse(val: unknown, depth: number): void {": "function traverse(val, depth) {",
        "const refuse = (): void => {": "const refuse = () => {",
        "  function update(text: string): void {": "  function update(text) {",
        "const seen = new WeakSet<object>();": "const seen = new WeakSet();",
        "const chunk = next.value as Uint8Array;": "const chunk = next.value;",
        "return (async (): Promise<string | null> => {": "return (async () => {",
        "new WeakSet<object>()": "new WeakSet()",
        "const obj = val as object;": "const obj = val;",
        "const objectValue = value as object;": "const objectValue = value;",
        "const record = value as Record<string, unknown>;": "const record = value;",
        "const record = val as Record<string, unknown>;": "const record = val;",
        "const nextItems: unknown[] = [];": "const nextItems = [];",
        "const nextRecord: Record<string, unknown> = {};": "const nextRecord = {};",
    }.items():
        helper = helper.replace(old, new)
    helper = re.sub(r"\s+as (?:object|Record<string, unknown>)", "", helper)
    return helper


def _generated_structured_helper(source: str) -> str:
    start = source.index("function structuredOutputJsonForPostToolUse(")
    end = source.index("\n\nfunction sourcePathFromToolInput(", start)
    helper = source[start:end]
    for old, new in {
        "function structuredOutputJsonForPostToolUse(value: unknown, deadlineAt?: number): string | null {":
            "function structuredOutputJsonForPostToolUse(value, deadlineAt) {",
        "  function hasUnpairedSurrogate(text: string): boolean {":
            "  function hasUnpairedSurrogate(text) {",
        "  function canonicalize(item: unknown, depth: number): unknown {":
            "  function canonicalize(item, depth) {",
        "  const deadlineExceeded = (): boolean => deadlineAt !== undefined && Date.now() >= deadlineAt;":
            "  const deadlineExceeded = () => deadlineAt !== undefined && Date.now() >= deadlineAt;",
        "  const checkDeadline = (): void => {": "  const checkDeadline = () => {",
        "const seen = new WeakSet<object>();": "const seen = new WeakSet();",
        "const record = item as Record<string, unknown>;": "const record = item;",
        "const blockRecord = block as Record<string, unknown>;": "const blockRecord = block;",
        "const parsed = JSON.parse(structuredText) as unknown;": "const parsed = JSON.parse(structuredText);",
        "const normalized = Object.create(null) as Record<string, unknown>;":
            "const normalized = Object.create(null);",
    }.items():
        helper = helper.replace(old, new)
    return helper


def _run_generated_preprocessing_fixture(source: str, body: str) -> dict[str, object]:
    javascript = f"""\
import {{ createHash }} from "node:crypto";

const GUARD_TEXT_LIMIT_CHARS = 12000;
const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;
const GUARD_CONTENT_ITEM_LIMIT = 24;
const GUARD_OBJECT_KEY_LIMIT = 24;
const GUARD_MAX_DEPTH = 24;
const GUARD_MAX_SERIALIZED_PAYLOAD_CHARS = 24000;

{_generated_preprocessing_helper(source)}

{body}
"""
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", prefix="omp-preprocessing-contract-", delete=False) as fixture:
        fixture.write(javascript)
        fixture_path = fixture.name
    try:
        completed = subprocess.run(
            ["node", fixture_path],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        Path(fixture_path).unlink(missing_ok=True)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _run_generated_callback_payload(
    source: str,
    content: object,
    guard_response: dict[str, object],
    *,
    include_signal: bool = True,
    abort_before_guard: bool = False,
    abort_during_guard: bool = False,
    abort_during_structured_proof: bool = False,
    expire_during_structured_proof: bool = False,
    guard_timeout_ms: int = 4250,
) -> dict[str, object]:
    handler_start = source.index('  pi.on("tool_result"')
    handler_end = source.index("\n  });\n}", handler_start) + len("\n  });")
    handler = source[handler_start:handler_end]
    for old, new in {
        "(event as { input?: Record<string, unknown> })": "event",
        "(event as { toolInput?: Record<string, unknown> })": "event",
        "(event as { arguments?: Record<string, unknown> })": "event",
        "event as Record<string, unknown>": "event",
        "const guardPayload: Record<string, unknown>": "const guardPayload",
        " as string": "",
    }.items():
        handler = handler.replace(old, new)

    event_json = json.dumps(
        {
            "toolCallId": "fixture-call",
            "toolName": "Bash",
            "content": content,
            "details": {"source": "fixture"},
            "isError": False,
        }
    )
    response_json = json.dumps(guard_response)
    javascript = f"""\
import {{ createHash }} from "node:crypto";

const GUARD_CONFIG_PATH = "/tmp/omp-hook-contract/settings.json";
const GUARD_TEXT_LIMIT_CHARS = 12000;
const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;
const GUARD_CONTENT_ITEM_LIMIT = 24;
const GUARD_OBJECT_KEY_LIMIT = 24;
const GUARD_MAX_DEPTH = 24;
const GUARD_TIMEOUT_MS = {guard_timeout_ms};
const GUARD_DEADLINE_RESERVE_MS = 250;
const GUARD_STRUCTURED_MAX_BYTES = 64 * 1024;
const GUARD_STRUCTURED_MAX_DEPTH = 8;
const GUARD_STRUCTURED_MAX_NODES = 128;
const GUARD_STRUCTURED_MAX_FIELDS = 64;
const OUTPUT_TEXT_KEYS = ["stdout", "stderr", "output", "content", "result", "message", "text"];
const blockedToolResults = new Map();
const handlers = {{}};
const notifications = [];
let capturedPayload = null;
let capturedSerializedPayload = null;
const guardResponse = JSON.parse({json.dumps(response_json)});
const realDateNow = Date.now;
let forceExpiredDeadline = false;
Date.now = () => forceExpiredDeadline ? realDateNow() + 60_000 : realDateNow();

{_generated_preprocessing_helper(source)}
{_generated_structured_helper(source)}

function sourceFileRefForPostToolUse() {{ return null; }}
function toolCallIdKey(value) {{ return typeof value === "string" && value.trim() ? value.trim() : null; }}
function modelVisibleBlockedReason(reason) {{ return `blocked: ${{reason}}`; }}
function blockedToolResult(reason, details) {{
  return {{ content: [{{ type: "text", text: reason }}], details, isError: true }};
}}
function reviewedToolResult(content, details, isError) {{
  return isError ? {{ content, details, isError: true }} : {{ content, details }};
}}
function handlerAbortSignal(ctx) {{
  const candidate = ctx?.signal;
  return candidate && typeof candidate === "object" && typeof candidate.aborted === "boolean"
    && typeof candidate.addEventListener === "function" && typeof candidate.removeEventListener === "function"
    ? candidate : undefined;
}}
const handlerController = new AbortController();
if ({str(abort_before_guard).lower()}) handlerController.abort();
const handlerSignal = {"handlerController.signal" if include_signal else "undefined"};
if (
  guardResponse.structured_content_mediation &&
  ({str(abort_during_structured_proof).lower()} || {str(expire_during_structured_proof).lower()})
) {{
  const mediation = guardResponse.structured_content_mediation;
  const contentSha256 = mediation.content_sha256;
  Object.defineProperty(mediation, "content_sha256", {{
    configurable: true,
    get() {{
      if ({str(abort_during_structured_proof).lower()}) handlerController.abort();
      if ({str(expire_during_structured_proof).lower()}) forceExpiredDeadline = true;
      return contentSha256;
    }},
  }});
}}
async function runGuard(payload) {{
  if ({str(abort_during_guard).lower()}) handlerController.abort();
  if (!payloadWithinSerializedBudget(payload, Date.now() + GUARD_TIMEOUT_MS - GUARD_DEADLINE_RESERVE_MS)) {{
    return {{ decision: "deny", reason_code: "hook_payload_unbounded" }};
  }}
  capturedSerializedPayload = JSON.stringify(payload);
  capturedPayload = JSON.parse(JSON.stringify(payload));
  return guardResponse;
}}
const pi = {{ on(name, handler) {{ handlers[name] = handler; }} }};
{handler}

const event = JSON.parse({json.dumps(event_json)});
const ctx = {{ cwd: "/tmp", signal: handlerSignal, ui: {{ notify(message) {{ notifications.push(message); }} }} }};
const result = await handlers.tool_result(event, ctx);
console.log(JSON.stringify({{
  payload: capturedPayload,
  serialized_payload: capturedSerializedPayload,
  result,
  preserved: result === undefined,
}}));
"""
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", prefix="omp-callback-contract-", delete=False) as fixture:
        fixture.write(javascript)
        fixture_path = fixture.name
    try:
        completed = subprocess.run(
            ["node", fixture_path],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        Path(fixture_path).unlink(missing_ok=True)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _run_generated_source_ref_fixture(
    source: str,
    content: object,
    path: Path,
) -> dict[str, object]:
    source_path_start = source.index("function sourcePathFromToolInput(")
    source_path_end = source.index("\n\nfunction isVirtualSourcePath(", source_path_start)
    source_path = source[source_path_start:source_path_end].replace(
        "function sourcePathFromToolInput(toolInput: Record<string, unknown>): string | null {",
        "function sourcePathFromToolInput(toolInput) {",
    )
    virtual_start = source.index("function isVirtualSourcePath(")
    virtual_end = source.index("\n\nfunction sourceFileRefForPostToolUse(", virtual_start)
    virtual = source[virtual_start:virtual_end].replace(
        "function isVirtualSourcePath(path: string): boolean {",
        "function isVirtualSourcePath(path) {",
    )
    source_ref_start = source.index("function sourceFileRefForPostToolUse(")
    source_ref_end = source.index("\n\ntype BoundedValue", source_ref_start)
    source_ref = source[source_ref_start:source_ref_end].replace(
        (
            "function sourceFileRefForPostToolUse(\n"
            "  event: Record<string, unknown>,\n"
            "  toolInput: Record<string, unknown>,\n"
            "  digest: OutputDigest,\n"
            "): { version: number; kind: string; path: string; tool_input_path: string; "
            "output_sha256: string; output_chars: number } | null {"
        ),
        """function sourceFileRefForPostToolUse(
  event,
  toolInput,
  digest,
) {""",
    )
    javascript = f"""\
import {{ createHash }} from "node:crypto";

const GUARD_CONFIG_PATH = "/tmp/omp-hook-contract/settings.json";
const GUARD_TEXT_LIMIT_CHARS = 12000;
const GUARD_SOURCE_REF_MAX_OUTPUT_CHARS = 5 * 1024 * 1024;
const GUARD_CONTENT_ITEM_LIMIT = 24;
const GUARD_OBJECT_KEY_LIMIT = 24;
const GUARD_MAX_DEPTH = 24;
const GUARD_STRUCTURED_MAX_BYTES = 64 * 1024;
const GUARD_STRUCTURED_MAX_DEPTH = 8;
const GUARD_STRUCTURED_MAX_NODES = 128;
const GUARD_STRUCTURED_MAX_FIELDS = 64;
const GUARD_SOURCE_REF_ALLOWED_TOOL_NAMES = new Set(["Read"]);
const OUTPUT_TEXT_KEYS = ["stdout", "stderr", "output", "content", "result", "message", "text"];

{_generated_digest_helper(source)}
{_generated_structured_helper(source)}
{source_path}
{virtual}
{source_ref}

const event = {{ toolName: "Read" }};
const toolInput = {{ file_path: {json.dumps(str(path))} }};
const content = JSON.parse({json.dumps(json.dumps(content))});
const digest = digestOutputText(content);
const sourceRef = sourceFileRefForPostToolUse(event, toolInput, digest);
console.log(JSON.stringify({{ digest, sourceRef }}));
"""
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", prefix="omp-source-ref-contract-", delete=False) as fixture:
        fixture.write(javascript)
        fixture_path = fixture.name
    try:
        completed = subprocess.run(
            ["node", fixture_path],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        Path(fixture_path).unlink(missing_ok=True)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_canonical_omp_allow_deny_and_lifecycle_shapes() -> None:
    allow = harness_json_from_native_pre_tool(
        "omp",
        {"decision": "allow", "minimum_action": "allow", "reason_code": "fixture_allow"},
    )
    deny = harness_json_from_native_pre_tool(
        "omp",
        {
            "decision": "deny",
            "minimum_action": "block",
            "reason": "fixture block",
            "reason_code": "fixture_block",
        },
    )
    lifecycle = observe_lifecycle_fail_safe_response(
        "omp",
        event_name="UserPromptSubmit",
        reason_code="fixture_lifecycle",
    )

    assert allow["decision"] == "allow"
    assert deny["decision"] == "deny"
    assert lifecycle == {
        "decision": "allow",
        "policy_action": "allow",
        "reason_code": "fixture_lifecycle",
    }


def test_generated_omp_rejects_ambiguous_success_and_preserves_retry_semantics(tmp_path: Path) -> None:
    result = _run_generated_fixture(_generated_source(tmp_path))

    assert result["daemon_allow"] == {"decision": "allow"}
    assert result["daemon_lifecycle_allow"] == {
        "decision": "allow",
        "policy_action": "allow",
        "reason_code": "fixture_lifecycle",
    }
    assert result["daemon_deny"] == {"decision": "deny", "reason": "fixture block"}
    assert result["daemon_empty"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_whitespace"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_malformed"] == {
        "decision": "deny",
        "reason": "HOL Guard received an invalid response from the authenticated local daemon.",
        "reason_code": "daemon_invalid_response",
    }
    assert result["daemon_malformed_reason"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_null_reason"] == {"decision": "deny", "reason": None}
    assert result["daemon_omitted_reason"] == {"decision": "deny"}
    assert result["daemon_shape"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_array"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_unknown"] == {"response": None, "recoveryKind": "transport-failure"}
    assert result["daemon_block"] == {"decision": "deny", "reason": "fixture block"}
    assert result["daemon_oversized_body"] == {
        "response": None,
        "recoveryKind": "transport-failure",
    }

    assert result["retry_still_malformed"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["retry_still_malformed_daemon_calls"] == 2
    assert result["retry_still_malformed_recovery_calls"] == 1
    assert result["retry_still_malformed_cli_calls"] == 1

    assert result["retry_malformed_reason"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["retry_malformed_reason_daemon_calls"] == 2
    assert result["retry_malformed_reason_recovery_calls"] == 1
    assert result["retry_malformed_reason_cli_calls"] == 1

    assert result["retry_valid"] == {"decision": "allow"}
    assert result["retry_valid_daemon_calls"] == 2
    assert result["retry_valid_recovery_calls"] == 1
    assert result["retry_valid_cli_calls"] == 0
    assert result["posttool_daemon_allow"] == {
        "decision": "allow",
        "reason_code": "native_policy_not_ready",
    }
    assert result["posttool_daemon_allow_daemon_calls"] == 1
    assert result["posttool_daemon_allow_recovery_calls"] == 0
    assert result["posttool_daemon_allow_cli_calls"] == 0
    assert result["stale_daemon_cli_success"] == {"decision": "allow"}
    assert result["stale_daemon_cli_daemon_calls"] == 1
    assert result["stale_daemon_cli_recovery_calls"] == 0
    assert result["stale_daemon_cli_calls"] == 0

    assert result["cli_missing_decision"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_empty_prompt"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_empty_post"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_malformed_reason"] == {
        "decision": "deny",
        "reason": "HOL Guard fallback did not return a valid decision. Retry the action.",
        "reason_code": "guard_cli_invalid_response",
    }
    assert result["cli_null_reason"] == {"decision": "deny", "reason": None}
    assert result["cli_omitted_reason"] == {"decision": "deny"}
    assert result["cli_lifecycle_allow"] == {"decision": "allow", "policy_action": "allow"}
    assert result["cli_allow"] == {"decision": "allow"}
    assert result["cli_deny"] == {"decision": "deny", "reason": "fixture block"}
    assert result["cli_block_prompt"] == {"decision": "deny", "reason": "fixture block"}
    assert result["cli_block_post"] == {"decision": "deny", "reason": "fixture block"}
    assert result["cli_nonzero_allow"] == {"decision": "deny", "reason": "cli failed"}
    assert result["cli_signal_allow"] == {"decision": "deny", "reason": "Blocked by HOL Guard."}


def test_generated_omp_tool_result_preserves_daemon_allow_without_hash(tmp_path: Path) -> None:
    result = _run_generated_tool_result_fixture(_generated_source(tmp_path))

    assert result["valid"] is True
    assert result["missing_directive"] is True
    assert result["contradictory_directive"]["content"][0]["text"] == "reviewed-safe"
    assert result["contradictory_directive"].get("isError") is not True
    assert result["missing_excerpt"]["isError"] is True
    assert result["missing_digest"]["isError"] is True
    assert result["mismatched_digest"]["isError"] is True
    assert result["reviewed_excerpt"]["content"][0]["text"] == "reviewed-long"
    assert result["reviewed_excerpt"].get("isError") is not True
    assert result["observe_mode"] is True


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_generated_structured_receiver_requires_exact_clean_forward_bytes(
    tmp_path: Path,
    harness: str,
) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / harness / "guard-home",
        home_dir=tmp_path / harness / "home",
        settings_path=tmp_path / harness / "settings.json",
        harness=harness,
        display_name=harness,
    )
    content = [{"type": "text", "text": '{"employee":{"email":"","id":7},"note":"π"}'}]
    candidate = '{"employee":{"email":"","id":7},"note":"π"}'
    text_digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    structured_digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    forward = _run_generated_callback_payload(
        source,
        content,
        {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": text_digest,
            "structured_content_mediation": {
                "schema": "guard-structured-content-mediation.v1",
                "action": "forward",
                "reason_code": "structured_clean_forward",
                "native_decision_id": "a" * 64,
                "content_sha256": structured_digest,
            },
        },
    )
    assert forward["payload"]["structured_output_json"] == candidate
    assert forward["preserved"] is True

    withhold = _run_generated_callback_payload(
        source,
        content,
        {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": text_digest,
            "structured_content_mediation": {
                "schema": "guard-structured-content-mediation.v1",
                "action": "withhold",
                "reason_code": "structured_declared_schema_scan",
                "native_decision_id": "a" * 64,
            },
        },
    )
    assert withhold["result"]["isError"] is True
    assert "π" not in withhold["result"]["content"][0]["text"]

    changed = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": '{"employee":{"email":"","id":7},"note":"changed"}'}],
        {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": text_digest,
            "structured_content_mediation": {
                "schema": "guard-structured-content-mediation.v1",
                "action": "forward",
                "reason_code": "structured_clean_forward",
                "native_decision_id": "a" * 64,
                "content_sha256": structured_digest,
            },
        },
    )
    assert changed["result"]["isError"] is True

    protected_content = [
        {"type": "text", "text": '{"employee":{"email":"person@example.test","id":7},"note":"π"}'},
    ]
    protected_candidate = '{"employee":{"email":"person@example.test","id":7},"note":"π"}'
    protected = _run_generated_callback_payload(
        source,
        protected_content,
        {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": hashlib.sha256(protected_candidate.encode("utf-8")).hexdigest(),
            "structured_content_mediation": {
                "schema": "guard-structured-content-mediation.v1",
                "action": "withhold",
                "reason_code": "structured_declared_schema_scan",
                "native_decision_id": "a" * 64,
            },
        },
    )
    assert protected["result"]["isError"] is True
    assert "person@example.test" not in protected["result"]["content"][0]["text"]

    unknown_metadata = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": candidate, "metadata": {"fixture": "unknown"}}],
        {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": text_digest,
            "structured_content_mediation": {
                "schema": "guard-structured-content-mediation.v1",
                "action": "forward",
                "reason_code": "structured_clean_forward",
                "native_decision_id": "a" * 64,
                "content_sha256": structured_digest,
            },
        },
    )
    assert unknown_metadata["result"]["isError"] is True


def test_generated_structured_receiver_fails_closed_without_host_cancellation_signal(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    candidate = '{"employee":{"email":"","id":7},"note":"x"}'
    response = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        "structured_content_mediation": {
            "schema": "guard-structured-content-mediation.v1",
            "action": "forward",
            "reason_code": "structured_clean_forward",
            "native_decision_id": "a" * 64,
            "content_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        },
    }
    result = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": candidate}],
        response,
        include_signal=False,
    )
    assert "structured_output_json" not in result["payload"]
    assert result["preserved"] is False
    assert result["result"]["isError"] is True


def test_generated_managed_structured_mediation_precedes_watch_shortcut(tmp_path: Path) -> None:
    source = _generated_source(tmp_path, harness="pi")
    benign = '{"employee":{"email":"","id":7},"note":"watch"}'
    benign_response = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "observe_mode": True,
        "reviewed_output_sha256": hashlib.sha256(benign.encode("utf-8")).hexdigest(),
        "structured_content_mediation": {
            "schema": "guard-structured-content-mediation.v1",
            "action": "forward",
            "reason_code": "structured_clean_forward",
            "native_decision_id": "a" * 64,
            "content_sha256": hashlib.sha256(benign.encode("utf-8")).hexdigest(),
        },
    }
    allowed = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": benign}],
        benign_response,
    )
    assert allowed["preserved"] is True
    assert allowed["payload"]["structured_output_json"] == benign

    protected = '{"employee":{"email":"person@example.test","id":7},"note":"watch"}'
    protected_response = {
        **benign_response,
        "reviewed_output_sha256": hashlib.sha256(protected.encode("utf-8")).hexdigest(),
        "structured_content_mediation": {
            **benign_response["structured_content_mediation"],
            "action": "withhold",
            "reason_code": "structured_declared_schema_scan",
        },
    }
    blocked = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": protected}],
        protected_response,
    )
    assert blocked["preserved"] is False
    assert blocked["result"]["isError"] is True
    assert "person@example.test" not in blocked["result"]["content"][0]["text"]


def test_generated_structured_receiver_rejects_late_cancellation_and_expired_deadline(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    candidate = '{"employee":{"email":"","id":7},"note":"x"}'
    response = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        "structured_content_mediation": {
            "schema": "guard-structured-content-mediation.v1",
            "action": "forward",
            "reason_code": "structured_clean_forward",
            "native_decision_id": "a" * 64,
            "content_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        },
    }
    cancelled = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": candidate}],
        response,
        abort_during_guard=True,
    )
    assert cancelled["preserved"] is False
    assert cancelled["result"]["isError"] is True

    expired = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": candidate}],
        response,
        guard_timeout_ms=0,
    )
    assert expired["payload"] is None
    assert expired["preserved"] is False
    assert expired["result"]["isError"] is True


@pytest.mark.parametrize("trigger", ["abort", "deadline"])
def test_generated_structured_receiver_rechecks_lifecycle_at_final_original_proof(
    tmp_path: Path,
    trigger: str,
) -> None:
    source = _generated_source(tmp_path, harness="pi")
    candidate = '{"employee":{"email":"","id":7},"note":"final"}'
    digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    response = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": digest,
        "structured_content_mediation": {
            "schema": "guard-structured-content-mediation.v1",
            "action": "forward",
            "reason_code": "structured_clean_forward",
            "native_decision_id": "a" * 64,
            "content_sha256": digest,
        },
    }
    result = _run_generated_callback_payload(
        source,
        [{"type": "text", "text": candidate}],
        response,
        abort_during_structured_proof=trigger == "abort",
        expire_during_structured_proof=trigger == "deadline",
    )
    assert result["preserved"] is False
    assert result["result"]["isError"] is True


def test_generated_omp_payload_matches_real_python_review(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    store = GuardStore(tmp_path / "guard-home")
    scanner = ContentScanner()
    cache = HookDecisionCache(store)
    engine = HookReviewEngine(
        store=store,
        scanner=scanner,
        cache=cache,
        config_loader=lambda guard_home, workspace: GuardConfig(
            guard_home=guard_home,
            workspace=workspace,
        ),
    )
    cases = (
        ([{"type": "text", "text": "plain output"}], "plain output"),
        (
            [
                {"type": "text", "text": "first"},
                {"type": "image", "data": "ignored"},
                {"type": "text", "text": "second"},
            ],
            "firstsecond",
        ),
        ([], ""),
        ([{"type": "text", "text": "astral 🌋 output"}], "astral 🌋 output"),
        ([{"type": "text", "text": " first\r\nsecond \r\n"}], " first\r\nsecond \r\n"),
    )

    for content, expected_text in cases:
        captured = _run_generated_callback_payload(
            source,
            content,
            {"decision": "deny", "reason": "capture"},
        )
        serialized_payload = captured["serialized_payload"]
        assert isinstance(serialized_payload, str)
        payload = json.loads(serialized_payload)
        assert payload["tool_response"] == content
        assert "stdout" not in payload

        response = engine.review(
            HookReviewRequest(
                harness="omp",
                event_name="PostToolUse",
                payload=payload,
                payload_kind="inline",
                config_path=None,
                cwd=tmp_path,
                home_dir=tmp_path / "home",
                guard_home=tmp_path / "guard-home",
                source_scope="project",
            )
        )
        assert response.decision == "allow"
        assert response.model_output_action == "allow_original"
        assert response.reviewed_output_sha256 == sha256_text(expected_text)

        accepted = _run_generated_callback_payload(source, content, response.to_harness_json())
        assert accepted["preserved"] is True

        recording_only = _watch_native_post_tool_result(
            {
                "decision": "deny",
                "model_output_action": "block",
                "policy_action": "block",
                "reason": "output requires review",
            },
            payload,
        )
        assert recording_only["decision"] == "allow"
        assert recording_only["model_output_action"] == "allow_original"
        assert recording_only["reviewed_output_sha256"] == sha256_text(expected_text)
        assert "observe_mode" not in recording_only
        accepted_recording = _run_generated_callback_payload(source, content, recording_only)
        assert accepted_recording["preserved"] is True


def test_generated_unicode_source_ref_matches_python_fast_path(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    path = source_dir / "fixture.txt"
    text = "first 🌋 line\r\nsecond line\n"
    path.write_bytes(text.encode("utf-8"))
    generated = _run_generated_source_ref_fixture(
        source,
        [{"type": "text", "text": text}],
        Path("src/fixture.txt"),
    )

    digest = generated["digest"]
    source_ref = generated["sourceRef"]
    assert isinstance(digest, dict)
    assert isinstance(source_ref, dict)
    assert digest["chars"] == len(text)
    assert source_ref["output_chars"] == len(text)
    assert source_ref["output_sha256"] == sha256_text(text)

    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/fixture.txt"},
        "tool_response": text,
        "guard_source_ref": source_ref,
    }
    source_ref_model = HookSourceFileRef(
        version=source_ref["version"],
        path=source_ref["path"],
        output_sha256=source_ref["output_sha256"],
        output_chars=source_ref["output_chars"],
        tool_input_path=source_ref["tool_input_path"],
    )
    store = GuardStore(tmp_path / "guard-home")
    scanner = ContentScanner()
    cache = HookDecisionCache(store)
    config = GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path)
    request = HookReviewRequest(
        harness="omp",
        event_name="PostToolUse",
        payload=payload,
        payload_kind="source_file_ref",
        config_path=None,
        cwd=tmp_path,
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        source_scope="project",
        source_ref=source_ref_model,
    )
    envelope = normalize_harness_payload(
        "omp",
        "PostToolUse",
        payload,
        workspace=tmp_path,
        home_dir=tmp_path / "home",
    )
    fast_path = evaluate_source_file_ref(
        request=request,
        envelope=envelope,
        scanner=scanner,
        cache=cache,
        config=config,
        store=store,
        deadline_monotonic=time.monotonic() + 2,
    )
    assert fast_path.status == "allow_original", (
        fast_path.reason_code,
        source_ref,
        envelope.target_paths,
    )
    assert fast_path.proof is not None
    assert fast_path.proof.output_sha256 == sha256_text(text)

    response = HookReviewEngine(
        store=store,
        scanner=scanner,
        cache=cache,
        config_loader=lambda guard_home, workspace: config,
    ).review(request)
    assert response.decision == "allow"
    assert response.model_output_action == "allow_original"
    assert response.reviewed_output_sha256 == sha256_text(text)


def test_generated_large_non_source_result_fails_closed_before_serialization(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    large_text = "x" * (5 * 1024 * 1024 + 1)
    content = [{"type": "text", "text": large_text}]
    captured = _run_generated_callback_payload(
        source,
        content,
        {"decision": "deny", "reason": "capture"},
    )
    assert captured["serialized_payload"] is None
    assert captured["payload"] is None
    result = captured["result"]
    assert isinstance(result, dict)
    assert result["isError"] is True
    assert "blocked" in result["content"][0]["text"]


def test_generated_preprocessing_rejects_oversized_single_text_before_hash(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const content = [{ type: "text", text: "x".repeat(5 * 1024 * 1024 + 1) }];
const digest = digestOutputText(content, Date.now() + 10_000);
const bounded = boundValue(content, 0, new WeakSet(), createTraversalBudget(Date.now() + 10_000));
const excerpt = boundedOutputText(content, Date.now() + 10_000);
console.log(JSON.stringify({
  digest: {
    sha256: digest.sha256,
    chars: digest.chars,
    excerptChars: digest.textForExcerpt.length,
    traversalTruncated: digest.traversalTruncated,
  },
  bounded: { truncated: bounded.truncated },
  excerpt: { chars: excerpt.value.length, truncated: excerpt.truncated },
}));
""",
    )

    assert result["digest"] == {
        "sha256": None,
        "chars": 0,
        "excerptChars": 12_000,
        "traversalTruncated": True,
    }
    assert result["bounded"] == {"truncated": True}
    assert result["excerpt"] == {"chars": 12_000, "truncated": True}


def test_generated_preprocessing_caps_branching_traversal_work(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const branching = Array.from({ length: 24 }, () =>
  Array.from({ length: 24 }, () => ({ type: "text", text: "x" })));
const digest = digestOutputText(branching);
const bounded = boundValue(branching);
const excerpt = boundedOutputText(branching);
console.log(JSON.stringify({
  digest: {
    sha256: digest.sha256,
    traversalTruncated: digest.traversalTruncated,
    chars: digest.chars,
  },
  bounded: { truncated: bounded.truncated },
  excerpt: { truncated: excerpt.truncated, chars: excerpt.value.length },
}));
""",
    )

    assert result["digest"]["sha256"] is None
    assert result["digest"]["traversalTruncated"] is True
    assert result["digest"]["chars"] < 24 * 24
    assert result["bounded"] == {"truncated": True}
    assert result["excerpt"]["truncated"] is True


def test_generated_preprocessing_withholds_when_deadline_is_already_expired(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const branching = Array.from({ length: 24 }, () =>
  Array.from({ length: 24 }, () => ({ type: "text", text: "x" })));
const deadlineAt = Date.now() - 1;
const digest = digestOutputText(branching, deadlineAt);
const bounded = boundValue(branching, 0, new WeakSet(), createTraversalBudget(deadlineAt));
const excerpt = boundedOutputText(branching, deadlineAt);
console.log(JSON.stringify({
  digest: { sha256: digest.sha256, traversalTruncated: digest.traversalTruncated },
  bounded: { truncated: bounded.truncated },
  excerpt: { truncated: excerpt.truncated },
}));
""",
    )

    assert result == {
        "digest": {"sha256": None, "traversalTruncated": True},
        "bounded": {"truncated": True},
        "excerpt": {"truncated": True},
    }


def test_generated_payload_budget_rejects_large_tool_input_before_json_stringify(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const payload = {
  hook_event_name: "PostToolUse",
  tool_input: { command: "x".repeat(5 * 1024 * 1024 + 1) },
  tool_response: [{ type: "text", text: "small" }],
};
console.log(JSON.stringify({ bounded: payloadWithinSerializedBudget(payload, Date.now() + 10_000) }));
""",
    )
    assert result == {"bounded": False}


def test_generated_payload_budget_accepts_valid_reference_sized_json(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        r"""
const samples = [
  "x".repeat(25_000),
  "\t\n\r\b\f\u0000\"\\".repeat(4_000),
  "\u00e9\u4e2d\ud83e\uddea\ud800".repeat(4_000),
];
const cases = samples.map((text) => {
  const payload = { tool_response: [{ type: "text", text }] };
  const actualBytes = Buffer.byteLength(JSON.stringify(payload), "utf8");
  const measuredBytes = boundedJsonSize(payload, createTraversalBudget(Date.now() + 10_000),
    0, new WeakSet(), false);
  return {
    exactBytes: actualBytes === measuredBytes,
    usesReference: JSON.stringify(payload).length > GUARD_MAX_SERIALIZED_PAYLOAD_CHARS,
    bounded: payloadWithinSerializedBudget(payload, Date.now() + 10_000),
  };
});
console.log(JSON.stringify({ cases }));
""",
    )
    assert result == {"cases": [{"exactBytes": True, "usesReference": True, "bounded": True}] * 3}


def test_generated_payload_budget_rejects_reference_overflow_before_stringify(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const payload = { text: "\\ud83e\\uddea".repeat(Math.ceil((5 * 1024 * 1024) / 4)) };
const originalStringify = JSON.stringify;
let payloadSerializationCalls = 0;
JSON.stringify = (value, ...args) => {
  if (value === payload) payloadSerializationCalls += 1;
  return originalStringify(value, ...args);
};
const bounded = payloadWithinSerializedBudget(payload, Date.now() + 10_000);
JSON.stringify = originalStringify;
console.log(JSON.stringify({ bounded, payloadSerializationCalls }));
""",
    )
    assert result == {"bounded": False, "payloadSerializationCalls": 0}


def test_generated_response_reader_withholds_completion_after_deadline(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const originalNow = Date.now;
const cases = [];
try {
  for (const done of [false, true]) {
    let now = 100;
    let cancelled = false;
    let released = false;
    Date.now = () => now;
    const reader = {
      async read() {
        now = 201;
        return { done, value: new TextEncoder().encode('late') };
      },
      async cancel() { cancelled = true; },
      releaseLock() { released = true; },
    };
    const text = await boundedResponseText({ body: { getReader: () => reader } }, 100, 200);
    cases.push({ text, cancelled, released });
  }
} finally {
  Date.now = originalNow;
}
console.log(JSON.stringify({ cases }));
""",
    )
    assert result == {"cases": [{"text": None, "cancelled": True, "released": True}] * 2}


def test_generated_payload_budget_matches_exact_encrypted_reference_boundary(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const emptyBytes = Buffer.byteLength(JSON.stringify({ text: '' }), 'utf8');
const cases = [0, 1].map((overflow) => {
  const payload = { text: 'x'.repeat(GUARD_MAX_REFERENCE_JSON_BYTES - emptyBytes + overflow) };
  return {
    ciphertextBytes: Buffer.byteLength(JSON.stringify(payload), 'utf8') + 16,
    bounded: payloadWithinSerializedBudget(payload, Date.now() + 10_000),
  };
});
console.log(JSON.stringify({ cases }));
""",
    )
    assert result == {
        "cases": [
            {"ciphertextBytes": 5 * 1024 * 1024, "bounded": True},
            {"ciphertextBytes": 5 * 1024 * 1024 + 1, "bounded": False},
        ],
    }

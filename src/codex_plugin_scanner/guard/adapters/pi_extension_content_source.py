"""Generated Pi managed extension content-review helper source."""

# ruff: noqa: E501

from __future__ import annotations

CONTENT_REVIEW_HELPERS_SOURCE = r"""type OutputDigest = {
  sha256: string | null;
  chars: number;
  textForExcerpt: string;
  excerptTruncated: boolean;
  traversalTruncated: boolean;
};

function legacyDigestOutputText(value: unknown): OutputDigest {
  const hash = createHash('sha256');
  let chars = 0;
  let textForExcerpt = '';
  let excerptTruncated = false;
  let traversalTruncated = false;
  const seen = new WeakSet<object>();
  function update(text: string): void {
    hash.update(text, 'utf8');
    chars += text.length;
    if (textForExcerpt.length < GUARD_TEXT_LIMIT_CHARS) {
      const remaining = GUARD_TEXT_LIMIT_CHARS - textForExcerpt.length;
      if (text.length <= remaining) {
        textForExcerpt += text;
      } else {
        textForExcerpt += text.slice(0, remaining);
        excerptTruncated = true;
      }
    }
    if (chars > GUARD_SOURCE_REF_MAX_OUTPUT_CHARS) {
      traversalTruncated = true;
    }
  }
  function traverse(val: unknown, depth: number): void {
    if (traversalTruncated) return;
    if (typeof val === 'string') { update(val); return; }
    if (val === undefined || val === null) return;
    if (typeof val === 'number' || typeof val === 'boolean') return;
    if (typeof val === 'bigint') { update(val.toString()); return; }
    if (typeof val !== 'object') { traversalTruncated = true; return; }
    const obj = val as object;
    if (seen.has(obj)) { traversalTruncated = true; return; }
    if (depth > GUARD_MAX_DEPTH) { traversalTruncated = true; return; }
    seen.add(obj);
    if (Array.isArray(val)) {
      if (val.length > GUARD_CONTENT_ITEM_LIMIT) { traversalTruncated = true; return; }
      for (const item of val) { if (traversalTruncated) return; traverse(item, depth + 1); }
      return;
    }
    const record = val as Record<string, unknown>;
    // Match collectOutputText: only extract text from {type: "text", text: ...}
    // objects, not from metadata keys like "type".
    if (record.type === 'text' && typeof record.text === 'string') {
      update(record.text);
      return;
    }
    let keyCount = 0;
    for (const key of OUTPUT_TEXT_KEYS) {
      if (!(key in record)) continue;
      if (keyCount >= GUARD_OBJECT_KEY_LIMIT) { traversalTruncated = true; return; }
      keyCount++;
      if (traversalTruncated) return;
      traverse(record[key], depth + 1);
    }
  }
  try {
    traverse(value, 0);
  } catch {
    traversalTruncated = true;
  }
  return {
    sha256: traversalTruncated ? null : hash.digest('hex'),
    chars,
    textForExcerpt,
    excerptTruncated,
    traversalTruncated,
  };
}

function structuredOutputJsonForPostToolUse(value: unknown, deadlineAt?: number): string | null {
  let nodeCount = 0;
  let keyCount = 0;
  const seen = new WeakSet<object>();
  const deadlineExceeded = (): boolean => deadlineAt !== undefined && Date.now() >= deadlineAt;
  const checkDeadline = (): void => {
    if (deadlineExceeded()) throw new Error('structured output deadline exceeded');
  };
  function hasUnpairedSurrogate(text: string): boolean {
    checkDeadline();
    for (let index = 0; index < text.length; index += 1) {
      if ((index & 0x3ff) === 0) checkDeadline();
      const code = text.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff) {
        const next = text.charCodeAt(index + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
        index += 1;
      } else if (code >= 0xdc00 && code <= 0xdfff) {
        return true;
      }
    }
    return false;
  }
  function canonicalize(item: unknown, depth: number): unknown {
    checkDeadline();
    nodeCount += 1;
    if (nodeCount > GUARD_STRUCTURED_MAX_NODES || depth > GUARD_STRUCTURED_MAX_DEPTH) {
      throw new Error('structured output bounds exceeded');
    }
    if (typeof item === 'string') {
      if (hasUnpairedSurrogate(item)) throw new Error('structured output unicode is invalid');
      if (item.length > GUARD_STRUCTURED_MAX_BYTES || Buffer.byteLength(item, 'utf8') > GUARD_STRUCTURED_MAX_BYTES) {
        throw new Error('structured output string bounds exceeded');
      }
      checkDeadline();
      return item;
    }
    if (item === null || typeof item === 'boolean') return item;
    if (typeof item === 'number') {
      if (!Number.isFinite(item) || !Number.isSafeInteger(item)) {
        throw new Error('structured output number is unsupported');
      }
      return item;
    }
    if (typeof item !== 'object' || Array.isArray(item)) {
      throw new Error('structured output value is unsupported');
    }
    const record = item as Record<string, unknown>;
    const prototype = Object.getPrototypeOf(record);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error('structured output object prototype is unsupported');
    }
    if (Object.getOwnPropertySymbols(record).length > 0) {
      throw new Error('structured output symbols are unsupported');
    }
    if (seen.has(record)) throw new Error('structured output cycle');
    seen.add(record);
    try {
      const keys = Object.keys(record);
      keyCount += keys.length;
      if (keyCount > GUARD_STRUCTURED_MAX_FIELDS) {
        throw new Error('structured output field bounds exceeded');
      }
      let keyBytes = 0;
      for (const key of keys) {
        checkDeadline();
        if (hasUnpairedSurrogate(key)) throw new Error('structured output key unicode is invalid');
        keyBytes += Buffer.byteLength(key, 'utf8');
        if (keyBytes > GUARD_STRUCTURED_MAX_BYTES) throw new Error('structured output key bounds exceeded');
      }
      checkDeadline();
      keys.sort();
      checkDeadline();
      const normalized = Object.create(null) as Record<string, unknown>;
      for (const key of keys) {
        normalized[key] = canonicalize(record[key], depth + 1);
      }
      checkDeadline();
      return normalized;
    } finally {
      seen.delete(record);
    }
  }
  function canonicalStringify(item: unknown): string {
    checkDeadline();
    if (item === null || typeof item !== 'object') {
      const serialized = JSON.stringify(item);
      if (typeof serialized !== 'string') throw new Error('structured output value is unsupported');
      return serialized;
    }
    if (Array.isArray(item)) {
      return `[${item.map((entry) => canonicalStringify(entry)).join(',')}]`;
    }
    const record = item as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    const entries: string[] = [];
    for (const key of keys) {
      checkDeadline();
      entries.push(`${JSON.stringify(key)}:${canonicalStringify(record[key])}`);
    }
    return `{${entries.join(',')}}`;
  }
  try {
    // The host contract is ToolResultEvent.content: an array of content
    // blocks.  This adapter intentionally accepts one closed text envelope
    // carrying a canonical JSON object.  Every wrapper key is checked, so an
    // image, a second block, or unknown metadata is withheld instead of being
    // silently dropped before the model-visible receiver proof.
    if (!Array.isArray(value) || value.length !== 1) return null;
    const block = value[0];
    if (block === null || typeof block !== 'object' || Array.isArray(block)) return null;
    const blockRecord = block as Record<string, unknown>;
    const blockPrototype = Object.getPrototypeOf(blockRecord);
    if (blockPrototype !== Object.prototype && blockPrototype !== null) return null;
    // Host object symbol/key enumeration is a native operation that this
    // adapter cannot preempt. Unknown metadata remains fail-closed; the
    // checks below validate the complete ordinary-object shape after that
    // host input boundary and do not claim to bound malicious proxies.
    if (Object.getOwnPropertySymbols(blockRecord).length > 0) return null;
    checkDeadline();
    const blockKeys = Object.keys(blockRecord);
    if (blockKeys.length !== 2) return null;
    let blockKeyBytes = 0;
    for (const key of blockKeys) {
      checkDeadline();
      if (hasUnpairedSurrogate(key)) return null;
      blockKeyBytes += Buffer.byteLength(key, 'utf8');
      if (blockKeyBytes > GUARD_STRUCTURED_MAX_BYTES) return null;
    }
    checkDeadline();
    blockKeys.sort();
    checkDeadline();
    if (blockKeys[0] !== 'text' || blockKeys[1] !== 'type') return null;
    if (blockRecord.type !== 'text' || typeof blockRecord.text !== 'string') return null;
    const structuredText = blockRecord.text;
    if (structuredText.length > GUARD_STRUCTURED_MAX_BYTES) return null;
    checkDeadline();
    if (Buffer.byteLength(structuredText, 'utf8') > GUARD_STRUCTURED_MAX_BYTES) return null;
    checkDeadline();
    const parsed = JSON.parse(structuredText) as unknown;
    checkDeadline();
    const normalized = canonicalize(parsed, 0);
    checkDeadline();
    const serialized = canonicalStringify(normalized);
    checkDeadline();
    if (typeof serialized !== 'string' || serialized !== structuredText || serialized.includes('\\')) return null;
    if (Buffer.byteLength(serialized, 'utf8') > GUARD_STRUCTURED_MAX_BYTES) return null;
    checkDeadline();
    return serialized;
  } catch {
    return null;
  }
}

function sourcePathFromToolInput(toolInput: Record<string, unknown>): string | null {
  for (const key of ['file_path', 'filePath', 'path', 'file', 'filename']) {
    const value = toolInput[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

function isVirtualSourcePath(path: string): boolean {
  if (/^[A-Za-z]:[\\/]/.test(path)) return false;
  return /^[A-Za-z][A-Za-z0-9+.-]*:/.test(path);
}

function sourceFileRefForPostToolUse(
  event: Record<string, unknown>,
  toolInput: Record<string, unknown>,
  digest: OutputDigest,
): { version: number; kind: string; path: string; tool_input_path: string; output_sha256: string; output_chars: number } | null {
  const toolName = typeof event.toolName === 'string' ? event.toolName : '';
  if (!GUARD_SOURCE_REF_ALLOWED_TOOL_NAMES.has(toolName)) return null;
  if (!digest.sha256 || digest.traversalTruncated) return null;
  if (digest.chars > GUARD_SOURCE_REF_MAX_OUTPUT_CHARS) return null;
  const path = sourcePathFromToolInput(toolInput);
  // The daemon independently resolves, validates, and re-reads this path
  // before it can return the original output. Absolute paths are common in
  // Pi Read calls and must retain that provenance rather than fall back to
  // context-free output scanning.
  if (!path || isVirtualSourcePath(path)) return null;
  return {
    version: 1,
    kind: 'source_file',
    path,
    tool_input_path: path,
    output_sha256: digest.sha256,
    output_chars: digest.chars,
  };
}

type BoundedValue = { value: unknown; truncated: boolean };
const OUTPUT_TEXT_KEYS = ["stdout", "stderr", "output", "content", "result", "message", "text"] as const;

function truncateText(value: string, limit = GUARD_TEXT_LIMIT_CHARS): string {
  if (value.length <= limit) return value;
  return `${value.slice(0, Math.max(limit, 0))}\n...[truncated by HOL Guard]...`;
}

function legacyBoundValue(value: unknown, depth = 0, seen = new WeakSet<object>()): BoundedValue {
  if (typeof value === 'string') {
    if (value.length <= GUARD_TEXT_LIMIT_CHARS) {
      return { value, truncated: false };
    }
    return { value: truncateText(value), truncated: true };
  }
  if (value === undefined) return { value: undefined, truncated: false };
  if (typeof value === 'bigint') return { value: value.toString(), truncated: false };
  if (
    value === null ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return { value, truncated: false };
  }
  if (typeof value !== 'object') {
    return { value: String(value), truncated: true };
  }
  const objectValue = value as object;
  if (seen.has(objectValue)) {
    return { value: '[cycle omitted by HOL Guard]', truncated: true };
  }
  if (depth > GUARD_MAX_DEPTH) {
    return { value: '[deep object omitted by HOL Guard]', truncated: true };
  }
  seen.add(objectValue);
  try {
    if (Array.isArray(value)) {
      const truncated = value.length > GUARD_CONTENT_ITEM_LIMIT;
      const items = value.slice(0, GUARD_CONTENT_ITEM_LIMIT);
      const nextItems: unknown[] = [];
      let childTruncated = truncated;
      for (const item of items) {
        const next = legacyBoundValue(item, depth + 1, seen);
        nextItems.push(next.value);
        childTruncated = childTruncated || next.truncated;
      }
      return { value: nextItems, truncated: childTruncated };
    }
    const record = value as Record<string, unknown>;
    const nextRecord: Record<string, unknown> = {};
    let truncated = false;
    let keyCount = 0;
    for (const key in record) {
      if (!Object.prototype.hasOwnProperty.call(record, key)) continue;
      if (keyCount >= GUARD_OBJECT_KEY_LIMIT) {
        truncated = true;
        break;
      }
      keyCount += 1;
      const entryValue = record[key];
      const next = legacyBoundValue(entryValue, depth + 1, seen);
      nextRecord[key] = next.value;
      truncated = truncated || next.truncated;
    }
    return { value: nextRecord, truncated };
  } finally {
    seen.delete(objectValue);
  }
}

function appendBoundedText(accumulator: { text: string; truncated: boolean }, value: string): void {
  if (accumulator.truncated || value.length === 0) return;
  const prefix = accumulator.text ? "\n" : "";
  const available = GUARD_TEXT_LIMIT_CHARS - accumulator.text.length - prefix.length;
  if (available <= 0) {
    accumulator.truncated = true;
    return;
  }
  if (value.length > available) {
    accumulator.text += `${prefix}${value.slice(0, available)}`;
    accumulator.truncated = true;
    return;
  }
  accumulator.text += `${prefix}${value}`;
}

function collectOutputText(
  value: unknown,
  accumulator: { text: string; truncated: boolean; itemCount: number },
  depth = 0,
  seen = new WeakSet<object>(),
): void {
  if (accumulator.truncated) return;
  if (typeof value === 'string') {
    appendBoundedText(accumulator, value);
    return;
  }
  if (typeof value === 'bigint') {
    appendBoundedText(accumulator, value.toString());
    return;
  }
  if (
    value === undefined ||
    value === null ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return;
  }
  if (typeof value !== 'object') {
    accumulator.truncated = true;
    return;
  }
  const objectValue = value as object;
  if (seen.has(objectValue) || depth > GUARD_MAX_DEPTH) {
    accumulator.truncated = true;
    return;
  }
  seen.add(objectValue);
  try {
    if (Array.isArray(value)) {
      const arrayItems = value as unknown[];
      for (const item of arrayItems) {
        if (accumulator.itemCount >= GUARD_CONTENT_ITEM_LIMIT) {
          accumulator.truncated = true;
          break;
        }
        accumulator.itemCount += 1;
        collectOutputText(item, accumulator, depth + 1, seen);
        if (accumulator.truncated) break;
      }
      if (arrayItems.length > GUARD_CONTENT_ITEM_LIMIT) accumulator.truncated = true;
      return;
    }
    const record = value as Record<string, unknown>;
    if (record.type === 'text' && typeof record.text === 'string') {
      appendBoundedText(accumulator, record.text);
      return;
    }
    for (const key of OUTPUT_TEXT_KEYS) {
      if (!(key in record)) continue;
      collectOutputText(record[key], accumulator, depth + 1, seen);
      if (accumulator.truncated) break;
    }
  } finally {
    seen.delete(objectValue);
  }
}

function legacyBoundedOutputText(value: unknown): BoundedValue {
  const accumulator = { text: '', truncated: false, itemCount: 0 };
  collectOutputText(value, accumulator);
  return { value: accumulator.text, truncated: accumulator.truncated };
}

function toolCallIdKey(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function base64Url(value: Buffer): string {
  return value.toString('base64url');
}

function encryptedPayload(serializedPayload: string) {
  const key = randomBytes(32);
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([
    cipher.update(serializedPayload, 'utf8'),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return { ciphertext, key: base64Url(key), nonce: base64Url(nonce) };
}

function referencedPayload(payload: Record<string, unknown>, serializedPayload: string) {
  const directory = mkdtempSync(join(tmpdir(), 'hol-guard-hook-payload-'));
  try { chmodSync(directory, 0o700); } catch {}
  const path = join(directory, 'payload.json');
  const encrypted = encryptedPayload(serializedPayload);
  writeFileSync(path, encrypted.ciphertext, { mode: 0o600 });
  const sha256 = createHash('sha256').update(encrypted.ciphertext).digest('hex');
  const referencePayload: Record<string, unknown> = {
    hook_event_name: payload.hook_event_name,
    config_path: payload.config_path,
    tool_name: payload.tool_name,
    is_error: payload.is_error,
    ...(typeof payload.structured_output_json === 'string'
      ? { structured_output_json: payload.structured_output_json }
      : {}),
    guard_payload_ref: {
      version: 1,
      path,
      sha256,
      encoding: 'json',
      encryption: 'aes-256-gcm',
      key: encrypted.key,
      nonce: encrypted.nonce,
      serialized_chars: serializedPayload.length,
    },
  };
  return {
    payload: referencePayload,
    cleanup: () => { try { rmSync(directory, { recursive: true, force: true }); } catch {} },
  };
}

/* HOL Guard bounded preprocessing begins */
type TraversalBudget = {
  deadlineAt?: number;
  nodes: number;
  exhausted: boolean;
  maxNodes?: number;
};
type BoundedCodePointPrefix = { text: string; chars: number; complete: boolean };

const GUARD_PREPROCESS_MAX_NODES = 256;
// The native reference resolver caps ciphertext at 5 MiB; AES-GCM appends a 16-byte tag.
const GUARD_MAX_REFERENCE_JSON_BYTES = 5 * 1024 * 1024 - 16;

function createTraversalBudget(deadlineAt?: number): TraversalBudget {
  return { deadlineAt, nodes: 0, exhausted: false };
}

function traversalBudgetReady(budget: TraversalBudget): boolean {
  if (budget.exhausted) return false;
  if (budget.deadlineAt !== undefined && Date.now() >= budget.deadlineAt) {
    budget.exhausted = true;
    return false;
  }
  return true;
}

function consumeTraversalNode(budget: TraversalBudget): boolean {
  if (!traversalBudgetReady(budget)) return false;
  budget.nodes += 1;
  if (budget.nodes > (budget.maxNodes ?? GUARD_PREPROCESS_MAX_NODES)) {
    budget.exhausted = true;
    return false;
  }
  return true;
}

function boundedCodePointPrefix(
  value: string,
  limit: number,
  budget: TraversalBudget,
): BoundedCodePointPrefix {
  const max = Math.max(limit, 0);
  let index = 0;
  let chars = 0;
  while (index < value.length && chars < max) {
    if ((chars & 0x3ff) === 0 && !traversalBudgetReady(budget)) {
      return { text: value.slice(0, index), chars, complete: false };
    }
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
      const next = value.charCodeAt(index + 1);
      index += next >= 0xdc00 && next <= 0xdfff ? 2 : 1;
    } else {
      index += 1;
    }
    chars += 1;
  }
  if (!traversalBudgetReady(budget)) {
    return { text: value.slice(0, index), chars, complete: false };
  }
  return { text: value.slice(0, index), chars, complete: index >= value.length };
}

function appendSafeExcerpt(
  accumulator: { text: string; truncated: boolean },
  value: string,
  budget: TraversalBudget,
): void {
  if (accumulator.truncated || value.length === 0) return;
  if (!traversalBudgetReady(budget)) {
    accumulator.truncated = true;
    return;
  }
  const prefix = accumulator.text ? "\n" : "";
  const available = GUARD_TEXT_LIMIT_CHARS - accumulator.text.length - prefix.length;
  if (available <= 0) {
    accumulator.truncated = true;
    return;
  }
  if (value.length <= available) {
    accumulator.text += `${prefix}${value}`;
    return;
  }
  const bounded = boundedCodePointPrefix(value, available, budget);
  accumulator.text += `${prefix}${bounded.text}`;
  accumulator.truncated = true;
}

function safeTruncateText(
  value: string,
  limit = GUARD_TEXT_LIMIT_CHARS,
  budget: TraversalBudget = createTraversalBudget(),
): string {
  if (value.length <= limit && traversalBudgetReady(budget)) return value;
  const bounded = boundedCodePointPrefix(value, limit, budget);
  return `${bounded.text}\n...[truncated by HOL Guard]...`;
}

function digestOutputText(
  value: unknown,
  deadlineAt?: number,
  budget = createTraversalBudget(deadlineAt),
): OutputDigest {
  const hash = createHash('sha256');
  let chars = 0;
  let textForExcerpt = '';
  let excerptTruncated = false;
  let traversalTruncated = false;
  const seen = new WeakSet<object>();
  const excerpt = { text: '', truncated: false };
  const refuse = (): void => {
    traversalTruncated = true;
    budget.exhausted = true;
  };
  function update(text: string): void {
    if (traversalTruncated || !traversalBudgetReady(budget)) {
      refuse();
      return;
    }
    // Reject before hashing or counting an uncapped string.  Only the small
    // excerpt prefix is inspected, so a hostile single string cannot force a
    // full code-point array or an unbounded hash operation.
    if (text.length > GUARD_SOURCE_REF_MAX_OUTPUT_CHARS) {
      appendSafeExcerpt(excerpt, text, budget);
      excerptTruncated = true;
      refuse();
      return;
    }
    const bounded = boundedCodePointPrefix(text, GUARD_SOURCE_REF_MAX_OUTPUT_CHARS, budget);
    if (!bounded.complete) {
      appendSafeExcerpt(excerpt, bounded.text, budget);
      excerptTruncated = true;
      refuse();
      return;
    }
    if (!traversalBudgetReady(budget)) {
      refuse();
      return;
    }
    hash.update(text, 'utf8');
    chars += bounded.chars;
    appendSafeExcerpt(excerpt, text, budget);
    if (excerpt.truncated) excerptTruncated = true;
    if (!traversalBudgetReady(budget)) refuse();
  }
  function traverse(val: unknown, depth: number): void {
    if (traversalTruncated || !consumeTraversalNode(budget)) {
      refuse();
      return;
    }
    if (typeof val === 'string') { update(val); return; }
    if (val === undefined || val === null) return;
    if (typeof val === 'number' || typeof val === 'boolean') return;
    if (typeof val === 'bigint') { update(val.toString()); return; }
    if (typeof val !== 'object') { refuse(); return; }
    const obj = val as object;
    if (seen.has(obj) || depth > GUARD_MAX_DEPTH) { refuse(); return; }
    seen.add(obj);
    try {
      if (Array.isArray(val)) {
        if (val.length > GUARD_CONTENT_ITEM_LIMIT) { refuse(); return; }
        for (const item of val) {
          if (traversalTruncated) return;
          traverse(item, depth + 1);
        }
        return;
      }
      const record = val as Record<string, unknown>;
      if (record.type === 'text' && typeof record.text === 'string') {
        update(record.text);
        return;
      }
      let keyCount = 0;
      for (const key of OUTPUT_TEXT_KEYS) {
        if (!(key in record)) continue;
        if (keyCount >= GUARD_OBJECT_KEY_LIMIT) { refuse(); return; }
        keyCount += 1;
        traverse(record[key], depth + 1);
        if (traversalTruncated) return;
      }
    } finally {
      seen.delete(obj);
    }
  }
  try {
    traverse(value, 0);
  } catch {
    refuse();
  }
  textForExcerpt = excerpt.text;
  excerptTruncated = excerptTruncated || excerpt.truncated;
  return {
    sha256: traversalTruncated ? null : hash.digest('hex'),
    chars,
    textForExcerpt,
    excerptTruncated,
    traversalTruncated,
  };
}

function boundValue(
  value: unknown,
  depth = 0,
  seen = new WeakSet<object>(),
  budget = createTraversalBudget(),
): BoundedValue {
  if (!consumeTraversalNode(budget)) {
    return { value: '[content omitted by HOL Guard]', truncated: true };
  }
  if (typeof value === 'string') {
    if (value.length <= GUARD_TEXT_LIMIT_CHARS && traversalBudgetReady(budget)) {
      return { value, truncated: false };
    }
    return { value: safeTruncateText(value, GUARD_TEXT_LIMIT_CHARS, budget), truncated: true };
  }
  if (value === undefined) return { value: undefined, truncated: false };
  if (typeof value === 'bigint') {
    const text = value.toString();
    return {
      value: safeTruncateText(text, GUARD_TEXT_LIMIT_CHARS, budget),
      truncated: text.length > GUARD_TEXT_LIMIT_CHARS,
    };
  }
  if (
    value === null ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return { value, truncated: false };
  }
  if (typeof value !== 'object') {
    return { value: String(value), truncated: true };
  }
  const objectValue = value as object;
  if (seen.has(objectValue)) {
    return { value: '[cycle omitted by HOL Guard]', truncated: true };
  }
  if (depth > GUARD_MAX_DEPTH) {
    return { value: '[deep object omitted by HOL Guard]', truncated: true };
  }
  seen.add(objectValue);
  try {
    if (Array.isArray(value)) {
      const itemLimit = Math.min(value.length, GUARD_CONTENT_ITEM_LIMIT);
      const nextItems: unknown[] = [];
      let truncated = value.length > GUARD_CONTENT_ITEM_LIMIT;
      for (let index = 0; index < itemLimit; index += 1) {
        const next = boundValue(value[index], depth + 1, seen, budget);
        nextItems.push(next.value);
        truncated = truncated || next.truncated;
        if (!traversalBudgetReady(budget)) {
          truncated = true;
          break;
        }
      }
      return { value: nextItems, truncated };
    }
    const record = value as Record<string, unknown>;
    const nextRecord: Record<string, unknown> = {};
    let truncated = false;
    let keyCount = 0;
    for (const key in record) {
      if (!Object.prototype.hasOwnProperty.call(record, key)) continue;
      if (keyCount >= GUARD_OBJECT_KEY_LIMIT || !traversalBudgetReady(budget)) {
        truncated = true;
        break;
      }
      keyCount += 1;
      const next = boundValue(record[key], depth + 1, seen, budget);
      nextRecord[key] = next.value;
      truncated = truncated || next.truncated;
    }
    return { value: nextRecord, truncated };
  } finally {
    seen.delete(objectValue);
  }
}

function safeCollectOutputText(
  value: unknown,
  accumulator: { text: string; truncated: boolean; itemCount: number },
  depth: number,
  seen: WeakSet<object>,
  budget: TraversalBudget,
): void {
  if (accumulator.truncated || !consumeTraversalNode(budget)) {
    accumulator.truncated = true;
    return;
  }
  if (typeof value === 'string') {
    appendSafeExcerpt(accumulator, value, budget);
    return;
  }
  if (typeof value === 'bigint') {
    appendSafeExcerpt(accumulator, value.toString(), budget);
    return;
  }
  if (
    value === undefined ||
    value === null ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) return;
  if (typeof value !== 'object') {
    accumulator.truncated = true;
    return;
  }
  const objectValue = value as object;
  if (seen.has(objectValue) || depth > GUARD_MAX_DEPTH) {
    accumulator.truncated = true;
    return;
  }
  seen.add(objectValue);
  try {
    if (Array.isArray(value)) {
      const itemLimit = Math.min(value.length, GUARD_CONTENT_ITEM_LIMIT);
      for (let index = 0; index < itemLimit; index += 1) {
        if (accumulator.itemCount >= GUARD_CONTENT_ITEM_LIMIT) {
          accumulator.truncated = true;
          break;
        }
        accumulator.itemCount += 1;
        safeCollectOutputText(value[index], accumulator, depth + 1, seen, budget);
        if (accumulator.truncated) break;
      }
      if (value.length > GUARD_CONTENT_ITEM_LIMIT) accumulator.truncated = true;
      return;
    }
    const record = value as Record<string, unknown>;
    if (record.type === 'text' && typeof record.text === 'string') {
      appendSafeExcerpt(accumulator, record.text, budget);
      return;
    }
    for (const key of OUTPUT_TEXT_KEYS) {
      if (!(key in record)) continue;
      safeCollectOutputText(record[key], accumulator, depth + 1, seen, budget);
      if (accumulator.truncated) break;
    }
  } finally {
    seen.delete(objectValue);
  }
}

function boundedOutputText(
  value: unknown,
  deadlineAt?: number,
  budget = createTraversalBudget(deadlineAt),
): BoundedValue {
  const accumulator = { text: '', truncated: false, itemCount: 0 };
  safeCollectOutputText(value, accumulator, 0, new WeakSet<object>(), budget);
  return { value: accumulator.text, truncated: accumulator.truncated || budget.exhausted };
}

function boundedResponseText(
  response: Response,
  maxChars: number,
  deadlineAt?: number,
): Promise<string | null> {
  return (async (): Promise<string | null> => {
    const body = response.body;
    const reader = body && typeof body.getReader === 'function' ? body.getReader() : null;
    if (!reader) return null;
    const decoder = new TextDecoder();
    let text = '';
    try {
      for (;;) {
        if (deadlineAt !== undefined && Date.now() >= deadlineAt) {
          try { await reader.cancel(); } catch {}
          return null;
        }
        const next = await reader.read();
        if (deadlineAt !== undefined && Date.now() >= deadlineAt) {
          try { await reader.cancel(); } catch {}
          return null;
        }
        if (next.done) {
          const tail = decoder.decode();
          if (text.length + tail.length > maxChars) return null;
          text += tail;
          return text;
        }
        const chunk = next.value as Uint8Array;
        const remaining = maxChars - text.length;
        // UTF-8 needs at most four bytes per code point plus a small
        // incomplete-sequence allowance. Reject before decoding an oversized
        // stream chunk so a hostile daemon body is not materialized first.
        if (remaining < 0 || chunk.byteLength > remaining * 4 + 4) {
          try { await reader.cancel(); } catch {}
          return null;
        }
        const decoded = decoder.decode(chunk, { stream: true });
        if (text.length + decoded.length > maxChars) {
          try { await reader.cancel(); } catch {}
          return null;
        }
        text += decoded;
      }
    } catch {
      return null;
    } finally {
      try { reader.releaseLock(); } catch {}
    }
  })();
}

function boundedJsonStringSize(value: string, budget: TraversalBudget): number | null {
  if (!traversalBudgetReady(budget)) return null;
  if (value.length + 2 > GUARD_MAX_REFERENCE_JSON_BYTES) return null;
  let size = 2;
  for (let index = 0; index < value.length; index += 1) {
    if ((index & 0x3ff) === 0 && !traversalBudgetReady(budget)) return null;
    const code = value.charCodeAt(index);
    if (code === 0x22 || code === 0x5c) {
      size += 2;
    } else if (code < 0x20) {
      if ([8, 9, 10, 12, 13].includes(code)) {
        size += 2;
      } else {
        size += 6;
      }
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        size += 4;
        index += 1;
      } else {
        size += 6;
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      size += 6;
    } else {
      if (code < 0x80) {
        size += 1;
      } else if (code < 0x800) {
        size += 2;
      } else {
        size += 3;
      }
    }
    if (size > GUARD_MAX_REFERENCE_JSON_BYTES) return null;
  }
  return size;
}

function hasCallableSerializationHook(value: object): boolean {
  try {
    let owner: object | null = value;
    while (owner !== null) {
      const descriptor = Object.getOwnPropertyDescriptor(owner, 'toJSON');
      if (descriptor) {
        if (!Object.prototype.hasOwnProperty.call(descriptor, 'value')) return true;
        if (typeof descriptor.value === 'function') return true;
      }
      owner = Object.getPrototypeOf(owner);
    }
    return false;
  } catch {
    return true;
  }
}

// The preflight proves only ordinary JSON-like data. Reflection of arbitrary
// objects can execute proxy traps, so this does not claim universal detection
// or boundedness for custom JavaScript objects.
function safeEnumerableDataKeys(record: Record<string, unknown>): string[] | null {
  try {
    const prototype = Object.getPrototypeOf(record);
    if (prototype !== Object.prototype && prototype !== null) return null;
    if (hasCallableSerializationHook(record)) return null;
    const keys = Object.keys(record);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(record, key);
      if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) return null;
    }
    return keys;
  } catch {
    return null;
  }
}

function boundedJsonSize(
  value: unknown,
  budget: TraversalBudget,
  depth: number,
  seen: WeakSet<object>,
  inArray: boolean,
): number | null {
  if (!consumeTraversalNode(budget) || depth > GUARD_MAX_DEPTH) return null;
  if (value === null) return 4;
  if (typeof value === 'string') return boundedJsonStringSize(value, budget);
  if (typeof value === 'boolean') return value ? 4 : 5;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return 4;
    try {
      const serialized = JSON.stringify(value);
      return typeof serialized === 'string' ? serialized.length : 4;
    } catch {
      return null;
    }
  }
  if (value === undefined || typeof value === 'function' || typeof value === 'symbol') {
    return inArray ? 4 : 0;
  }
  if (typeof value === 'bigint' || typeof value !== 'object') return null;
  const objectValue = value as object;
  if (seen.has(objectValue)) return null;
  seen.add(objectValue);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype || hasCallableSerializationHook(value)) return null;
      const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
      if (
        !lengthDescriptor
        || !Object.prototype.hasOwnProperty.call(lengthDescriptor, 'value')
        || !Number.isSafeInteger(lengthDescriptor.value)
        // Every dense element uses at least one byte, plus comma separators.
        || lengthDescriptor.value > Math.floor((GUARD_MAX_REFERENCE_JSON_BYTES - 1) / 2)
      ) return null;
      const length = lengthDescriptor.value;
      let size = 2;
      for (let index = 0; index < length; index += 1) {
        if (!traversalBudgetReady(budget)) return null;
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) return null;
        const child = boundedJsonSize(descriptor.value, budget, depth + 1, seen, true);
        if (child === null) return null;
        if (index > 0) size += 1;
        size += child;
        if (size > GUARD_MAX_REFERENCE_JSON_BYTES) return null;
      }
      return size;
    }
    const record = value as Record<string, unknown>;
    const keys = safeEnumerableDataKeys(record);
    if (keys === null) return null;
    let size = 2;
    let included = 0;
    for (const key of keys) {
      if (!traversalBudgetReady(budget)) return null;
      const child = boundedJsonSize(record[key], budget, depth + 1, seen, false);
      if (child === null) return null;
      if (child === 0) continue;
      const keySize = boundedJsonStringSize(key, budget);
      if (keySize === null) return null;
      if (included > 0) size += 1;
      size += keySize + 1 + child;
      included += 1;
      if (size > GUARD_MAX_REFERENCE_JSON_BYTES) return null;
    }
    return size;
  } catch {
    return null;
  } finally {
    seen.delete(objectValue);
  }
}

function payloadWithinSerializedBudget(payload: Record<string, unknown>, deadlineAt?: number): boolean {
  const budget = createTraversalBudget(deadlineAt);
  // Shape traversal may exceed the ordinary excerpt budget, but never the
  // same native reference byte budget used by the final serialized payload.
  budget.maxNodes = GUARD_MAX_REFERENCE_JSON_BYTES;
  try {
    const size = boundedJsonSize(payload, budget, 0, new WeakSet<object>(), false);
    return size !== null && size <= GUARD_MAX_REFERENCE_JSON_BYTES && traversalBudgetReady(budget);
  } catch {
    return false;
  }
}

/* HOL Guard bounded preprocessing ends */

"""

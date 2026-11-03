import { PATTERNS, SENSITIVE_KEY, normaliseKey, luhn, type Pattern } from "./patterns.js";

export { PATTERNS, SENSITIVE_KEY, normaliseKey, luhn, type Pattern };

export interface ScrubOptions {
  /** Replacement text, or a function given the secret and detector type. Default: "[REDACTED]". */
  replacement?: string | ((secret: string, type: string) => string);
  /** Append the detector type, e.g. "[REDACTED:jwt]". Ignored when `replacement` is a function. Default: false. */
  tag?: boolean;
  /** Keep this many trailing characters visible, e.g. "[REDACTED…x9Qz]". Default: 0. */
  reveal?: number;
  /** Enable optional detectors by type, e.g. ["email", "ipv4"]. */
  enable?: string[];
  /** Disable detectors by type. */
  disable?: string[];
  /** Extra detectors, run before the built-ins. */
  patterns?: Pattern[];
  /** Extra object keys (exact, case-insensitive) whose values are redacted wholesale. */
  keys?: string[];
  /** Object keys (exact, case-insensitive) never redacted wholesale. Their string values are still pattern-scanned. */
  ignoreKeys?: string[];
  /** Maximum nesting depth for objects. Deeper values become "[DEPTH LIMIT]". Default: 32. */
  maxDepth?: number;
}

export interface Finding {
  /** Detector type, e.g. "github-token", or "key" for a sensitive object key. */
  type: string;
  /** Character offset in the string, when scanning a string. */
  start?: number;
  end?: number;
  /** Object path, e.g. "headers.authorization", when scanning an object. */
  path?: string;
}

interface Resolved {
  patterns: Pattern[];
  replace: (secret: string, type: string) => string;
  keys: Set<string>;
  ignoreKeys: Set<string>;
  maxDepth: number;
}

function resolve(options: ScrubOptions): Resolved {
  const enable = new Set(options.enable ?? []);
  const disable = new Set(options.disable ?? []);
  const patterns = [...(options.patterns ?? []), ...PATTERNS].filter(
    (p) => !disable.has(p.type) && (!p.optional || enable.has(p.type)),
  );
  for (const p of patterns) if (!p.regex.global) throw new TypeError(`Pattern "${p.type}" must use the global flag`);

  const { replacement = "[REDACTED]", tag = false, reveal = 0 } = options;
  const replace =
    typeof replacement === "function"
      ? replacement
      : (secret: string, type: string) => {
          // "[REDACTED]" -> "[REDACTED:jwt…x9Qz]"; a replacement without brackets just gets suffixes.
          const bracket = replacement.endsWith("]");
          let out = bracket ? replacement.slice(0, -1) : replacement;
          if (tag) out += `:${type}`;
          if (reveal > 0 && secret.length > reveal) out += `…${secret.slice(-reveal)}`;
          return bracket ? `${out}]` : out;
        };

  return {
    patterns,
    replace,
    keys: new Set((options.keys ?? []).map((k) => k.toLowerCase())),
    ignoreKeys: new Set((options.ignoreKeys ?? []).map((k) => k.toLowerCase())),
    maxDepth: options.maxDepth ?? 32,
  };
}

interface Span { start: number; end: number; type: string; secret: string }

function findSpans(text: string, patterns: Pattern[]): Span[] {
  const spans: Span[] = [];
  const taken: Array<[number, number]> = [];
  const overlaps = (s: number, e: number) => taken.some(([ts, te]) => s < te && e > ts);

  for (const p of patterns) {
    p.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = p.regex.exec(text)) !== null) {
      if (m[0] === "") { p.regex.lastIndex++; continue; }
      const g = p.group ?? 0;
      const secret = m[g];
      if (secret === undefined || secret === "") continue;
      // Offset of the group within the match: sum of the preceding groups' lengths.
      let offset = 0;
      for (let i = 1; i < g; i++) offset += (m[i] ?? "").length;
      const start = m.index + offset;
      const end = start + secret.length;
      if (overlaps(start, end)) continue;
      if (p.validate && !p.validate(secret)) continue;
      spans.push({ start, end, type: p.type, secret });
      taken.push([start, end]);
    }
  }
  return spans.sort((a, b) => a.start - b.start);
}

function scrubString(text: string, r: Resolved): string {
  const spans = findSpans(text, r.patterns);
  if (spans.length === 0) return text;
  let out = "";
  let cursor = 0;
  for (const s of spans) {
    out += text.slice(cursor, s.start) + r.replace(s.secret, s.type);
    cursor = s.end;
  }
  return out + text.slice(cursor);
}

function isSensitiveKey(key: string, r: Resolved): boolean {
  const lower = key.toLowerCase();
  if (r.ignoreKeys.has(lower)) return false;
  if (r.keys.has(lower)) return true;
  return SENSITIVE_KEY.test(normaliseKey(key));
}

function scrubValue(value: unknown, r: Resolved, depth: number, seen: WeakSet<object>): unknown {
  if (typeof value === "string") return scrubString(value, r);
  if (value === null || typeof value !== "object") return value;
  if (depth > r.maxDepth) return "[DEPTH LIMIT]";
  if (seen.has(value)) return "[CIRCULAR]";
  seen.add(value);

  if (value instanceof Error) {
    const out: Record<string, unknown> = { name: value.name, message: scrubString(value.message, r) };
    if (value.stack) out.stack = scrubString(value.stack, r);
    for (const k of Object.keys(value)) out[k] = scrubField(k, (value as unknown as Record<string, unknown>)[k], r, depth, seen);
    return out;
  }
  if (Array.isArray(value)) return value.map((v) => scrubValue(v, r, depth + 1, seen));
  if (value instanceof Date || value instanceof RegExp) return value;
  if (value instanceof Map) {
    return new Map([...value].map(([k, v]) => [k, typeof k === "string" ? scrubField(k, v, r, depth, seen) : scrubValue(v, r, depth + 1, seen)]));
  }
  if (value instanceof Set) return new Set([...value].map((v) => scrubValue(v, r, depth + 1, seen)));

  const out: Record<string, unknown> = {};
  for (const k of Object.keys(value)) out[k] = scrubField(k, (value as Record<string, unknown>)[k], r, depth, seen);
  return out;
}

function scrubField(key: string, v: unknown, r: Resolved, depth: number, seen: WeakSet<object>): unknown {
  if (isSensitiveKey(key, r)) {
    if (v === null || v === undefined) return v;
    if (typeof v === "string" || typeof v === "number" || typeof v === "bigint") return r.replace(String(v), "key");
    if (typeof v === "boolean") return v;
    // Objects under a sensitive key: redact every leaf.
    return redactLeaves(v, r, seen);
  }
  return scrubValue(v, r, depth + 1, seen);
}

function redactLeaves(v: unknown, r: Resolved, seen: WeakSet<object>): unknown {
  if (v === null || v === undefined || typeof v === "boolean") return v;
  if (typeof v !== "object") return r.replace(String(v), "key");
  if (seen.has(v) && !Array.isArray(v)) return "[CIRCULAR]";
  seen.add(v);
  if (Array.isArray(v)) return v.map((x) => redactLeaves(x, r, seen));
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(v)) out[k] = redactLeaves((v as Record<string, unknown>)[k], r, seen);
  return out;
}

/**
 * Return a copy of `input` with secrets replaced.
 * Strings are pattern-scanned. Objects and arrays are walked without mutation;
 * values under sensitive keys (password, token, apiKey, authorization, ...) are
 * redacted wholesale, and every other string is pattern-scanned.
 */
export function scrub<T>(input: T, options: ScrubOptions = {}): T {
  const r = resolve(options);
  return scrubValue(input, r, 0, new WeakSet()) as T;
}

/**
 * Report where secrets are, without returning their values.
 * For strings you get offsets; for objects you get paths.
 */
export function scan(input: unknown, options: ScrubOptions = {}): Finding[] {
  const r = resolve(options);
  const findings: Finding[] = [];
  if (typeof input === "string") {
    for (const s of findSpans(input, r.patterns)) findings.push({ type: s.type, start: s.start, end: s.end });
    return findings;
  }
  const seen = new WeakSet<object>();
  const walk = (v: unknown, path: string, depth: number) => {
    if (typeof v === "string") {
      for (const s of findSpans(v, r.patterns)) findings.push({ type: s.type, path, start: s.start, end: s.end });
      return;
    }
    if (v === null || typeof v !== "object" || depth > r.maxDepth || seen.has(v)) return;
    seen.add(v);
    const entries: Array<[string, unknown]> = Array.isArray(v)
      ? v.map((x, i) => [String(i), x] as [string, unknown])
      : v instanceof Map
        ? [...v].map(([k, x]) => [String(k), x] as [string, unknown])
        : v instanceof Set
          ? [...v].map((x, i) => [String(i), x] as [string, unknown])
          : v instanceof Error
            ? [["message", v.message], ["stack", v.stack], ...Object.entries(v)]
            : Object.entries(v);
    for (const [k, x] of entries) {
      const p = path ? `${path}.${k}` : k;
      if (!Array.isArray(v) && !(v instanceof Set) && isSensitiveKey(k, r) && x !== null && x !== undefined && typeof x !== "boolean") {
        findings.push({ type: "key", path: p });
      } else {
        walk(x, p, depth + 1);
      }
    }
  };
  walk(input, "", 0);
  return findings;
}

/** True when `input` contains at least one secret. */
export function hasSecrets(input: unknown, options: ScrubOptions = {}): boolean {
  return scan(input, options).length > 0;
}

/** Build a reusable scrubber with fixed options. */
export function createScrubber(options: ScrubOptions = {}) {
  return {
    scrub: <T>(input: T) => scrub(input, options),
    scan: (input: unknown) => scan(input, options),
    hasSecrets: (input: unknown) => hasSecrets(input, options),
  };
}

export default scrub;

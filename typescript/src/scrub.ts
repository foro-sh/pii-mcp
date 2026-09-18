/**
 * Language packs and scrub walk with optional Rust acceleration.
 *
 * When the napi addon (``pii-core`` via ``crates/pii-mcp-napi``) is loadable,
 * ``scrubText`` / ``scrubPayload`` prefer it. Set ``PII_MCP_BACKEND=js`` (or
 * ``typescript`` / ``ts``) to force the pure TypeScript path; ``native`` /
 * ``rust`` requires the addon. Default ``npm install`` stays pure TS — no Rust
 * toolchain required.
 */

import { loadNative, type NativeCounts } from "./native.js";
import {
  scrubPayloadJs,
  scrubTextJs,
} from "./scrub-js.js";
import {
  MAX_DEPTH,
  PII_TYPES,
  PiiScrubError,
  emptyPiiCounts,
  type PiiCounts,
  type ScrubReport,
} from "./types.js";

export {
  DEFAULT_LANGUAGES,
  MAX_DEPTH,
  MAX_SCRUB_BYTES,
  PII_TYPES,
  PiiScrubError,
  emptyPiiCounts,
  mergeCounts,
  normalizeLanguages,
  totalPiiCount,
  type LanguageCode,
  type PiiCounts,
  type PiiType,
  type ScrubReport,
} from "./scrub-js.js";

export type ScrubTextResult = { text: string } & ScrubReport;
export type ScrubPayloadResult = { payload: unknown } & ScrubReport;

export type ScrubOptions = {
  languages?: readonly string[] | null | undefined;
};

function normalizeCounts(raw: NativeCounts): PiiCounts {
  const counts = emptyPiiCounts();
  for (const t of PII_TYPES) {
    const n = raw[t];
    counts[t] = typeof n === "number" ? n : 0;
  }
  return counts;
}

function raiseNativeError(err: unknown): never {
  const msg = err instanceof Error ? err.message : String(err);
  if (msg.startsWith("PiiScrubError:")) {
    throw new PiiScrubError(msg.slice("PiiScrubError:".length));
  }
  if (msg.startsWith("unknown language")) {
    throw new Error(msg);
  }
  throw err instanceof Error ? err : new Error(msg);
}

function resolveBackend(): "native" | "js" {
  const flag = (process.env.PII_MCP_BACKEND ?? "auto").trim().toLowerCase();
  if (flag === "js" || flag === "javascript" || flag === "ts" || flag === "typescript") {
    return "js";
  }
  if (flag === "native" || flag === "rust") {
    if (loadNative() === null) {
      throw new Error(
        "PII_MCP_BACKEND=native but the napi addon is not installed; " +
          "build with: npm run build:native (in typescript/)",
      );
    }
    return "native";
  }
  return loadNative() !== null ? "native" : "js";
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

/**
 * Mirror Python ``py_to_value``: reject non-JSON / non-plain values before the
 * napi boundary, so Date/Map/class instances fail closed instead of being
 * silently coerced by serde.
 */
function assertPlainJson(value: unknown, depth = 0): unknown {
  if (depth > MAX_DEPTH) {
    throw new PiiScrubError(
      `payload nests past the ${MAX_DEPTH}-level scrub limit`,
    );
  }
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return value;
  }
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => assertPlainJson(item, depth + 1));
  }
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = assertPlainJson(item, depth + 1);
    }
    return out;
  }
  throw new PiiScrubError(
    "payload contains a non-plain object that cannot be safely scrubbed",
  );
}

/** Return true when the optional Rust napi addon will handle scrub calls. */
export function usingNative(): boolean {
  return resolveBackend() === "native";
}

/**
 * Mask pattern-detectable PII in a string. Returns ``{text, found, counts}``.
 *
 * Raises ``PiiScrubError`` when input exceeds ``MAX_SCRUB_BYTES``.
 */
export function scrubText(
  text: string,
  options?: ScrubOptions,
): ScrubTextResult {
  if (resolveBackend() === "native") {
    const native = loadNative();
    if (native === null) {
      throw new Error("native backend selected but addon failed to load");
    }
    try {
      const languages =
        options?.languages === undefined || options.languages === null
          ? null
          : [...options.languages];
      const result = native.scrubText(text, languages);
      return {
        text: result.text,
        found: result.found,
        counts: normalizeCounts(result.counts),
      };
    } catch (err) {
      raiseNativeError(err);
    }
  }
  return scrubTextJs(text, {
    languages: options?.languages,
    checkSize: true,
  });
}

/**
 * Walk a JSON-like payload and mask string leaves. Fails closed on errors.
 *
 * Size is enforced on string leaves before the walk. Non-plain objects and
 * oversize input raise ``PiiScrubError``.
 */
export function scrubPayload(
  payload: unknown,
  options?: ScrubOptions,
): ScrubPayloadResult {
  if (resolveBackend() === "native") {
    const native = loadNative();
    if (native === null) {
      throw new Error("native backend selected but addon failed to load");
    }
    try {
      const languages =
        options?.languages === undefined || options.languages === null
          ? null
          : [...options.languages];
      const plain = assertPlainJson(payload);
      const result = native.scrubPayload(plain, languages);
      return {
        payload: result.payload,
        found: result.found,
        counts: normalizeCounts(result.counts),
      };
    } catch (err) {
      raiseNativeError(err);
    }
  }
  return scrubPayloadJs(payload, { languages: options?.languages });
}

/**
 * Tier 1 gate surface for foro user-container proxies.
 *
 * Sync, fail-closed, pattern-only (no native addon, no NER, no network).
 * Bundled by ``npm run build:gate`` into ``gate/pii-gate.mjs`` for a zero-npm
 * COPY into container images. Prefer this entry over the package root when the
 * process must never load napi or spaCy/candle.
 *
 * Contract details: ``docs/tier1-gate.md``.
 */

import {
  DEFAULT_LANGUAGES,
  MAX_DEPTH,
  MAX_SCRUB_BYTES,
  PII_TYPES,
  PiiScrubError,
  emptyPiiCounts,
  mergeCounts,
  normalizeLanguages,
  normalizeTypes,
  scrubPayloadJs,
  scrubTextJs,
  totalPiiCount,
  type LanguageCode,
  type MaskOptions,
  type PiiCounts,
  type PiiType,
  type ScrubReport,
} from "./scrub-js.js";

export type ScrubTextResult = { text: string } & ScrubReport;
export type ScrubPayloadResult = { payload: unknown } & ScrubReport;

export type GateScrubOptions = {
  languages?: readonly string[] | null | undefined;
} & MaskOptions;

const NER_REMOVED =
  "ner was removed from pii-mcp; use Presidio or another out-of-process NER " +
  "for person names in prose (see README Scope)";

function rejectRemovedNer(options?: GateScrubOptions): void {
  const ner = (options as { ner?: boolean } | undefined)?.ner;
  if (ner) {
    throw new PiiScrubError(NER_REMOVED);
  }
}

/**
 * Mask pattern-detectable PII in a string. Returns ``{text, found, counts}``.
 *
 * Raises ``PiiScrubError`` when input exceeds ``MAX_SCRUB_BYTES`` (32 MiB).
 */
export function scrubText(
  text: string,
  options: GateScrubOptions = {},
): ScrubTextResult {
  rejectRemovedNer(options);
  return scrubTextJs(text, {
    languages: options.languages,
    types: options.types,
    allow: options.allow,
    checkSize: true,
  });
}

/**
 * Walk a JSON-like payload and mask string leaves. Fails closed on errors.
 *
 * Skips MCP binary fields (``data`` on image/audio, ``blob`` on resource
 * contents). Raises ``PiiScrubError`` on oversize input, depth past
 * ``MAX_DEPTH``, or non-plain objects.
 */
export function scrubPayload(
  payload: unknown,
  options: GateScrubOptions = {},
): ScrubPayloadResult {
  rejectRemovedNer(options);
  return scrubPayloadJs(payload, {
    languages: options.languages,
    types: options.types,
    allow: options.allow,
  });
}

export {
  DEFAULT_LANGUAGES,
  MAX_DEPTH,
  MAX_SCRUB_BYTES,
  PII_TYPES,
  PiiScrubError,
  emptyPiiCounts,
  mergeCounts,
  normalizeLanguages,
  normalizeTypes,
  totalPiiCount,
  type LanguageCode,
  type MaskOptions,
  type PiiCounts,
  type PiiType,
  type ScrubReport,
};

/**
 * Pattern-based PII scrubbing for MCP tool/resource/prompt results.
 *
 * Sync, in-process, regex + checksum detectors. Does not include NER for
 * person names or full street addresses (e.g. Presidio). Optional Rust
 * acceleration via the napi addon built from ``crates/pii-mcp-napi``.
 */

export {
  DEFAULT_LANGUAGES,
  MAX_DEPTH,
  MAX_SCRUB_BYTES,
  PII_TYPES,
  PiiScrubError,
  emptyPiiCounts,
  mergeCounts,
  normalizeLanguages,
  scrubPayload,
  scrubText,
  totalPiiCount,
  usingNative,
  type LanguageCode,
  type PiiCounts,
  type PiiType,
  type ScrubOptions,
  type ScrubPayloadResult,
  type ScrubReport,
  type ScrubTextResult,
} from "./scrub.js";

export { loadNative, resetNativeCache } from "./native.js";

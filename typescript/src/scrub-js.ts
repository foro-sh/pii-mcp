/**
 * Language packs and scrub walk for pattern-based detectors.
 *
 * Universal detectors (email, IBAN, credit card, BIC, MAC, IP, location) always
 * run. Locale packs add national IDs / phone shapes / NL postcodes / kentekens /
 * BTW-ids. Counts always include every ``PiiType`` key (0 when unused), including
 * reserved ``person`` (unused until NER is added). ``address`` is reserved for
 * street-address NER and also receives NL postcode hits from the pattern pack.
 *
 * ``MAX_SCRUB_BYTES`` matches foro-proxy (32 MiB). Oversize raises
 * ``PiiScrubError`` so callers withhold rather than forward unscrubbed text.
 *
 * Detector pack order (see ``detectorsFor``): universal → checksum/rule-backed
 * national IDs (BSN before SSN when both packs are on; NL BTW after BSN) → NL
 * postcode / kenteken when ``nl`` → phones (international when any pack is
 * active, then locale forms).
 */

import {
  UNIVERSAL_DETECTORS,
  bsnDetector,
  nlLicensePlateDetector,
  nlPostcodeDetector,
  nlVatDetector,
  phoneDeDetector,
  phoneEnDetector,
  phoneInternationalDetector,
  phoneNlDetector,
  ssnDetector,
  taxIdDetector,
  type Detector,
} from "./detectors.js";
import {
  DEFAULT_LANGUAGES,
  MAX_DEPTH,
  MAX_SCRUB_BYTES,
  PII_TYPES,
  PiiScrubError,
  emptyPiiCounts,
  mergeCounts,
  totalPiiCount,
  type LanguageCode,
  type PiiCounts,
  type PiiType,
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
  totalPiiCount,
  type LanguageCode,
  type PiiCounts,
  type PiiType,
  type ScrubReport,
};

const KNOWN_LANGUAGES = new Set<string>(["en", "nl", "de"]);

export function normalizeLanguages(
  languages: readonly string[] | null | undefined,
): readonly LanguageCode[] {
  if (languages === undefined || languages === null) {
    return DEFAULT_LANGUAGES;
  }
  if (languages.length === 0) {
    return [];
  }
  const out: LanguageCode[] = [];
  const seen = new Set<string>();
  for (const raw of languages) {
    const code = raw.toLowerCase();
    if (!KNOWN_LANGUAGES.has(code)) {
      const supported = [...KNOWN_LANGUAGES].sort().map((c) => `'${c}'`).join(", ");
      throw new Error(`unknown language '${raw}'; supported: [${supported}]`);
    }
    if (!seen.has(code)) {
      seen.add(code);
      out.push(code as LanguageCode);
    }
  }
  return out;
}

function detectorsFor(
  languages: readonly string[] | null | undefined,
): readonly Detector[] {
  const langs = normalizeLanguages(languages);
  const pack: Detector[] = [...UNIVERSAL_DETECTORS];
  if (langs.includes("nl")) {
    pack.push(bsnDetector, nlVatDetector);
  }
  if (langs.includes("de")) {
    pack.push(taxIdDetector);
  }
  if (langs.includes("en")) {
    pack.push(ssnDetector);
  }
  if (langs.includes("nl")) {
    pack.push(nlPostcodeDetector, nlLicensePlateDetector);
  }
  if (langs.length > 0) {
    pack.push(phoneInternationalDetector);
  }
  if (langs.includes("nl")) {
    pack.push(phoneNlDetector);
  }
  if (langs.includes("en")) {
    pack.push(phoneEnDetector);
  }
  if (langs.includes("de")) {
    pack.push(phoneDeDetector);
  }
  return pack;
}

function utf8Size(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

function payloadStringBytes(value: unknown, depth = 0): number {
  if (depth > MAX_DEPTH) {
    throw new PiiScrubError(`payload nests past the ${MAX_DEPTH}-level scrub limit`);
  }
  if (typeof value === "string") {
    return utf8Size(value);
  }
  if (Array.isArray(value)) {
    let total = 0;
    for (const item of value) {
      total += payloadStringBytes(item, depth + 1);
    }
    return total;
  }
  if (isPlainObject(value)) {
    let total = 0;
    for (const item of Object.values(value)) {
      total += payloadStringBytes(item, depth + 1);
    }
    return total;
  }
  return 0;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === null || proto === Object.prototype;
}

function isJsonScalar(value: unknown): value is null | boolean | number {
  return value === null || typeof value === "boolean" || typeof value === "number";
}

export interface ScrubTextJsOptions {
  languages?: readonly string[] | null | undefined;
  checkSize?: boolean;
}

export interface ScrubPayloadJsOptions {
  languages?: readonly string[] | null | undefined;
}

export function scrubTextJs(
  text: string,
  options: ScrubTextJsOptions = {},
): { text: string; found: boolean; counts: PiiCounts } {
  if (typeof text !== "string") {
    throw new TypeError("scrubTextJs expects a string");
  }

  const checkSize = options.checkSize ?? true;
  if (checkSize && utf8Size(text) > MAX_SCRUB_BYTES) {
    throw new PiiScrubError(
      `scrub input exceeds the ${MAX_SCRUB_BYTES}-byte size cap`,
    );
  }

  const counts = emptyPiiCounts();
  let out = text;
  for (const detector of detectorsFor(options.languages)) {
    const result = detector.scrub(out);
    out = result.text;
    counts[detector.type] += result.count;
  }
  return { text: out, found: totalPiiCount(counts) > 0, counts };
}

function scrubWalk(
  value: unknown,
  counts: PiiCounts,
  depth: number,
  languages: readonly string[] | null | undefined,
): unknown {
  if (depth > MAX_DEPTH) {
    throw new PiiScrubError(`payload nests past the ${MAX_DEPTH}-level scrub limit`);
  }
  if (typeof value === "string") {
    const result = scrubTextJs(value, { languages, checkSize: false });
    for (const t of PII_TYPES) {
      counts[t] += result.counts[t];
    }
    return result.text;
  }
  if (Array.isArray(value)) {
    return value.map((item) => scrubWalk(item, counts, depth + 1, languages));
  }
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = scrubWalk(item, counts, depth + 1, languages);
    }
    return out;
  }
  if (isJsonScalar(value)) {
    return value;
  }
  throw new PiiScrubError(
    "payload contains a non-plain object that cannot be safely scrubbed",
  );
}

export function scrubPayloadJs(
  payload: unknown,
  options: ScrubPayloadJsOptions = {},
): { payload: unknown; found: boolean; counts: PiiCounts } {
  if (payloadStringBytes(payload) > MAX_SCRUB_BYTES) {
    throw new PiiScrubError(
      `scrub input exceeds the ${MAX_SCRUB_BYTES}-byte size cap`,
    );
  }
  const counts = emptyPiiCounts();
  const scrubbed = scrubWalk(payload, counts, 0, options.languages);
  return {
    payload: scrubbed,
    found: totalPiiCount(counts) > 0,
    counts,
  };
}

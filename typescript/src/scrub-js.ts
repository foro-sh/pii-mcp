/**
 * Language packs and scrub walk for pattern-based detectors.
 *
 * Universal detectors (email, IBAN, credit card, BIC, MAC, IMEI, IP, location)
 * always run. Locale packs add national IDs / phone shapes / NL, UK, DE and US
 * postcodes / kentekens / VAT IDs / passport numbers. Counts always include
 * every ``PiiType`` key (0 when unused). ``person`` stays 0 until key-aware
 * masking (issue #52). ``address`` counts street + house number hits and NL /
 * UK / DE / US postcodes.
 *
 * ``MAX_SCRUB_BYTES`` matches foro-proxy (32 MiB). Oversize raises
 * ``PiiScrubError`` so callers withhold rather than forward unscrubbed text.
 *
 * Detector pack order (see ``detectorsFor``): universal → international phone
 * (when any pack is active, before national IDs so ``+31(0)6…`` is not eaten by
 * SSN) → UK NHS number when ``en`` (its ``3-3-4`` shape is a NANP number, and
 * an NL trunk-``0`` phone match can start in its middle group) → locale phone
 * forms (before BSN takes the subscriber part of ``040 78703244``) →
 * checksum/rule-backed national IDs (DE IdNr before BSN, BSN before SSN when
 * both packs are on, US ITIN before SSN; DE USt-IdNr and NL BTW before BSN,
 * DE/NL passport after) → street + house number per pack (en, de, nl) →
 * postcode per pack (UK and hinted US ZIP for en, hinted postcode for de,
 * bare postcode for nl) → kenteken when ``nl``.
 *
 * MCP binary content is left unscrubbed (foro-pii ``binaryKey`` parity): on an
 * object with ``type`` of ``image`` or ``audio`` and a string ``data``, that
 * ``data`` field is passed through; on an object with string ``uri`` and string
 * ``blob``, ``blob`` is passed through. Sibling string fields are still scrubbed.
 * Matched by shape, not key alone, so a ``data`` field elsewhere is scrubbed.
 * Binary leaves are also excluded from the ``MAX_SCRUB_BYTES`` string-leaf sum.
 */

import {
  UNIVERSAL_DETECTORS,
  bsnDetector,
  dePassportDetector,
  dePostcodeDetector,
  deVatDetector,
  itinDetector,
  nhsDetector,
  ninoDetector,
  nlLicensePlateDetector,
  nlPassportDetector,
  nlPostcodeDetector,
  nlVatDetector,
  phoneDeDetector,
  phoneEnDetector,
  phoneInternationalDetector,
  phoneNlDetector,
  ssnDetector,
  streetDeDetector,
  streetEnDetector,
  streetNlDetector,
  taxIdDetector,
  ukPostcodeDetector,
  usZipDetector,
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
  if (langs.length > 0) {
    pack.push(phoneInternationalDetector);
  }
  if (langs.includes("en")) {
    pack.push(nhsDetector);
  }
  // National phone forms (trunk ``0`` + area code) before bare-digit IDs, so
  // BSN does not take the subscriber part of ``040 78703244``.
  if (langs.includes("nl")) {
    pack.push(phoneNlDetector);
  }
  if (langs.includes("en")) {
    pack.push(phoneEnDetector);
  }
  if (langs.includes("de")) {
    // Tax id before BSN: the last three groups of ``12 345 678 901`` are a
    // spaced 9-digit BSN candidate.
    pack.push(phoneDeDetector, taxIdDetector, deVatDetector, dePassportDetector);
  }
  if (langs.includes("nl")) {
    // BTW-id first: its 9-digit body can itself pass the BSN elfproef.
    pack.push(nlVatDetector, bsnDetector, nlPassportDetector);
  }
  if (langs.includes("en")) {
    pack.push(
      ninoDetector,
      itinDetector,
      ssnDetector,
      streetEnDetector,
      ukPostcodeDetector,
      usZipDetector,
    );
  }
  if (langs.includes("de")) {
    pack.push(streetDeDetector, dePostcodeDetector);
  }
  if (langs.includes("nl")) {
    pack.push(streetNlDetector, nlPostcodeDetector, nlLicensePlateDetector);
  }
  return pack;
}

function utf8Size(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

/**
 * Return the MCP binary field to leave unscrubbed, or ``null``.
 *
 * Matching foro-pii: ``data`` when ``type`` is ``image`` or ``audio`` and
 * ``data`` is a string; ``blob`` when both ``uri`` and ``blob`` are strings.
 */
function binaryKey(value: Record<string, unknown>): string | null {
  if (
    (value.type === "image" || value.type === "audio") &&
    typeof value.data === "string"
  ) {
    return "data";
  }
  if (typeof value.uri === "string" && typeof value.blob === "string") {
    return "blob";
  }
  return null;
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
    const skip = binaryKey(value);
    let total = 0;
    for (const [key, item] of Object.entries(value)) {
      if (key === skip) {
        continue;
      }
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
    const skip = binaryKey(value);
    for (const [key, item] of Object.entries(value)) {
      out[key] =
        key === skip ? item : scrubWalk(item, counts, depth + 1, languages);
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

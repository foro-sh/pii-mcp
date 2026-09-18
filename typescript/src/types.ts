/**
 * Shared types and constants for pattern-based PII scrubbing.
 *
 * Sync, in-process, regex + checksum detectors. Does not include NER for
 * person names or full street addresses (e.g. Presidio).
 */

export const PII_TYPES = [
  "email",
  "iban",
  "credit_card",
  "bic",
  "mac",
  "imei",
  "ip",
  "location",
  "bsn",
  "ssn",
  "tax_id",
  "vat_id",
  "passport",
  "phone",
  "person",
  "address",
  "license_plate",
] as const;

export type PiiType = (typeof PII_TYPES)[number];

export type PiiCounts = Record<PiiType, number>;

export type LanguageCode = "en" | "nl" | "de";

export const DEFAULT_LANGUAGES: readonly LanguageCode[] = ["en", "nl"];

export const MAX_SCRUB_BYTES = 32 * 1024 * 1024;
export const MAX_DEPTH = 200;

export interface ScrubReport {
  /** Counts/found only — never carries plaintext. */
  found: boolean;
  counts: PiiCounts;
}

export class PiiScrubError extends Error {
  readonly statusCode = 500;

  constructor(message: string) {
    super(message);
    this.name = "PiiScrubError";
  }
}

export function emptyPiiCounts(): PiiCounts {
  const counts = {} as PiiCounts;
  for (const t of PII_TYPES) {
    counts[t] = 0;
  }
  return counts;
}

export function totalPiiCount(counts: PiiCounts): number {
  let total = 0;
  for (const t of PII_TYPES) {
    total += counts[t];
  }
  return total;
}

export function mergeCounts(parts: Iterable<PiiCounts>): PiiCounts {
  const merged = emptyPiiCounts();
  for (const part of parts) {
    for (const t of PII_TYPES) {
      merged[t] += part[t];
    }
  }
  return merged;
}

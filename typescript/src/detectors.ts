/**
 * Pattern detectors: regex + checksum where one exists.
 *
 * Ported from foro-sh/platform ``infra/templates/foro-pii.mts``. Detector order
 * matters — earlier matches become digit-free placeholders before looser
 * numeric detectors run.
 *
 * Patterns:
 * - Email uses bounded quantifiers (unbounded local-part ``+`` is ReDoS-prone)
 *   and ``(?!@)`` so glued addresses (``a@b.comc@d.com``) backtrack to two hits.
 *   When a TLD absorbs a following IBAN/card/IP/MAC/location, the match is
 *   shortened so both hits still redact.
 * - Spaced IBANs use separate upper- and lower-case optional-space patterns so a
 *   trailing word is not swallowed by a mixed-case class. Further patterns allow
 *   mixed case and hyphen/tab/nbsp/slash separators, plus a single hyphen after
 *   check digits. Soft hyphens and zero-width characters are stripped before
 *   IBAN matching.
 * - Credit cards include Amex 4-6-5 groupings as well as 4-4-4-x and compact;
 *   grouped forms also accept tab, nbsp, ideographic space, unicode dashes,
 *   ``.``, and ``/``; zero-width characters are stripped before matching.
 * - BIC/SWIFT: 8 or 11 alnum with ISO 3166-1 country letters (AP: financial data).
 * - MAC: colon/dash IEEE and Cisco dotted forms (AP: device MAC is personal data).
 * - IMEI: hyphen/space-grouped 15-digit forms with Luhn (AP: gegevens over
 *   elektronische communicatie / device identifiers). Compact 15-digit IMEIs
 *   that are also Luhn-valid collide with Amex and stay under ``credit_card``.
 * - IP: IPv6 with an embedded dotted quad (``::ffff:a.b.c.d``, NAT64
 *   ``64:ff9b::a.b.c.d``) is matched whole before bare IPv4, so bare IPv4 may
 *   follow a label colon (``host:10.0.0.1``); leading zeros in octets are
 *   accepted (``192.168.001.001``).
 * - Location: decimal lat/lon pairs with ≥3 fractional digits, optional
 *   ``N``/``S``/``E``/``W`` hemisphere letters, and range checks (AP lists
 *   locatiegegevens as privacy-sensitive).
 * - US SSN: hyphen/space/dot/slash or compact 9-digit with SSA area/group/serial
 *   rejects, plus obvious fakes (all-same digit, 123456789 / 987654321).
 * - German Steuer-IdNr (tax_id): 11 digits with structure + mod-11/10 check.
 * - NL BTW-id (``vat_id``): ``NL`` + 9 digits + ``B`` + 2 digits with optional
 *   spaces/dots (format only — post-2020 sole-trader ids are not elfproef-gated).
 * - NL passport / ID-card number (``passport``): 9-char RvIG document number
 *   (``[A-Za-z]{2}[0-9A-Za-z]{6}[0-9]``, letter O forbidden after uppercasing)
 *   — national identificatienummer alongside BSN; format only, no check digit.
 * - NL postcode (``address``): ``1234 AB`` / ``1234AB`` with uppercase letters
 *   only and SA/SD/SS rejects — structured fragment, not street-address NER.
 * - NL kenteken (``license_plate``): hyphenated RDW sidecodes 1–14 (case-
 *   insensitive), with SA/SD/SS letter-pair rejects.
 * - Phone packs: international (any active pack), NL national (allows ``/`` and
 *   parentheses; rejects hex-digest glue), NANP, DE national (DE excludes exact
 *   Dutch ``06…`` 10-digit mobiles; same hex-glue guard).
 * - BSN spaced/dotted/hyphenated ``111-222-333`` groups.
 *
 * ``UNIVERSAL_DETECTORS`` (email, IBAN, credit card, BIC, MAC, IMEI, IP, location)
 * always run; locale detectors are selected by ``languages=`` in the scrub layer.
 */

import { isIP } from "node:net";

export type PiiCategory =
  | "email"
  | "iban"
  | "credit_card"
  | "bic"
  | "mac"
  | "imei"
  | "ip"
  | "location"
  | "bsn"
  | "ssn"
  | "tax_id"
  | "vat_id"
  | "passport"
  | "phone"
  | "address"
  | "license_plate";

export interface Detector {
  readonly type: PiiCategory;
  scrub(text: string): { text: string; count: number };
}

function cloneRegExp(pattern: RegExp): RegExp {
  return new RegExp(pattern.source, pattern.flags);
}

function replaceMatches(
  text: string,
  pattern: RegExp,
  placeholder: string,
  isValid?: (value: string) => boolean,
): { text: string; count: number } {
  let count = 0;
  const re = cloneRegExp(pattern);
  const out = text.replace(re, (value) => {
    if (isValid !== undefined && !isValid(value)) {
      return value;
    }
    count += 1;
    return placeholder;
  });
  return { text: out, count };
}

const EMAIL_RE =
  /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}(?!@)/g;

const EMAIL_NEXT_PII_RE =
  /^(?:[A-Za-z]{2}\d{2}[A-Za-z0-9]|\d{13,19}|\d{3}[- ./]?\d{2}[- ./]?\d{4}|\d{3}[ .]\d{3}[ .]\d{3}|\d{8,9}(?!\d)|(?:\d{1,3}\.){3}\d{1,3}|\d{1,3}\.\d{3,8}|[0-9A-Fa-f]{2}([-:/.])[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{3,4}:|::)|[A-Za-z0-9._%+-]{1,64}@|[+0]\d)/;

function emailEndOk(text: string, end: number): boolean {
  if (end >= text.length) {
    return true;
  }
  const ch = text[end]!;
  if (ch === "@") {
    return false;
  }
  if (!/[A-Za-z0-9]/.test(ch)) {
    return true;
  }
  return EMAIL_NEXT_PII_RE.test(text.slice(end));
}

function emailShouldPeel(text: string, start: number, end: number): boolean {
  for (let tryEnd = end - 1; tryEnd > start; tryEnd -= 1) {
    if (!/[A-Za-z]/.test(text[tryEnd]!)) {
      break;
    }
    const cand = text.slice(start, tryEnd);
    const full = cloneRegExp(EMAIL_RE);
    full.lastIndex = 0;
    const m = full.exec(cand);
    if (m === null || m.index !== 0 || m[0].length !== cand.length) {
      continue;
    }
    if (EMAIL_NEXT_PII_RE.test(text.slice(tryEnd))) {
      return true;
    }
  }
  return false;
}

function scrubEmail(text: string): { text: string; count: number } {
  let count = 0;
  const parts: string[] = [];
  let last = 0;
  let pos = 0;
  const re = cloneRegExp(EMAIL_RE);
  re.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    let start = match.index;
    let end = start + match[0].length;
    if (!emailEndOk(text, end) || emailShouldPeel(text, start, end)) {
      let shortened: number | null = null;
      for (let tryEnd = end - 1; tryEnd > start; tryEnd -= 1) {
        const cand = text.slice(start, tryEnd);
        const full = cloneRegExp(EMAIL_RE);
        full.lastIndex = 0;
        const m = full.exec(cand);
        if (m === null || m.index !== 0 || m[0].length !== cand.length) {
          continue;
        }
        if (emailEndOk(text, tryEnd)) {
          shortened = tryEnd;
          break;
        }
      }
      if (shortened === null) {
        re.lastIndex = start + 1;
        continue;
      }
      end = shortened;
    }
    parts.push(text.slice(last, start));
    parts.push("[EMAIL]");
    last = end;
    count += 1;
    re.lastIndex = end;
  }
  if (count === 0) {
    return { text, count: 0 };
  }
  parts.push(text.slice(last));
  return { text: parts.join(""), count };
}

export const emailDetector: Detector = { type: "email", scrub: scrubEmail };

// Unicode Zs separators commonly used in OCR / rich text (thin/figure/nbsp…).
const SEP_SPACE = String.raw`[ \t\r\n\xa0\u2000-\u200a\u202f\u3000]`;
const INVISIBLE = /[\u00ad\u200b\u200c\u200d\ufeff]/g;

const IBAN_RES = [
  // Allow after digits (card|IBAN glue); still reject mid-letter (xNL91…).
  /(?<![A-Za-z])[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30}(?![A-Za-z0-9])/g,
  new RegExp(
    String.raw`\b[A-Z]{2}\d{2}(?:${SEP_SPACE}?[A-Z0-9]{1,4}){3,8}\b`,
    "g",
  ),
  new RegExp(
    String.raw`\b[a-z]{2}\d{2}(?:${SEP_SPACE}?[a-z0-9]{1,4}){3,8}\b`,
    "g",
  ),
  // Mixed case / hyphen|slash|dot|whitespace groups (one or more seps).
  new RegExp(
    String.raw`(?<![A-Za-z])[A-Za-z]{2}\d{2}(?:(?:${SEP_SPACE}|[\-/.])+[A-Za-z0-9]{1,4}){3,8}(?![A-Za-z0-9])`,
    "g",
  ),
  // Single hyphen after check digits, compact BBAN.
  /(?<![A-Za-z])[A-Za-z]{2}\d{2}-[A-Za-z0-9]{11,30}(?![A-Za-z0-9])/g,
] as const;

function ibanValid(value: string): boolean {
  const compact = value
    .replace(/[\s\-\u00ad\u200b\u200c\u200d\ufeff/.]+/g, "")
    .toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(compact)) {
    return false;
  }
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    if (ch >= "A") {
      remainder = (remainder * 100 + (ch.charCodeAt(0) - 55)) % 97;
    } else {
      remainder = (remainder * 10 + (ch.charCodeAt(0) - 48)) % 97;
    }
  }
  return remainder === 1;
}

function scrubIban(text: string): { text: string; count: number } {
  let out = text.replace(INVISIBLE, "");
  let count = 0;
  for (const pattern of IBAN_RES) {
    const result = replaceMatches(out, pattern, "[IBAN]", ibanValid);
    out = result.text;
    count += result.count;
  }
  return { text: out, count };
}

export const ibanDetector: Detector = { type: "iban", scrub: scrubIban };

// One or more whitespace / dash / punct separators between digit groups.
const CC_SEP = String.raw`(?:${SEP_SPACE}|[./\-\u2010-\u2015])+`;

const CREDIT_CARD_RES = [
  new RegExp(
    String.raw`(?<!\d)\d{4}${CC_SEP}\d{4}${CC_SEP}\d{4}${CC_SEP}\d{1,4}(?!\d)`,
    "g",
  ),
  new RegExp(
    String.raw`(?<!\d)\d{4}${CC_SEP}\d{6}${CC_SEP}\d{5}(?!\d)`,
    "g",
  ),
  // Digit/letter glue: \b does not split 1N.
  /(?<!\d)\d{13,19}(?!\d)/g,
] as const;

function luhnValid(digits: string): boolean {
  if (digits.length < 13 || digits.length > 19) {
    return false;
  }
  let total = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) {
        d -= 9;
      }
    }
    total += d;
    double = !double;
  }
  return total % 10 === 0;
}

function scrubCreditCard(text: string): { text: string; count: number } {
  let out = text.replace(INVISIBLE, "");
  let count = 0;
  for (const pattern of CREDIT_CARD_RES) {
    const result = replaceMatches(
      out,
      pattern,
      "[CREDIT_CARD]",
      (m) => luhnValid(m.replace(/\D/g, "")),
    );
    out = result.text;
    count += result.count;
  }
  return { text: out, count };
}

export const creditCardDetector: Detector = {
  type: "credit_card",
  scrub: scrubCreditCard,
};

const ISO_3166_1_ALPHA2 = new Set(
  `
    AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ
    BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR
    CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
    GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU
    ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ
    LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ
    MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF
    PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI
    SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR
    TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
    `.trim().split(/\s+/),
);

const BIC_RE = /\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g;

function bicValid(value: string): boolean {
  if (value.length !== 8 && value.length !== 11) {
    return false;
  }
  if (!/^[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?$/.test(value)) {
    return false;
  }
  return ISO_3166_1_ALPHA2.has(value.slice(4, 6));
}

function scrubBic(text: string): { text: string; count: number } {
  return replaceMatches(text, BIC_RE, "[BIC]", bicValid);
}

export const bicDetector: Detector = { type: "bic", scrub: scrubBic };

const MAC_RES = [
  /(?<![\w:])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:])/g,
  /(?<![\w.])(?:[0-9A-Fa-f]{2}\.){5}[0-9A-Fa-f]{2}(?![\w.])/g,
  /(?<![\w.])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![\w.])/g,
] as const;

function scrubMac(text: string): { text: string; count: number } {
  let out = text;
  let count = 0;
  for (const pattern of MAC_RES) {
    const result = replaceMatches(out, pattern, "[MAC]");
    out = result.text;
    count += result.count;
  }
  return { text: out, count };
}

export const macDetector: Detector = { type: "mac", scrub: scrubMac };

// Grouped only — compact 15-digit Luhn values collide with Amex credit cards.
const IMEI_RES = [
  /(?<![\w.-])\d{2}[- ./]\d{6}[- ./]\d{6}[- ./]\d(?![\w.-])/g,
  /(?<![\w.-])\d{8}[- ./]\d{6}[- ./]\d(?![\w.-])/g,
  /(?<![\w.-])\d{2}[- ./]\d{6}[- ./]\d{7}(?![\w.-])/g,
] as const;

function imeiValid(value: string): boolean {
  const digits = value.replace(/[ ./\-]/g, "");
  return digits.length === 15 && /^\d+$/.test(digits) && luhnValid(digits);
}

function scrubImei(text: string): { text: string; count: number } {
  let out = text;
  let count = 0;
  for (const pattern of IMEI_RES) {
    const result = replaceMatches(out, pattern, "[IMEI]", imeiValid);
    out = result.text;
    count += result.count;
  }
  return { text: out, count };
}

export const imeiDetector: Detector = { type: "imei", scrub: scrubImei };

const IPV4_RE =
  /(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\w.])/g;

// IPv6 with a trailing dotted quad (``::ffff:a.b.c.d``, NAT64 ``64:ff9b::a.b.c.d``).
const IPV6_V4_RE =
  /(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\w.])/g;

const IPV6_RE =
  /(?<![\w:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|::)(?![\w:])/g;

function normalizeIpv4Octets(value: string): string | null {
  const parts = value.split(".");
  if (
    parts.length !== 4 ||
    !parts.every((p) => /^\d{1,3}$/.test(p))
  ) {
    return null;
  }
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => n > 255)) {
    return null;
  }
  return nums.join(".");
}

function ipValid(value: string): boolean {
  if (isIP(value) !== 0) {
    return true;
  }
  const colon = value.lastIndexOf(":");
  if (colon !== -1) {
    const v4 = normalizeIpv4Octets(value.slice(colon + 1));
    return v4 !== null && isIP(`${value.slice(0, colon)}:${v4}`) !== 0;
  }
  return normalizeIpv4Octets(value) !== null;
}

function scrubIp(text: string): { text: string; count: number } {
  const mapped = replaceMatches(text, IPV6_V4_RE, "[IP]", ipValid);
  const v4 = replaceMatches(mapped.text, IPV4_RE, "[IP]", ipValid);
  const v6 = replaceMatches(v4.text, IPV6_RE, "[IP]", ipValid);
  return {
    text: v6.text,
    count: mapped.count + v4.count + v6.count,
  };
// IPv6-embedded dotted quads are consumed by IPV6_V4_RE first, so a label
// colon (``host:10.0.0.1``) may precede a bare IPv4.
}

export const ipDetector: Detector = { type: "ip", scrub: scrubIp };

const LOCATION_RE =
  /(?<![\d.+-])[-+]?\d{1,3}\.\d{3,8}°?(?:\s*[NnSs])?\s*,\s*[-+]?\d{1,3}\.\d{3,8}°?(?:\s*[EeWw])?(?![A-Za-z\d.])/g;

function coordComponent(part: string): number {
  return Number(part.replace(/[^\d.+-]/g, ""));
}

function locationValid(value: string): boolean {
  const parts = value.trim().split(/\s*,\s*/);
  if (parts.length !== 2) {
    return false;
  }
  const lat = coordComponent(parts[0]!);
  const lon = coordComponent(parts[1]!);
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
    return false;
  }
  return lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0;
}

function scrubLocation(text: string): { text: string; count: number } {
  return replaceMatches(text, LOCATION_RE, "[LOCATION]", locationValid);
}

export const locationDetector: Detector = {
  type: "location",
  scrub: scrubLocation,
};

const BSN_RES = [/\b\d{8,9}\b/g, /\b\d{3}[ .\-]\d{3}[ .\-]\d{3}\b/g] as const;

function bsnValid(value: string): boolean {
  const digits = value.replace(/[ .\-]/g, "");
  if (digits.length < 8 || digits.length > 9 || !/^\d+$/.test(digits)) {
    return false;
  }
  const padded = digits.padStart(9, "0");
  if (padded === "000000000") {
    return false;
  }
  const weights = [9, 8, 7, 6, 5, 4, 3, 2, -1] as const;
  let total = 0;
  for (let i = 0; i < 9; i += 1) {
    total += (padded.charCodeAt(i) - 48) * weights[i]!;
  }
  return total % 11 === 0;
}

function scrubBsn(text: string): { text: string; count: number } {
  let out = text;
  let count = 0;
  for (const pattern of BSN_RES) {
    const result = replaceMatches(out, pattern, "[BSN]", bsnValid);
    out = result.text;
    count += result.count;
  }
  return { text: out, count };
}

export const bsnDetector: Detector = { type: "bsn", scrub: scrubBsn };

const SSN_RES = [
  /\b\d{3}-\d{2}-\d{4}\b/g,
  /\b\d{3}\/\d{2}\/\d{4}\b/g,
  /\b\d{3}[ .]\d{2}[ .]\d{4}\b/g,
  /\b\d{9}\b/g,
] as const;

function ssnObviouslyFake(digits: string): boolean {
  if (new Set(digits).size === 1) {
    return true;
  }
  return digits === "123456789" || digits === "987654321";
}

function ssnValid(value: string): boolean {
  const digits = value.replace(/[ .\-/]/g, "");
  if (digits.length !== 9 || !/^\d{9}$/.test(digits)) {
    return false;
  }
  if (ssnObviouslyFake(digits)) {
    return false;
  }
  const area = Number(digits.slice(0, 3));
  const group = Number(digits.slice(3, 5));
  const serial = Number(digits.slice(5));
  if (area === 0 || area === 666 || area >= 900) {
    return false;
  }
  if (group === 0 || serial === 0) {
    return false;
  }
  return true;
}

function scrubSsn(text: string): { text: string; count: number } {
  let out = text;
  let count = 0;
  for (const pattern of SSN_RES) {
    const result = replaceMatches(out, pattern, "[SSN]", ssnValid);
    out = result.text;
    count += result.count;
  }
  return { text: out, count };
}

export const ssnDetector: Detector = { type: "ssn", scrub: scrubSsn };

const TAX_ID_RE = /\b\d{11}\b/g;

function taxIdValid(digits: string): boolean {
  if (digits.length !== 11 || !/^\d{11}$/.test(digits)) {
    return false;
  }
  if (digits[0] === "0") {
    return false;
  }
  const body = digits.slice(0, 10);
  const counts = new Map<string, number>();
  for (const ch of body) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  const repeats = [...counts.values()].filter((n) => n > 1);
  if (repeats.length !== 1 || (repeats[0] !== 2 && repeats[0] !== 3)) {
    return false;
  }
  let product = 10;
  for (const ch of body) {
    let total = ((ch.charCodeAt(0) - 48 + product) % 10);
    if (total === 0) {
      total = 10;
    }
    product = (2 * total) % 11;
  }
  let check = 11 - product;
  if (check === 10) {
    check = 0;
  }
  return check === digits.charCodeAt(10) - 48;
}

function scrubTaxId(text: string): { text: string; count: number } {
  return replaceMatches(text, TAX_ID_RE, "[TAX_ID]", taxIdValid);
}

export const taxIdDetector: Detector = { type: "tax_id", scrub: scrubTaxId };

const NL_VAT_RE = /\b[Nn][Ll][.\s]*\d{9}[.\s]*[Bb][.\s]*\d{2}\b/g;

function scrubNlVat(text: string): { text: string; count: number } {
  return replaceMatches(text, NL_VAT_RE, "[VAT_ID]");
}

export const nlVatDetector: Detector = { type: "vat_id", scrub: scrubNlVat };

const NL_PASSPORT_RE = /\b[A-Za-z]{2}[0-9A-Za-z]{6}\d\b/g;

function nlPassportValid(value: string): boolean {
  const compact = value.toUpperCase();
  if (compact.length !== 9) {
    return false;
  }
  if (!/^[A-Z]{2}[0-9A-Z]{6}\d$/.test(compact)) {
    return false;
  }
  return !compact.includes("O");
}

function scrubNlPassport(text: string): { text: string; count: number } {
  return replaceMatches(text, NL_PASSPORT_RE, "[PASSPORT]", nlPassportValid);
}

export const nlPassportDetector: Detector = {
  type: "passport",
  scrub: scrubNlPassport,
};

function digitCount(text: string): number {
  let count = 0;
  for (const ch of text) {
    if (ch >= "0" && ch <= "9") {
      count += 1;
    }
  }
  return count;
}

const PHONE_INTERNATIONAL: readonly [RegExp, (value: string) => boolean] = [
  /(?<![\w+])(?:\+|00)\d[\d .()-]{6,16}\d/g,
  (m) => digitCount(m) >= 8 && digitCount(m) <= 15,
];

const PHONE_NL_NATIONAL: readonly [RegExp, (value: string) => boolean] = [
  /(?<![\w+])\(?0\d\)?(?:[ .\-/()]?\d){8}(?!\d)(?![A-Fa-f]{2})/g,
  (m) => digitCount(m) === 10,
];

const PHONE_EN_NANP: readonly [RegExp, (value: string) => boolean] = [
  /(?<![\w+])(?:1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]\d{4}(?!\d)/g,
  (m) => {
    const digits = digitCount(m);
    return (
      digits === 10 || (digits === 11 && m.replace(/\D/g, "").startsWith("1"))
    );
  },
];

const PHONE_DE_NATIONAL: readonly [RegExp, (value: string) => boolean] = [
  /(?<![\w+])\(?0\d\)?(?:[ .\-/()]?\d){8,10}(?!\d)(?![A-Fa-f]{2})/g,
  (m) => {
    const digits = digitCount(m);
    if (digits < 10 || digits > 12) {
      return false;
    }
    if (digits === 10 && m.replace(/\D/g, "").startsWith("06")) {
      return false;
    }
    // Separator-free 12-digit runs collide with UPC-A barcodes.
    if (digits === 12 && /^\d{12}$/.test(m)) {
      return false;
    }
    return true;
  },
];

function makePhoneDetector(
  patterns: readonly (readonly [RegExp, (value: string) => boolean])[],
): Detector {
  return {
    type: "phone",
    scrub(text: string): { text: string; count: number } {
      let out = text;
      let count = 0;
      for (const [pattern, valid] of patterns) {
        const result = replaceMatches(out, pattern, "[PHONE]", valid);
        out = result.text;
        count += result.count;
      }
      return { text: out, count };
    },
  };
}

export const phoneInternationalDetector = makePhoneDetector([PHONE_INTERNATIONAL]);
export const phoneNlDetector = makePhoneDetector([PHONE_NL_NATIONAL]);
export const phoneEnDetector = makePhoneDetector([PHONE_EN_NANP]);
export const phoneDeDetector = makePhoneDetector([PHONE_DE_NATIONAL]);

const NL_POSTCODE_RE = /\b[1-9]\d{3}\s+[A-Z]{2}\b|\b[1-9]\d{3}[A-Z]{2}\b/g;
const NL_POSTCODE_LETTER_REJECTS = new Set(["SA", "SD", "SS"]);

function nlPostcodeValid(value: string): boolean {
  const compact = value.replace(/\s+/g, "").toUpperCase();
  if (!/^[1-9]\d{3}[A-Z]{2}$/.test(compact)) {
    return false;
  }
  return !NL_POSTCODE_LETTER_REJECTS.has(compact.slice(4));
}

function scrubNlPostcode(text: string): { text: string; count: number } {
  return replaceMatches(text, NL_POSTCODE_RE, "[ADDRESS]", nlPostcodeValid);
}

export const nlPostcodeDetector: Detector = {
  type: "address",
  scrub: scrubNlPostcode,
};

const NL_LICENSE_PLATE_RE =
  /(?<![\w-])(?:[A-Z]{2}-\d{2}-\d{2}|\d{2}-\d{2}-[A-Z]{2}|\d{2}-[A-Z]{2}-\d{2}|[A-Z]{2}-\d{2}-[A-Z]{2}|[A-Z]{2}-[A-Z]{2}-\d{2}|\d{2}-[A-Z]{2}-[A-Z]{2}|\d{2}-[A-Z]{3}-\d|\d-[A-Z]{3}-\d{2}|[A-Z]{2}-\d{3}-[A-Z]|[A-Z]-\d{3}-[A-Z]{2}|[A-Z]{3}-\d{2}-[A-Z]|[A-Z]-\d{2}-[A-Z]{3}|\d-[A-Z]{2}-\d{3}|\d{3}-[A-Z]{2}-\d)(?![\w-])/gi;

const NL_PLATE_LETTER_REJECTS = new Set(["SA", "SD", "SS"]);

function nlLicensePlateValid(value: string): boolean {
  const letters = [...value.toUpperCase()].filter((ch) => ch >= "A" && ch <= "Z").join("");
  for (let i = 0; i < letters.length - 1; i += 1) {
    if (NL_PLATE_LETTER_REJECTS.has(letters.slice(i, i + 2))) {
      return false;
    }
  }
  return true;
}

function scrubNlLicensePlate(text: string): { text: string; count: number } {
  return replaceMatches(
    text,
    NL_LICENSE_PLATE_RE,
    "[LICENSE_PLATE]",
    nlLicensePlateValid,
  );
}

export const nlLicensePlateDetector: Detector = {
  type: "license_plate",
  scrub: scrubNlLicensePlate,
};

export const UNIVERSAL_DETECTORS: readonly Detector[] = [
  emailDetector,
  ibanDetector,
  creditCardDetector,
  bicDetector,
  macDetector,
  imeiDetector,
  ipDetector,
  locationDetector,
];

/**
 * Pattern detectors: regex + checksum where one exists.
 *
 * Ported from foro-sh/platform ``infra/templates/foro-pii.mts``. Detector order
 * matters — earlier matches become digit-free placeholders before looser
 * numeric detectors run.
 *
 * Patterns:
 * - Email uses bounded quantifiers (unbounded local-part ``+`` is ReDoS-prone).
 * - Spaced IBANs use separate upper- and lower-case patterns so a trailing word
 *   is not swallowed by a mixed-case class.
 * - Credit cards include Amex 4-6-5 groupings as well as 4-4-4-x and compact.
 * - BIC/SWIFT: 8 or 11 alnum with ISO 3166-1 country letters (AP: financial data).
 * - MAC: colon/dash IEEE and Cisco dotted forms (AP: device MAC is personal data).
 * - IP: IPv4 octet-bounded regex; IPv6 candidate shapes validated via
 *   ``node:net`` ``isIP`` (AP notes IP addresses can be personal data).
 * - Location: decimal lat/lon pairs with ≥3 fractional digits and range checks
 *   (AP lists locatiegegevens as privacy-sensitive).
 * - US SSN: hyphenated or compact 9-digit with SSA area/group/serial rejects.
 * - German Steuer-IdNr (tax_id): 11 digits with structure + mod-11/10 check.
 * - NL BTW-id (``vat_id``): ``NL`` + 9 digits + ``B`` + 2 digits (format only —
 *   post-2020 sole-trader ids are not elfproef-gated).
 * - NL postcode (``address``): ``1234 AB`` / ``1234AB`` with uppercase letters
 *   only and SA/SD/SS rejects — structured fragment, not street-address NER.
 * - NL kenteken (``license_plate``): hyphenated RDW sidecodes 1–14, uppercase,
 *   with SA/SD/SS letter-pair rejects.
 * - Phone packs: international (any active pack), NL national, NANP, DE national
 *   (DE excludes exact Dutch ``06…`` 10-digit mobiles).
 *
 * ``UNIVERSAL_DETECTORS`` (email, IBAN, credit card, BIC, MAC, IP, location)
 * always run; locale detectors are selected by ``languages=`` in the scrub layer.
 */

import { isIP } from "node:net";

export type PiiCategory =
  | "email"
  | "iban"
  | "credit_card"
  | "bic"
  | "mac"
  | "ip"
  | "location"
  | "bsn"
  | "ssn"
  | "tax_id"
  | "vat_id"
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

const EMAIL_RE = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}\b/g;

function scrubEmail(text: string): { text: string; count: number } {
  return replaceMatches(text, EMAIL_RE, "[EMAIL]");
}

export const emailDetector: Detector = { type: "email", scrub: scrubEmail };

const IBAN_RES = [
  /\b[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30}\b/g,
  /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{1,4}){3,8}\b/g,
  /\b[a-z]{2}\d{2}(?:[ ]?[a-z0-9]{1,4}){3,8}\b/g,
] as const;

function ibanValid(value: string): boolean {
  const compact = value.replace(/\s+/g, "").toUpperCase();
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
  let out = text;
  let count = 0;
  for (const pattern of IBAN_RES) {
    const result = replaceMatches(out, pattern, "[IBAN]", ibanValid);
    out = result.text;
    count += result.count;
  }
  return { text: out, count };
}

export const ibanDetector: Detector = { type: "iban", scrub: scrubIban };

const CREDIT_CARD_RES = [
  /\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4}\b/g,
  /\b\d{4}[ -]\d{6}[ -]\d{5}\b/g,
  /\b\d{13,19}\b/g,
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
  let out = text;
  let count = 0;
  for (const pattern of CREDIT_CARD_RES) {
    const result = replaceMatches(
      out,
      pattern,
      "[CREDIT_CARD]",
      (m) => luhnValid(m.replace(/[ -]/g, "")),
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

const IPV4_RE =
  /(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\w.])/g;

const IPV6_RE =
  /(?<![\w:])(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|::)(?![\w:])/g;

function ipValid(value: string): boolean {
  return isIP(value) !== 0;
}

function scrubIp(text: string): { text: string; count: number } {
  const v4 = replaceMatches(text, IPV4_RE, "[IP]", ipValid);
  const v6 = replaceMatches(v4.text, IPV6_RE, "[IP]", ipValid);
  return { text: v6.text, count: v4.count + v6.count };
}

export const ipDetector: Detector = { type: "ip", scrub: scrubIp };

const LOCATION_RE =
  /(?<![\d.+-])[-+]?\d{1,3}\.\d{3,8}\s*,\s*[-+]?\d{1,3}\.\d{3,8}(?![\d.])/g;

function locationValid(value: string): boolean {
  const parts = value.trim().split(/\s*,\s*/);
  if (parts.length !== 2) {
    return false;
  }
  const lat = Number(parts[0]);
  const lon = Number(parts[1]);
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

const BSN_RE = /\b\d{8,9}\b/g;

function bsnValid(digits: string): boolean {
  if (digits.length < 8 || digits.length > 9) {
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
  return replaceMatches(text, BSN_RE, "[BSN]", bsnValid);
}

export const bsnDetector: Detector = { type: "bsn", scrub: scrubBsn };

const SSN_RES = [/\b\d{3}-\d{2}-\d{4}\b/g, /\b\d{9}\b/g] as const;

function ssnValid(value: string): boolean {
  const digits = value.replace(/-/g, "");
  if (digits.length !== 9 || !/^\d{9}$/.test(digits)) {
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

const NL_VAT_RE = /\b[Nn][Ll]\d{9}[Bb]\d{2}\b/g;

function scrubNlVat(text: string): { text: string; count: number } {
  return replaceMatches(text, NL_VAT_RE, "[VAT_ID]");
}

export const nlVatDetector: Detector = { type: "vat_id", scrub: scrubNlVat };

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
  /(?<![\w+])0\d(?:[ .-]?\d){8}(?!\d)/g,
  (m) => digitCount(m) === 10,
];

const PHONE_EN_NANP: readonly [RegExp, (value: string) => boolean] = [
  /(?<![\w+])\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)/g,
  (m) => digitCount(m) === 10,
];

const PHONE_DE_NATIONAL: readonly [RegExp, (value: string) => boolean] = [
  /(?<![\w+])0\d(?:[ .-]?\d){8,10}(?!\d)/g,
  (m) => {
    const digits = digitCount(m);
    return (
      digits >= 10 &&
      digits <= 12 &&
      !(digits === 10 && m.replace(/\D/g, "").startsWith("06"))
    );
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

const NL_POSTCODE_RE = /\b[1-9]\d{3}\s?[A-Z]{2}\b/g;
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
  /(?<![\w-])(?:[A-Z]{2}-\d{2}-\d{2}|\d{2}-\d{2}-[A-Z]{2}|\d{2}-[A-Z]{2}-\d{2}|[A-Z]{2}-\d{2}-[A-Z]{2}|[A-Z]{2}-[A-Z]{2}-\d{2}|\d{2}-[A-Z]{2}-[A-Z]{2}|\d{2}-[A-Z]{3}-\d|\d-[A-Z]{3}-\d{2}|[A-Z]{2}-\d{3}-[A-Z]|[A-Z]-\d{3}-[A-Z]{2}|[A-Z]{3}-\d{2}-[A-Z]|[A-Z]-\d{2}-[A-Z]{3}|\d-[A-Z]{2}-\d{3}|\d{3}-[A-Z]{2}-\d)(?![\w-])/g;

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
  ipDetector,
  locationDetector,
];

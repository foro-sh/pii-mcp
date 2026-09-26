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
 *   Local part, domain labels, and TLD accept Unicode letters (EAI / IDN).
 *   When a TLD absorbs a following IBAN/card/IP/MAC/location, the match is
 *   shortened so both hits still redact.
 * - Spaced IBANs use separate upper- and lower-case optional-space patterns so a
 *   trailing word is not swallowed by a mixed-case class. Further patterns allow
 *   mixed case and hyphen/tab/nbsp/slash separators, plus a single hyphen after
 *   check digits. Soft hyphens and zero-width characters are stripped before
 *   IBAN matching.
 * - Credit cards include 4-4-4-4-x (17–19 digits), Amex 4-6-5, Diners 4-6-4
 *   groupings as well as 4-4-4-x and compact; Luhn plus an issuer-prefix gate
 *   (2–6, or 15 digits) keeps ms timestamps / ISBN-13s from matching;
 *   grouped forms also accept tab, nbsp, ideographic space, unicode dashes,
 *   ``.``, and ``/``; zero-width characters are stripped before matching.
 * - BIC/SWIFT: 8 or 11 alnum with ISO 3166-1 country letters (AP: financial data).
 * - MAC: colon/dash IEEE, Cisco dotted, and Huawei/H3C ``aabb-ccdd-eeff`` (with a
 *   hex letter) forms (AP: device MAC is personal data).
 *   A label colon (``mac:aa:bb:…``) is allowed; a preceding hex group is not.
 * - IMEI: hyphen/space-grouped 15-digit forms with Luhn (AP: gegevens over
 *   elektronische communicatie / device identifiers). Compact 15-digit IMEIs
 *   that are also Luhn-valid collide with Amex and stay under ``credit_card``.
 * - IP: IPv6 with an embedded dotted quad (``::ffff:a.b.c.d``, NAT64
 *   ``64:ff9b::a.b.c.d``) is matched whole before bare IPv4, so bare IPv4 may
 *   follow a label colon (``host:10.0.0.1``); leading zeros in octets are
 *   accepted (``192.168.001.001``).
 * - Location: decimal lat/lon pairs with ≥3 fractional digits, optional
 *   ``N``/``S``/``E``/``W`` hemisphere letters, and range checks (AP lists
 *   locatiegegevens as privacy-sensitive). Pairs with both |values| <= 1 are
 *   rejected (open ocean; embedding / weight vectors). Degrees-minutes(-seconds)
 *   pairs need a degree sign, minute mark, and hemisphere letter per half.
 * - US SSN: hyphen/space/dot/slash or compact 9-digit with SSA area/group/serial
 *   rejects, plus obvious fakes (all-same digit, 123456789 / 987654321). Grouped
 *   SSN / BSN forms also accept nbsp, thin / narrow nbsp, and unicode dashes.
 * - German Steuer-IdNr (tax_id): 11 digits, compact or grouped ``12 345 678 901``,
 *   with structure + mod-11/10 check.
 * - NL BTW-id (``vat_id``): ``NL`` + 9 digits + ``B`` + 2 digits with optional
 *   spaces/dots (format only — post-2020 sole-trader ids are not elfproef-gated).
 * - NL passport / ID-card number (``passport``): 9-char RvIG document number
 *   (``[A-Za-z]{2}[0-9A-Za-z]{6}[0-9]``, letter O forbidden after uppercasing)
 *   — national identificatienummer alongside BSN; format only, no check digit.
 * - NL postcode (``address``): ``1234 AB`` / ``1234AB`` with uppercase letters
 *   only and SA/SD/SS rejects — structured fragment, not street-address NER.
 * - NL kenteken (``license_plate``): hyphenated RDW sidecodes 1–14 (case-
 *   insensitive), with SA/SD/SS letter-pair rejects.
 * - Phone packs: international (any active pack; a ``(0)`` trunk may sit
 *   between groups and a run past 15 digits is cut back to the last whole
 *   group), NL national (allows ``/`` and parentheses; rejects hex-digest glue),
 *   NANP, DE national (DE excludes exact Dutch ``06…`` 10-digit mobiles; same
 *   hex-glue guard). All phone forms also accept nbsp, thin / narrow nbsp, and
 *   unicode dashes between groups.
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
  retry = false,
  acceptEnd?: (text: string, start: number, end: number) => number,
): { text: string; count: number } {
  let count = 0;
  const re = cloneRegExp(pattern);
  if (acceptEnd !== undefined) {
    // ``acceptEnd`` returns where the replacement ends (``start`` rejects),
    // like Python ``accept_end`` / Rust ``replace_matches_end``: a grouped hit
    // that swallowed a trailing word is cut back to the part that validates,
    // or a hit is re-measured against the text (and may end past the match).
    let out = "";
    let last = 0;
    for (let m = re.exec(text); m !== null; m = re.exec(text)) {
      const end = acceptEnd(text, m.index, m.index + m[0].length);
      if (end === m.index) {
        if (retry || m[0].length === 0) {
          re.lastIndex = m.index + 1;
        }
        continue;
      }
      out += text.slice(last, m.index) + placeholder;
      last = end;
      re.lastIndex = last;
      count += 1;
    }
    return { text: out + text.slice(last), count };
  }
  if (retry && isValid !== undefined) {
    // Resume a rejected match at start + 1 so an overlapping bogus candidate
    // (``2024 4111 1111 1111`` failing Luhn) does not swallow the real hit.
    let out = "";
    let last = 0;
    for (let m = re.exec(text); m !== null; m = re.exec(text)) {
      if (!isValid(m[0])) {
        re.lastIndex = m.index + 1;
        continue;
      }
      out += text.slice(last, m.index) + placeholder;
      last = re.lastIndex;
      count += 1;
    }
    return { text: out + text.slice(last), count };
  }
  const out = text.replace(re, (value) => {
    if (isValid !== undefined && !isValid(value)) {
      return value;
    }
    count += 1;
    return placeholder;
  });
  return { text: out, count };
}

// Scripts written without spaces (Thai, Lao, Tibetan, Myanmar, Khmer, kana,
// Bopomofo, CJK, Hangul, fullwidth forms) glue prose straight onto an
// address (``请发送至ada@example.com以便``), so a TLD is either all such
// script or free of it, and one such letter after the TLD ends the address.
// The local part may mix scripts (``田中123@``): glued prose before it is
// over-masked rather than a name part leaked.
const UNSPACED_SCRIPTS = String.raw`\u0e00-\u0eff\u0f00-\u0fff\u1000-\u109f\u1100-\u11ff\u1780-\u17ff\u3000-\u31ff\u3400-\u4dbf\u4e00-\u9fff\ua960-\ua97f\uac00-\ud7ff\uf900-\ufaff\uff00-\uffef\u{20000}-\u{3ffff}`;
const UNSPACED_CHAR_RE = new RegExp(`[${UNSPACED_SCRIPTS}]`, "u");
const EMAIL_LOCAL = String.raw`[\p{L}\p{N}_.%+\-]{1,64}`;
const EMAIL_TLD = String.raw`(?:(?:(?![${UNSPACED_SCRIPTS}])\p{L}){2,24}|(?:(?=[${UNSPACED_SCRIPTS}])\p{L}){2,24})`;

// Letters and digits are Unicode (EAI / IDN: ``josé@example.com``,
// ``ada@münchen.de``), matching Python's ``\w`` / ``[^\W_]``.
const EMAIL_RE = new RegExp(
  String.raw`${EMAIL_LOCAL}@[\p{L}\p{N}\-]{1,63}(?:\.[\p{L}\p{N}\-]{1,63})*\.${EMAIL_TLD}(?!@)`,
  "gu",
);

const EMAIL_NEXT_PII_RE = new RegExp(
  String.raw`^(?:[A-Za-z]{2}\d{2}[A-Za-z0-9]|\d{13,19}|\d{3}[- ./]?\d{2}[- ./]?\d{4}|\d{3}[ .]\d{3}[ .]\d{3}|\d{8,9}(?!\d)|(?:\d{1,3}\.){3}\d{1,3}|\d{1,3}\.\d{3,8}|[0-9A-Fa-f]{2}([-:/.])[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{3,4}:|::)|${EMAIL_LOCAL}@|[+0]\d)`,
  "u",
);

function emailEndOk(text: string, end: number): boolean {
  if (end >= text.length) {
    return true;
  }
  const ch = text[end]!;
  if (ch === "@") {
    return false;
  }
  if (!/[\p{L}\p{N}]/u.test(ch) || UNSPACED_CHAR_RE.test(ch)) {
    return true;
  }
  return EMAIL_NEXT_PII_RE.test(text.slice(end));
}

function emailShouldPeel(text: string, start: number, end: number): boolean {
  for (let tryEnd = end - 1; tryEnd > start; tryEnd -= 1) {
    if (!/\p{L}/u.test(text[tryEnd]!)) {
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

const EMAIL_DOMAIN_RUN_RE = /[\p{L}\p{N}.\-]*/uy;

/**
 * Leftmost ``EMAIL_RE`` match at or after ``pos``. Unicode letter classes make
 * every word of non-Latin prose a local-part candidate, so the regex runs only
 * on a window around each ``@``: 64 code points back (the local-part bound)
 * and forward over the domain run plus one char for ``(?!@)``. A match for one
 * ``@`` always starts before any match for the next (local parts exclude
 * ``@``), so taking the ``@``s in order keeps the whole-text result.
 */
function findEmail(text: string, pos: number): [number, number] | null {
  const re = cloneRegExp(EMAIL_RE);
  let dot = -1;
  for (let at = text.indexOf("@", pos); at !== -1; at = text.indexOf("@", at + 1)) {
    let winStart = at;
    for (let n = 0; n < 64 && winStart > pos; n += 1) {
      winStart -= 1;
      const unit = text.charCodeAt(winStart);
      if (unit >= 0xdc00 && unit <= 0xdfff && winStart > pos) {
        winStart -= 1;
      }
    }
    EMAIL_DOMAIN_RUN_RE.lastIndex = at + 1;
    EMAIL_DOMAIN_RUN_RE.exec(text);
    const runEnd = EMAIL_DOMAIN_RUN_RE.lastIndex;
    // No dot in the domain run: no TLD, so no address at this ``@``. The next
    // dot is cached so dot-free text with many ``@`` stays linear.
    if (dot !== Infinity && dot <= at) {
      dot = text.indexOf(".", at + 1);
      if (dot === -1) {
        dot = Infinity;
      }
    }
    if (dot >= runEnd) {
      continue;
    }
    const winEnd = Math.min(text.length, runEnd + 1);
    re.lastIndex = 0;
    const m = re.exec(text.slice(winStart, winEnd));
    if (m !== null) {
      return [winStart + m.index, winStart + m.index + m[0].length];
    }
  }
  return null;
}

function scrubEmail(text: string): { text: string; count: number } {
  let count = 0;
  const parts: string[] = [];
  let last = 0;
  let pos = 0;
  let found: [number, number] | null;
  while ((found = findEmail(text, pos)) !== null) {
    const start = found[0];
    let end = found[1];
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
        pos = start + 1;
        continue;
      }
      end = shortened;
    }
    parts.push(text.slice(last, start));
    parts.push("[EMAIL]");
    last = end;
    pos = end;
    count += 1;
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
// Group separators word processors / PDFs substitute for a typed space or
// hyphen in ids and phone numbers: nbsp, thin / narrow nbsp, unicode dashes
// and the minus sign. Character-class fragments, shared by both.
const GROUP_SPACES = String.raw`\xa0\u2009\u202f`;
const GROUP_DASHES = String.raw`\u2010-\u2015\u2212`;

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

// SWIFT IBAN registry: country code -> fixed IBAN length.
const IBAN_LENGTHS = new Map(
  `
    AD:24 AE:23 AL:28 AT:20 AZ:28 BA:20 BE:16 BG:22 BH:22 BI:27 BR:29 BY:28
    CH:21 CR:22 CY:28 CZ:24 DE:22 DJ:27 DK:18 DO:28 EE:20 EG:29 ES:24 FI:18
    FK:18 FO:18 FR:27 GB:22 GE:22 GI:23 GL:18 GR:27 GT:28 HN:28 HR:21 HU:28
    IE:22 IL:23 IQ:23 IS:26 IT:27 JO:30 KW:30 KZ:20 LB:28 LC:32 LI:21 LT:20
    LU:20 LV:21 LY:25 MC:27 MD:24 ME:22 MK:19 MN:20 MR:27 MT:31 MU:30 NI:28
    NL:18 NO:15 OM:23 PK:24 PL:28 PS:29 PT:25 QA:29 RO:24 RS:22 RU:33 SA:24
    SC:31 SD:18 SE:24 SI:19 SK:24 SM:27 SO:23 ST:25 SV:28 TL:23 TN:24 TR:26
    UA:29 VA:22 VG:24 XK:20 YE:30
  `
    .trim()
    .split(/\s+/)
    .map((item) => {
      const [cc, n] = item.split(":");
      return [cc!, Number(n)] as const;
    }),
);

/**
 * Mod-97 plus the registry length for the country, so a hex digest slice
 * (``ab531c3778d535f0a16019``) is not an IBAN one time in 97.
 */
function ibanValid(value: string): boolean {
  const compact = value
    .replace(/[\s\-\u00ad\u200b\u200c\u200d\ufeff/.]+/g, "")
    .toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(compact)) {
    return false;
  }
  if (IBAN_LENGTHS.get(compact.slice(0, 2)) !== compact.length) {
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

const IBAN_GROUP_SEP_RE = new RegExp(String.raw`(?:${SEP_SPACE}|[\-/.])+`, "g");

/**
 * Length of the longest prefix, cut at a group separator, that passes mod-97
 * (``GB82-BIWD-…-25 role`` / ``…6894\nend`` swallowed a word).
 */
function ibanAcceptLen(value: string): number {
  if (ibanValid(value)) {
    return value.length;
  }
  const cuts = [...value.matchAll(IBAN_GROUP_SEP_RE)].map((m) => m.index);
  for (let i = cuts.length - 1; i >= 0; i -= 1) {
    if (ibanValid(value.slice(0, cuts[i]))) {
      return cuts[i]!;
    }
  }
  return 0;
}

function scrubIban(text: string): { text: string; count: number } {
  let out = text.replace(INVISIBLE, "");
  let count = 0;
  for (const pattern of IBAN_RES) {
    const result = replaceMatches(
      out,
      pattern,
      "[IBAN]",
      undefined,
      false,
      (full, start, end) => start + ibanAcceptLen(full.slice(start, end)),
    );
    out = result.text;
    count += result.count;
  }
  return { text: out, count };
}

export const ibanDetector: Detector = { type: "iban", scrub: scrubIban };

// One or more whitespace / dash / punct separators between digit groups.
const CC_SEP = String.raw`(?:${SEP_SPACE}|[./\-\u2010-\u2015])+`;

const CREDIT_CARD_RES = [
  // 17–19 digit PANs (UnionPay, Maestro, Visa) group as 4-4-4-4-x.
  new RegExp(
    String.raw`(?<!\d)\d{4}${CC_SEP}\d{4}${CC_SEP}\d{4}${CC_SEP}\d{4}${CC_SEP}\d{1,3}(?!\d)`,
    "g",
  ),
  new RegExp(
    String.raw`(?<!\d)\d{4}${CC_SEP}\d{4}${CC_SEP}\d{4}${CC_SEP}\d{1,4}(?!\d)`,
    "g",
  ),
  new RegExp(
    String.raw`(?<!\d)\d{4}${CC_SEP}\d{6}${CC_SEP}\d{5}(?!\d)`,
    "g",
  ),
  // Diners Club 14-digit 4-6-4.
  new RegExp(
    String.raw`(?<!\d)\d{4}${CC_SEP}\d{6}${CC_SEP}\d{4}(?!\d)`,
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

/**
 * Luhn plus issuer prefix: payment PANs start 2–6; RuPay 81/82 and Troy 9792
 * are 16-digit exceptions; 15 digits stay open for UATP and compact IMEIs.
 * 13-digit PANs were only ever issued by Visa (4), so other 13-digit runs are
 * EANs; 17–19 digits need an issuer of long PANs.
 */
function cardValid(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length === 13 && !digits.startsWith("4")) {
    return false;
  }
  // Visa, Maestro, Discover/UnionPay (6), JCB 35 and Mir 2200–2204 issue
  // long PANs; 2/3-led snowflake ids are not cards.
  if (digits.length >= 17 && !/^(?:[456]|35|220[0-4])/.test(digits)) {
    return false;
  }
  const prefixOk =
    /^[2-6]/.test(digits) ||
    digits.length === 15 ||
    (digits.length === 16 && /^(?:81|82|9792)/.test(digits));
  return prefixOk && luhnValid(digits);
}

function scrubCreditCard(text: string): { text: string; count: number } {
  let out = text.replace(INVISIBLE, "");
  let count = 0;
  for (const pattern of CREDIT_CARD_RES) {
    const result = replaceMatches(
      out,
      pattern,
      "[CREDIT_CARD]",
      cardValid,
      true,
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

// A label colon (``mac:aa:bb:…``) is allowed; a preceding empty or 1–4 digit
// hex group means the hit is a slice of a longer colon-hex run.
const MAC_RES = [
  /(?<!\w)(?<!(?<!\w)[0-9A-Fa-f]{0,4}:)(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:])/g,
  /(?<![\w.])(?:[0-9A-Fa-f]{2}\.){5}[0-9A-Fa-f]{2}(?![\w.])/g,
  /(?<![\w.])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![\w.])/g,
] as const;

// Huawei / H3C ``aabb-ccdd-eeff``; ``macDashValid`` needs a hex letter.
const MAC_DASH_RE = /(?<![\w.-])(?:[0-9A-Fa-f]{4}-){2}[0-9A-Fa-f]{4}(?![\w.-])/g;

/** A 4-4-4 dash run of digits only is a part / order number, not a MAC. */
function macDashValid(value: string): boolean {
  return /[A-Fa-f]/.test(value);
}

function scrubMac(text: string): { text: string; count: number } {
  let out = text;
  let count = 0;
  for (const pattern of MAC_RES) {
    const result = replaceMatches(out, pattern, "[MAC]");
    out = result.text;
    count += result.count;
  }
  const dash = replaceMatches(out, MAC_DASH_RE, "[MAC]", macDashValid);
  return { text: dash.text, count: count + dash.count };
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

// IPv6-embedded dotted quads are consumed by IPV6_V4_RE first, so a label
// colon (``host:10.0.0.1``) may precede a bare IPv4.
const IPV4_RE =
  /(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\w.])/g;

// IPv6 with a trailing dotted quad (``::ffff:a.b.c.d``, NAT64 ``64:ff9b::a.b.c.d``).
// A label colon (``user:64:ff9b::…``) is allowed; a preceding empty or 1–4
// digit hex group means the hit is a slice of a longer colon-hex run.
const IPV6_V4_RE =
  /(?<![\w.])(?<!(?<!\w)[0-9A-Fa-f]{0,4}:)(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\w.])/g;

// Same label-colon rule as MAC (``user:2001:db8::1``).
const IPV6_RE =
  /(?<!\w)(?<!(?<!\w)[0-9A-Fa-f]{0,4}:)(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|::)(?![\w:])/g;

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
  // |lat|,|lon| <= 1 is open ocean (Gulf of Guinea): embedding / weight vectors.
  if (Math.abs(lat) <= 1 && Math.abs(lon) <= 1) {
    return false;
  }
  return lat >= -90.0 && lat <= 90.0 && lon >= -180.0 && lon <= 180.0;
}

// Degrees-minutes(-seconds) as maps, EXIF, and GPS units print them
// (``52°22'3.4"N 4°54'14.8"E``, ``N 52° 22.057' E 4° 54.246'``). Each half
// needs a degree sign, a minute mark, and a hemisphere letter before or after
// (Dutch / German ``Z`` / ``O`` for south / east); prime and double-prime
// glyphs stand in for ``'`` / ``"``.
const DMS_BODY = String.raw`\d{1,3}\s?[°º]\s?\d{1,2}(?:[.,]\d{1,4})?\s?['′’](?:\s?\d{1,2}(?:[.,]\d{1,4})?\s?(?:["″”]|''|′′))?`;
const LOCATION_DMS_RE = new RegExp(
  String.raw`(?<![A-Za-z0-9_.])(?:[NSZ]\s?${DMS_BODY}|${DMS_BODY}\s?[NSZ])\s{0,3}[,;/]?\s{0,3}(?:[EOW]\s?${DMS_BODY}|${DMS_BODY}\s?[EOW])(?![A-Za-z0-9_])`,
  "g",
);

function dmsNumbers(part: string): number[] {
  return [...part.matchAll(/\d+(?:[.,]\d+)?/g)].map((m) =>
    Number(m[0].replace(",", ".")),
  );
}

/**
 * Degrees within ±90 / ±180, minutes and seconds below 60. The two degree
 * signs split the hit: the number before the first is the latitude degrees,
 * the one before the second the longitude degrees.
 */
function locationDmsValid(value: string): boolean {
  const parts = value.split(/[°º]/);
  if (parts.length !== 3) {
    return false;
  }
  const lat = dmsNumbers(parts[0]!);
  const mid = dmsNumbers(parts[1]!);
  if (lat.length === 0 || mid.length === 0) {
    return false;
  }
  const latDeg = lat[lat.length - 1]!;
  const lonDeg = mid[mid.length - 1]!;
  const minutesSeconds = [...mid.slice(0, -1), ...dmsNumbers(parts[2]!)];
  return latDeg <= 90 && lonDeg <= 180 && minutesSeconds.every((n) => n < 60);
}

function scrubLocation(text: string): { text: string; count: number } {
  const dms = replaceMatches(
    text,
    LOCATION_DMS_RE,
    "[LOCATION]",
    locationDmsValid,
    true,
  );
  const decimal = replaceMatches(dms.text, LOCATION_RE, "[LOCATION]", locationValid);
  return { text: decimal.text, count: dms.count + decimal.count };
}

export const locationDetector: Detector = {
  type: "location",
  scrub: scrubLocation,
};

// Group separators for national ids: word processors and PDFs turn the typed
// space / hyphen into nbsp, thin / narrow nbsp, or a unicode dash.
const ID_SPACE = `[ ${GROUP_SPACES}]`;
const ID_DASH = String.raw`[\-${GROUP_DASHES}]`;
const ID_SEPS = new RegExp(String.raw`[ .\-/${GROUP_SPACES}${GROUP_DASHES}]`, "g");

// ``(?<!\d\.)``: the fractional part of a decimal (``0.12345678``) is not an id.
const BSN_RES = [
  /(?<!\d\.)\b\d{8,9}\b/g,
  new RegExp(
    String.raw`\b\d{3}(?:${ID_SPACE}|${ID_DASH}|\.)\d{3}(?:${ID_SPACE}|${ID_DASH}|\.)\d{3}\b`,
    "g",
  ),
] as const;

function bsnValid(value: string): boolean {
  const digits = value.replace(ID_SEPS, "");
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
  new RegExp(String.raw`\b\d{3}${ID_DASH}\d{2}${ID_DASH}\d{4}\b`, "g"),
  /\b\d{3}\/\d{2}\/\d{4}\b/g,
  new RegExp(
    String.raw`\b\d{3}(?:${ID_SPACE}|\.)\d{2}(?:${ID_SPACE}|\.)\d{4}\b`,
    "g",
  ),
  /(?<!\d\.)\b\d{9}\b/g,
] as const;

function ssnObviouslyFake(digits: string): boolean {
  if (new Set(digits).size === 1) {
    return true;
  }
  return digits === "123456789" || digits === "987654321";
}

function ssnValid(value: string): boolean {
  const digits = value.replace(ID_SEPS, "");
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

// Compact, or the ``12 345 678 901`` grouping printed on Steuerbescheide and
// payslips (single space / nbsp between groups).
const TAX_ID_RES = [
  /\b\d{11}\b/g,
  new RegExp(
    String.raw`\b\d{2}${ID_SPACE}\d{3}${ID_SPACE}\d{3}${ID_SPACE}\d{3}\b`,
    "g",
  ),
] as const;

function taxIdValid(value: string): boolean {
  const digits = value.replace(ID_SEPS, "");
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
  let out = text;
  let count = 0;
  for (const pattern of TAX_ID_RES) {
    const result = replaceMatches(out, pattern, "[TAX_ID]", taxIdValid);
    out = result.text;
    count += result.count;
  }
  return { text: out, count };
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

// Rich text / PDFs put nbsp, thin / narrow nbsp, or a unicode dash between
// phone groups; every phone pattern accepts them alongside the ASCII seps.
const PHONE_SEP_EXTRA = GROUP_SPACES + GROUP_DASHES;

// The span allows more than 15 digits so a ``(0)`` trunk between spaced groups
// (``+44 (0) 20 7946 0958``) fits; ``phoneInternationalEnd`` cuts it back.
const PHONE_INTERNATIONAL_RE = new RegExp(
  String.raw`(?<![\w+])(?:\+|00)\d[\d .()\-${PHONE_SEP_EXTRA}]{6,20}\d`,
  "g",
);

const PHONE_INTERNATIONAL_SEP_RE = new RegExp(String.raw`[ .()\-${PHONE_SEP_EXTRA}]`);

function isAsciiDigit(ch: string | undefined): boolean {
  return ch !== undefined && ch >= "0" && ch <= "9";
}

/**
 * End of the phone number starting at ``start`` (``start`` rejects).
 *
 * The run of digit groups is rescanned from ``start`` (40 chars of groups and
 * gaps) so a group the regex span cut in half never counts. Neither a ``00``
 * prefix nor a ``(0)`` trunk counts toward E.164's 8–15 digits. A run within
 * that range is taken whole. A longer one holds a second number: cut at the
 * last valid group boundary where one starts, i.e. before a spaced ``(``
 * group, a ``00`` + country-code group, or a ``0``-led group with a full
 * national number (10+ digits) left (``… 1234567 (06) …``, ``… 0031 6 …``,
 * ``… 020 7654321``); else at the last valid boundary. So the next number's
 * area code is not swallowed and its subscriber part leaked, while a
 * ``0``-led subscriber group (``+44 20 7946 0958``) stays whole. Digits are
 * ASCII, as JS ``\d`` is.
 */
function phoneInternationalEnd(text: string, start: number): number {
  const isSep = (k: number) =>
    k < text.length && PHONE_INTERNATIONAL_SEP_RE.test(text[k]!);
  // (end, digits so far, next group starts a new number, next is 0-led)
  const cuts: [number, number, boolean, boolean][] = [];
  let digits = 0;
  let whole = false;
  let i = text.startsWith("00", start) ? start + 2 : text[start] === "+" ? start + 1 : start;
  const limit = Math.min(text.length, start + 40);
  const cap = Math.min(text.length, start + 64);
  while (i < limit) {
    if (isSep(i)) {
      i += 1;
      continue;
    }
    if (!isAsciiDigit(text[i])) {
      break;
    }
    if (text[i - 1] === "(" && text.startsWith("0)", i)) {
      i += 1;
      continue;
    }
    while (i < cap && isAsciiDigit(text[i])) {
      digits += 1;
      i += 1;
    }
    if (isAsciiDigit(text[i])) {
      break;
    }
    let g = i;
    while (g < limit && isSep(g)) {
      g += 1;
    }
    const more = g < limit && isAsciiDigit(text[g]);
    const newNumber =
      more &&
      (text.slice(i, g).includes("(") ||
        (text.startsWith("00", g) && isAsciiDigit(text[g + 2])));
    cuts.push([i, digits, newNumber, more && text[g] === "0"]);
    if (!more) {
      whole = true;
      break;
    }
    i = g;
  }
  if (whole && digits >= 8 && digits <= 15) {
    return cuts[cuts.length - 1]![0];
  }
  const valid = cuts.filter(([, n]) => n >= 8 && n <= 15);
  const marked = valid.filter(
    ([, n, next, zero]) => next || (zero && digits - n >= 10),
  );
  const pick = marked.length > 0 ? marked : valid;
  return pick.length > 0 ? pick[pick.length - 1]![0] : start;
}

const PHONE_NL_NATIONAL: readonly [RegExp, (value: string) => boolean] = [
  new RegExp(
    String.raw`(?<![\w+])\(?0\d\)?(?:[ .\-/()${PHONE_SEP_EXTRA}]?\d){8}(?!\d)(?![A-Fa-f]{2})`,
    "g",
  ),
  (m) => digitCount(m) === 10,
];

const NANP_SEP = String.raw`[ .\-${PHONE_SEP_EXTRA}]`;

const PHONE_EN_NANP: readonly [RegExp, (value: string) => boolean] = [
  new RegExp(
    String.raw`(?<![\w+])(?:1${NANP_SEP}?)?\(?\d{3}\)?${NANP_SEP}?\d{3}${NANP_SEP}\d{4}(?!\d)`,
    "g",
  ),
  (m) => {
    const digits = digitCount(m);
    return (
      digits === 10 || (digits === 11 && m.replace(/\D/g, "").startsWith("1"))
    );
  },
];

const PHONE_DE_NATIONAL: readonly [RegExp, (value: string) => boolean] = [
  new RegExp(
    String.raw`(?<![\w+])\(?0\d\)?(?:[ .\-/()${PHONE_SEP_EXTRA}]?\d){8,10}(?!\d)(?![A-Fa-f]{2})`,
    "g",
  ),
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
        // An opening ``(`` belongs to the number only when it wraps the area
        // code (``(06)…``); ``(06-1234…)`` resumes at the ``0``.
        const result = replaceMatches(
          out,
          pattern,
          "[PHONE]",
          (m) => valid(m) && (!m.startsWith("(") || m.includes(")")),
          true,
        );
        out = result.text;
        count += result.count;
      }
      return { text: out, count };
    },
  };
}

export const phoneInternationalDetector: Detector = {
  type: "phone",
  scrub(text: string): { text: string; count: number } {
    return replaceMatches(
      text,
      PHONE_INTERNATIONAL_RE,
      "[PHONE]",
      undefined,
      true,
      (full, start) => phoneInternationalEnd(full, start),
    );
  },
};
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

/**
 * Reject RDW-forbidden SA/SD/SS pairs inside one letter group; letters split
 * by a hyphen (``KS-234-S``) are not a combination.
 */
function nlLicensePlateValid(value: string): boolean {
  return !value
    .toUpperCase()
    .split("-")
    .some((group) => [...NL_PLATE_LETTER_REJECTS].some((pair) => group.includes(pair)));
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

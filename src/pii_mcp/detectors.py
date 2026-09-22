"""Pattern detectors: regex + checksum where one exists.

Ported from foro-sh/platform ``infra/templates/foro-pii.mts``. Detector order
matters — earlier matches become digit-free placeholders before looser
numeric detectors run.

Patterns:
- Email uses bounded quantifiers (unbounded local-part ``+`` is ReDoS-prone)
  and ``(?!@)`` so glued addresses (``a@b.comc@d.com``) backtrack to two hits.
  When a TLD absorbs a following IBAN/card/IP/MAC/location
  (``ada@example.comNL91…`` / ``…com192.0.2.1`` / ``…comaa:bb:…``), the match
  is shortened so both hits still redact.
- Spaced IBANs use separate upper- and lower-case optional-space patterns so a
  trailing word is not swallowed by a mixed-case class. A fourth pattern allows
  mixed case and hyphen/tab/nbsp/slash separators when groups are explicitly separated
  (trailing word boundary blocks trailing-word swallow). A fifth matches a single
  hyphen after the check digits (``NL91-ABNA0417164300``).   Soft hyphens and zero-width characters are stripped before IBAN matching.
- Credit cards include Amex 4-6-5 groupings as well as 4-4-4-x and compact;
  grouped forms also accept tab, nbsp, ideographic space, unicode dashes,
  ``.``, and ``/``; zero-width characters are stripped before matching.
- IP: IPv4-mapped IPv6 (``::ffff:a.b.c.d``) is matched whole before bare IPv4;
  IPv4 rejects a preceding ``:`` so mapped forms are not partially eaten;
  leading zeros in octets are accepted (``192.168.001.001``).
- BIC/SWIFT: 8 or 11 alnum with ISO 3166-1 country letters (AP: financial data).
- MAC: colon/dash IEEE and Cisco dotted forms (AP: device MAC is personal data).
- IMEI: hyphen/space-grouped 15-digit forms with Luhn (AP: gegevens over
  elektronische communicatie / device identifiers). Compact 15-digit IMEIs
  that are also Luhn-valid collide with Amex and stay under ``credit_card``.
- IP: IPv4 octet-bounded regex; IPv6 candidate shapes validated via
  ``ipaddress`` (AP notes IP addresses can be personal data).
- Location: decimal lat/lon pairs with ≥3 fractional digits, optional
  ``N``/``S``/``E``/``W`` hemisphere letters, and range checks (AP lists
  locatiegegevens as privacy-sensitive).
- US SSN: hyphen/space/dot/slash or compact 9-digit with SSA area/group/serial
  rejects, plus obvious fakes (all-same digit, 123456789 / 987654321).
- German Steuer-IdNr (tax_id): 11 digits with structure + mod-11/10 check.
- NL BTW-id (``vat_id``): ``NL`` + 9 digits + ``B`` + 2 digits with optional
  spaces/dots (format only — post-2020 sole-trader ids are not elfproef-gated).
- NL passport / ID-card number (``passport``): 9-char RvIG document number
  (``[A-Za-z]{2}[0-9A-Za-z]{6}[0-9]``, letter O forbidden after uppercasing)
  — national identificatienummer alongside BSN; format only, no check digit.
- NL postcode (``address``): ``1234 AB`` / ``1234AB`` with uppercase letters
  only and SA/SD/SS rejects — structured fragment, not street-address NER.
- NL kenteken (``license_plate``): hyphenated RDW sidecodes 1–14 (case-
  insensitive), with SA/SD/SS letter-pair rejects.
- Phone packs: international (any active pack), NL national (allows ``/`` and
  parentheses; rejects hex-digest glue), NANP, DE national (DE excludes exact
  Dutch ``06…`` 10-digit mobiles; same hex-glue guard).
- BSN spaced/dotted/hyphenated ``111-222-333`` groups.

``UNIVERSAL_DETECTORS`` (email, IBAN, credit card, BIC, MAC, IMEI, IP, location)
always run; locale detectors are selected by ``languages=`` in the scrub layer.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

PiiCategory = Literal[
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
    "address",
    "license_plate",
]


@dataclass(frozen=True)
class Detector:
    type: PiiCategory
    scrub: Callable[[str], tuple[str, int]]


def _replace_matches(
    text: str,
    pattern: re.Pattern[str],
    placeholder: str,
    is_valid: Callable[[str], bool] | None = None,
) -> tuple[str, int]:
    count = 0

    def _sub(match: re.Match[str]) -> str:
        nonlocal count
        value = match.group(0)
        if is_valid is not None and not is_valid(value):
            return value
        count += 1
        return placeholder

    return pattern.sub(_sub, text), count


EMAIL_RE = re.compile(
    r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}"
    r"(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}(?!@)"
)

# After a shortened email, remainder may start a new structured hit.
_EMAIL_NEXT_PII_RE = re.compile(
    r"(?:"
    r"[A-Za-z]{2}\d{2}[A-Za-z0-9]"  # IBAN
    r"|\d{13,19}"  # compact card
    r"|\d{3}[- ./]?\d{2}[- ./]?\d{4}"  # SSN
    r"|\d{3}[ .]\d{3}[ .]\d{3}"  # spaced BSN
    r"|\d{8,9}(?!\d)"  # BSN / short national id
    r"|(?:\d{1,3}\.){3}\d{1,3}"  # IPv4
    r"|\d{1,3}\.\d{3,8}"  # location lat
    r"|[0-9A-Fa-f]{2}([-:/.])[0-9A-Fa-f]{2}"  # MAC
    r"|(?:[0-9A-Fa-f]{3,4}:|::)"  # IPv6 (3–4 digit hextet or compressed)
    r"|[A-Za-z0-9._%+-]{1,64}@"  # another email
    r"|[+0]\d"  # phone-ish
    r")"
)


def _email_end_ok(text: str, end: int) -> bool:
    if end >= len(text):
        return True
    ch = text[end]
    if ch == "@":
        return False
    if not ch.isalnum():
        return True
    return _EMAIL_NEXT_PII_RE.match(text, end) is not None


def _email_should_peel(text: str, start: int, end: int) -> bool:
    """True when trailing TLD letters belong to following letter-led PII (MAC)."""
    for try_end in range(end - 1, start, -1):
        if not text[try_end].isalpha():
            break
        cand = text[start:try_end]
        if EMAIL_RE.fullmatch(cand) is None:
            continue
        if _EMAIL_NEXT_PII_RE.match(text, try_end) is not None:
            return True
    return False


def _scrub_email(text: str) -> tuple[str, int]:
    """Mask emails; shorten when the TLD absorbed a following structured hit."""
    count = 0
    parts: list[str] = []
    last = 0
    pos = 0
    while True:
        match = EMAIL_RE.search(text, pos)
        if match is None:
            break
        start, end = match.start(), match.end()
        if not _email_end_ok(text, end) or _email_should_peel(text, start, end):
            shortened = None
            for try_end in range(end - 1, start, -1):
                cand = text[start:try_end]
                if EMAIL_RE.fullmatch(cand) is None:
                    continue
                if _email_end_ok(text, try_end):
                    shortened = try_end
                    break
            if shortened is None:
                pos = start + 1
                continue
            end = shortened
        parts.append(text[last:start])
        parts.append("[EMAIL]")
        last = end
        pos = end
        count += 1
    if count == 0:
        return text, 0
    parts.append(text[last:])
    return "".join(parts), count


email_detector = Detector(type="email", scrub=_scrub_email)

# Unicode Zs separators commonly used in OCR / rich text (thin/figure/nbsp…).
_SEP_SPACE = r"[ \t\r\n\xa0\u2000-\u200a\u202f\u3000]"
# Soft hyphen + zero-width chars that OCR/copy-paste insert between groups.
_INVISIBLE = "\u00ad\u200b\u200c\u200d\ufeff"

IBAN_RES: tuple[re.Pattern[str], ...] = (
    # Allow after digits (card|IBAN glue); still reject mid-letter (xNL91…).
    re.compile(r"(?<![A-Za-z])[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30}(?![A-Za-z0-9])"),
    re.compile(rf"\b[A-Z]{{2}}\d{{2}}(?:{_SEP_SPACE}?[A-Z0-9]{{1,4}}){{3,8}}\b"),
    re.compile(rf"\b[a-z]{{2}}\d{{2}}(?:{_SEP_SPACE}?[a-z0-9]{{1,4}}){{3,8}}\b"),
    # Mixed case / hyphen|slash|dot|whitespace groups (one or more seps).
    re.compile(
        rf"(?<![A-Za-z])[A-Za-z]{{2}}\d{{2}}"
        rf"(?:(?:{_SEP_SPACE}|[\-/.])+[A-Za-z0-9]{{1,4}}){{3,8}}(?![A-Za-z0-9])"
    ),
    # Single hyphen after check digits, compact BBAN.
    re.compile(r"(?<![A-Za-z])[A-Za-z]{2}\d{2}-[A-Za-z0-9]{11,30}(?![A-Za-z0-9])"),
)


def _iban_valid(value: str) -> bool:
    compact = re.sub(r"[\s\-\u00ad\u200b\u200c\u200d\ufeff/.]+", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    remainder = 0
    for ch in rearranged:
        if ch >= "A":
            remainder = (remainder * 100 + (ord(ch) - 55)) % 97
        else:
            remainder = (remainder * 10 + (ord(ch) - 48)) % 97
    return remainder == 1


def _scrub_iban(text: str) -> tuple[str, int]:
    out = text
    for ch in _INVISIBLE:
        out = out.replace(ch, "")
    count = 0
    for pattern in IBAN_RES:
        out, n = _replace_matches(out, pattern, "[IBAN]", _iban_valid)
        count += n
    return out, count


iban_detector = Detector(type="iban", scrub=_scrub_iban)

# One or more whitespace / dash / punct separators between digit groups.
_CC_SEP = rf"(?:{_SEP_SPACE}|[./\-\u2010-\u2015])+"

CREDIT_CARD_RES: tuple[re.Pattern[str], ...] = (
    re.compile(rf"(?<!\d)\d{{4}}{_CC_SEP}\d{{4}}{_CC_SEP}\d{{4}}{_CC_SEP}\d{{1,4}}(?!\d)"),
    re.compile(rf"(?<!\d)\d{{4}}{_CC_SEP}\d{{6}}{_CC_SEP}\d{{5}}(?!\d)"),
    # Digit/letter glue: \b does not split 1N.
    re.compile(r"(?<!\d)\d{13,19}(?!\d)"),
)


def _luhn_valid(digits: str) -> bool:
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    double = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


def _scrub_credit_card(text: str) -> tuple[str, int]:
    out = text
    for ch in _INVISIBLE:
        out = out.replace(ch, "")
    count = 0
    for pattern in CREDIT_CARD_RES:
        out, n = _replace_matches(
            out,
            pattern,
            "[CREDIT_CARD]",
            lambda m: _luhn_valid(re.sub(r"\D", "", m)),
        )
        count += n
    return out, count


credit_card_detector = Detector(type="credit_card", scrub=_scrub_credit_card)

# ISO 3166-1 alpha-2 — BIC country field must be a real country code.
_ISO_3166_1_ALPHA2 = frozenset(
    """
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
    """.split()
)

BIC_RE = re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b")


def _bic_valid(value: str) -> bool:
    """Uppercase SWIFT/BIC only; country letters must be ISO 3166-1 alpha-2."""
    if len(value) not in (8, 11):
        return False
    if not re.fullmatch(r"[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?", value):
        return False
    return value[4:6] in _ISO_3166_1_ALPHA2


def _scrub_bic(text: str) -> tuple[str, int]:
    return _replace_matches(text, BIC_RE, "[BIC]", _bic_valid)


bic_detector = Detector(type="bic", scrub=_scrub_bic)

MAC_RES: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?<![\w:])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![\w:])"
    ),
    re.compile(
        r"(?<![\w.])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![\w.])"
    ),
)


def _scrub_mac(text: str) -> tuple[str, int]:
    out = text
    count = 0
    for pattern in MAC_RES:
        out, n = _replace_matches(out, pattern, "[MAC]")
        count += n
    return out, count


mac_detector = Detector(type="mac", scrub=_scrub_mac)

# Grouped only — compact 15-digit Luhn values collide with Amex credit cards.
IMEI_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?<![\w.-])\d{2}[- .]\d{6}[- .]\d{6}[- .]\d(?![\w.-])"),
    re.compile(r"(?<![\w.-])\d{8}[- .]\d{6}[- .]\d(?![\w.-])"),
    re.compile(r"(?<![\w.-])\d{2}[- .]\d{6}[- .]\d{7}(?![\w.-])"),
)


def _imei_valid(value: str) -> bool:
    digits = re.sub(r"[ .-]", "", value)
    return len(digits) == 15 and digits.isdigit() and _luhn_valid(digits)


def _scrub_imei(text: str) -> tuple[str, int]:
    out = text
    count = 0
    for pattern in IMEI_RES:
        out, n = _replace_matches(out, pattern, "[IMEI]", _imei_valid)
        count += n
    return out, count


imei_detector = Detector(type="imei", scrub=_scrub_imei)

IPV4_RE = re.compile(
    r"(?<![\w.:])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\w.])"
)

# IPv4-mapped IPv6 must win before bare IPv4 / truncated IPv6 candidates.
IPV4_MAPPED_RE = re.compile(
    r"(?<![\w:])::[Ff]{4}:(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\w.])"
)

# Loose colon/hex shapes; ``_ip_valid`` drops non-addresses.
IPV6_RE = re.compile(
    r"(?<![\w:])(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|::"
    r")(?![\w:])"
)


def _normalize_ipv4_octets(value: str) -> str | None:
    """Strip leading zeros from a dotted quad; None if not four 0–255 octets."""
    parts = value.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 1 <= len(p) <= 3 for p in parts):
        return None
    nums = [int(p) for p in parts]
    if any(n > 255 for n in nums):
        return None
    return ".".join(str(n) for n in nums)


def _ip_valid(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return True
    lower = value.lower()
    if lower.startswith("::ffff:"):
        v4 = _normalize_ipv4_octets(value[7:])
        if v4 is None:
            return False
        try:
            ipaddress.ip_address("::ffff:" + v4)
        except ValueError:
            return False
        return True
    if ":" in value:
        return False
    return _normalize_ipv4_octets(value) is not None


def _scrub_ip(text: str) -> tuple[str, int]:
    out, count = _replace_matches(text, IPV4_MAPPED_RE, "[IP]", _ip_valid)
    out, n = _replace_matches(out, IPV4_RE, "[IP]", _ip_valid)
    count += n
    out, n = _replace_matches(out, IPV6_RE, "[IP]", _ip_valid)
    return out, count + n


ip_detector = Detector(type="ip", scrub=_scrub_ip)

# Decimal degree pairs; ≥3 fractional digits cuts version-like ``1.0, 2.0``.
LOCATION_RE = re.compile(
    r"(?<![\d.+-])[-+]?\d{1,3}\.\d{3,8}°?(?:\s*[NnSs])?\s*,\s*"
    r"[-+]?\d{1,3}\.\d{3,8}°?(?:\s*[EeWw])?(?![A-Za-z\d.])"
)


def _coord_component(part: str) -> float:
    cleaned = re.sub(r"[^\d.+-]", "", part)
    return float(cleaned)


def _location_valid(value: str) -> bool:
    """Accept lat,lon (WGS84) when both components fall in geographic ranges."""
    parts = re.split(r"\s*,\s*", value.strip())
    if len(parts) != 2:
        return False
    try:
        lat = _coord_component(parts[0])
        lon = _coord_component(parts[1])
    except ValueError:
        return False
    return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0


def _scrub_location(text: str) -> tuple[str, int]:
    return _replace_matches(text, LOCATION_RE, "[LOCATION]", _location_valid)


location_detector = Detector(type="location", scrub=_scrub_location)

BSN_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b\d{8,9}\b"),
    re.compile(r"\b\d{3}[ .\-]\d{3}[ .\-]\d{3}\b"),
)


def _bsn_valid(value: str) -> bool:
    digits = re.sub(r"[ .\-]", "", value)
    if len(digits) < 8 or len(digits) > 9 or not digits.isdigit():
        return False
    padded = digits.zfill(9)
    if padded == "000000000":
        return False
    weights = (9, 8, 7, 6, 5, 4, 3, 2, -1)
    total = sum((ord(padded[i]) - 48) * weights[i] for i in range(9))
    return total % 11 == 0


def _scrub_bsn(text: str) -> tuple[str, int]:
    out = text
    count = 0
    for pattern in BSN_RES:
        out, n = _replace_matches(out, pattern, "[BSN]", _bsn_valid)
        count += n
    return out, count


bsn_detector = Detector(type="bsn", scrub=_scrub_bsn)

SSN_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b\d{3}/\d{2}/\d{4}\b"),
    re.compile(r"\b\d{3}[ .]\d{2}[ .]\d{4}\b"),
    re.compile(r"\b\d{9}\b"),
)


def _ssn_obviously_fake(digits: str) -> bool:
    """Reject sequential / repeated 9-digit strings that pass SSA structure checks."""
    if len(set(digits)) == 1:
        return True
    if digits in {"123456789", "987654321"}:
        return True
    return False


def _ssn_valid(value: str) -> bool:
    """SSA rejects: area 000/666/9xx, group 00, serial 0000; drop obvious fakes."""
    digits = re.sub(r"[ .\-/]", "", value)
    if len(digits) != 9 or not digits.isdigit():
        return False
    if _ssn_obviously_fake(digits):
        return False
    area = int(digits[:3])
    group = int(digits[3:5])
    serial = int(digits[5:])
    if area == 0 or area == 666 or area >= 900:
        return False
    if group == 0 or serial == 0:
        return False
    return True


def _scrub_ssn(text: str) -> tuple[str, int]:
    out = text
    count = 0
    for pattern in SSN_RES:
        out, n = _replace_matches(out, pattern, "[SSN]", _ssn_valid)
        count += n
    return out, count


ssn_detector = Detector(type="ssn", scrub=_scrub_ssn)

TAX_ID_RE = re.compile(r"\b\d{11}\b")


def _tax_id_valid(digits: str) -> bool:
    """German IdNr: no leading zero; one digit repeats 2–3× in body; check digit."""
    if len(digits) != 11 or not digits.isdigit():
        return False
    if digits[0] == "0":
        return False
    body = digits[:10]
    counts: dict[str, int] = {}
    for ch in body:
        counts[ch] = counts.get(ch, 0) + 1
    repeats = [n for n in counts.values() if n > 1]
    if len(repeats) != 1 or repeats[0] not in (2, 3):
        return False
    product = 10
    for ch in body:
        total = (ord(ch) - 48 + product) % 10
        if total == 0:
            total = 10
        product = (2 * total) % 11
    check = 11 - product
    if check == 10:
        check = 0
    return check == (ord(digits[10]) - 48)


def _scrub_tax_id(text: str) -> tuple[str, int]:
    return _replace_matches(text, TAX_ID_RE, "[TAX_ID]", _tax_id_valid)


tax_id_detector = Detector(type="tax_id", scrub=_scrub_tax_id)

NL_VAT_RE = re.compile(r"\b[Nn][Ll][.\s]*\d{9}[.\s]*[Bb][.\s]*\d{2}\b")


def _scrub_nl_vat(text: str) -> tuple[str, int]:
    """Format-only: post-2020 sole-trader BTW-ids are not elfproef-gated."""
    return _replace_matches(text, NL_VAT_RE, "[VAT_ID]")


nl_vat_detector = Detector(type="vat_id", scrub=_scrub_nl_vat)

# RvIG document number (passport / NIK): positions 1–2 letters, 3–8 alnum,
# 9 digit; letter O never used (RvIG kenmerkenbrochure). Case-insensitive —
# candidates are uppercased before validate (same idea as NL VAT).
NL_PASSPORT_RE = re.compile(r"\b[A-Za-z]{2}[0-9A-Za-z]{6}\d\b")


def _nl_passport_valid(value: str) -> bool:
    compact = value.upper()
    if len(compact) != 9:
        return False
    if not re.fullmatch(r"[A-Z]{2}[0-9A-Z]{6}\d", compact):
        return False
    return "O" not in compact


def _scrub_nl_passport(text: str) -> tuple[str, int]:
    return _replace_matches(text, NL_PASSPORT_RE, "[PASSPORT]", _nl_passport_valid)


nl_passport_detector = Detector(type="passport", scrub=_scrub_nl_passport)


def _digit_count(text: str) -> int:
    return sum(1 for ch in text if ch.isdigit())


PHONE_INTERNATIONAL = (
    re.compile(r"(?<![\w+])(?:\+|00)\d[\d .()-]{6,16}\d"),
    lambda m: 8 <= _digit_count(m) <= 15,
)

# Trailing (?!\d)(?![A-Fa-f]{2}) blocks longer digit runs and hex digest glue
# (e.g. sha256:0123456789abcdef) without rejecting ``0612345678 ASAP``.
# Optional wrapping parens cover ``(06)12345678``; seps stay single-char so
# ``0132 / 415-…`` is not glued into one national hit.
PHONE_NL_NATIONAL = (
    re.compile(r"(?<![\w+])\(?0\d\)?(?:[ .\-/()]?\d){8}(?!\d)(?![A-Fa-f]{2})"),
    lambda m: _digit_count(m) == 10,
)

PHONE_EN_NANP = (
    re.compile(
        r"(?<![\w+])(?:1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]\d{4}(?!\d)"
    ),
    lambda m: _digit_count(m) in (10, 11) and (
        _digit_count(m) == 10 or re.sub(r"\D", "", m).startswith("1")
    ),
)

PHONE_DE_NATIONAL = (
    re.compile(r"(?<![\w+])\(?0\d\)?(?:[ .\-/()]?\d){8,10}(?!\d)(?![A-Fa-f]{2})"),
    lambda m: (
        10 <= _digit_count(m) <= 12
        and not (
            _digit_count(m) == 10
            and re.sub(r"\D", "", m).startswith("06")
        )
    ),
)


def _make_phone_detector(
    patterns: tuple[tuple[re.Pattern[str], Callable[[str], bool]], ...],
) -> Detector:
    def scrub(text: str) -> tuple[str, int]:
        out = text
        count = 0
        for pattern, valid in patterns:
            out, n = _replace_matches(out, pattern, "[PHONE]", valid)
            count += n
        return out, count

    return Detector(type="phone", scrub=scrub)


phone_international_detector = _make_phone_detector((PHONE_INTERNATIONAL,))
phone_nl_detector = _make_phone_detector((PHONE_NL_NATIONAL,))
phone_en_detector = _make_phone_detector((PHONE_EN_NANP,))
phone_de_detector = _make_phone_detector((PHONE_DE_NATIONAL,))

NL_POSTCODE_RE = re.compile(r"\b[1-9]\d{3}\s?[A-Z]{2}\b")
_NL_POSTCODE_LETTER_REJECTS = frozenset({"SA", "SD", "SS"})


def _nl_postcode_valid(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"[1-9]\d{3}[A-Z]{2}", compact):
        return False
    return compact[4:] not in _NL_POSTCODE_LETTER_REJECTS


def _scrub_nl_postcode(text: str) -> tuple[str, int]:
    return _replace_matches(text, NL_POSTCODE_RE, "[ADDRESS]", _nl_postcode_valid)


nl_postcode_detector = Detector(type="address", scrub=_scrub_nl_postcode)

# Hyphenated RDW sidecodes 1–14 only (compact forms are too collision-prone).
NL_LICENSE_PLATE_RE = re.compile(
    r"(?<![\w-])(?:"
    r"[A-Z]{2}-\d{2}-\d{2}"
    r"|\d{2}-\d{2}-[A-Z]{2}"
    r"|\d{2}-[A-Z]{2}-\d{2}"
    r"|[A-Z]{2}-\d{2}-[A-Z]{2}"
    r"|[A-Z]{2}-[A-Z]{2}-\d{2}"
    r"|\d{2}-[A-Z]{2}-[A-Z]{2}"
    r"|\d{2}-[A-Z]{3}-\d"
    r"|\d-[A-Z]{3}-\d{2}"
    r"|[A-Z]{2}-\d{3}-[A-Z]"
    r"|[A-Z]-\d{3}-[A-Z]{2}"
    r"|[A-Z]{3}-\d{2}-[A-Z]"
    r"|[A-Z]-\d{2}-[A-Z]{3}"
    r"|\d-[A-Z]{2}-\d{3}"
    r"|\d{3}-[A-Z]{2}-\d"
    r")(?![\w-])",
    re.IGNORECASE,
)
_NL_PLATE_LETTER_REJECTS = frozenset({"SA", "SD", "SS"})


def _nl_license_plate_valid(value: str) -> bool:
    """Reject RDW-forbidden SA/SD/SS letter pairs anywhere in the plate."""
    letters = "".join(ch for ch in value.upper() if ch.isalpha())
    for i in range(len(letters) - 1):
        if letters[i : i + 2] in _NL_PLATE_LETTER_REJECTS:
            return False
    return True


def _scrub_nl_license_plate(text: str) -> tuple[str, int]:
    return _replace_matches(
        text, NL_LICENSE_PLATE_RE, "[LICENSE_PLATE]", _nl_license_plate_valid
    )


nl_license_plate_detector = Detector(
    type="license_plate", scrub=_scrub_nl_license_plate
)

UNIVERSAL_DETECTORS: tuple[Detector, ...] = (
    email_detector,
    iban_detector,
    credit_card_detector,
    bic_detector,
    mac_detector,
    imei_detector,
    ip_detector,
    location_detector,
)

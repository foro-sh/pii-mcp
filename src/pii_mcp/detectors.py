"""Tier-1 detectors: regex + checksum where one exists.

Ported from foro-sh/platform ``infra/templates/foro-pii.mts``. Detector order
matters — earlier matches become digit-free placeholders before looser
numeric detectors run.

Patterns:
- Email uses bounded quantifiers (unbounded local-part ``+`` is ReDoS-prone).
- Spaced IBANs use separate upper- and lower-case patterns so a trailing word
  is not swallowed by a mixed-case class.
- Credit cards include Amex 4-6-5 groupings as well as 4-4-4-x and compact.
- IP: IPv4 octet-bounded regex; IPv6 candidate shapes validated via
  ``ipaddress`` (AP notes IP addresses can be personal data).
- US SSN: hyphenated or compact 9-digit with SSA area/group/serial rejects.
- German Steuer-IdNr (tax_id): 11 digits with structure + mod-11/10 check.
- NL postcode (``address``): ``1234 AB`` / ``1234AB`` with uppercase letters
  only and SA/SD/SS rejects — structured address fragment without Tier-2 NER.
- Phone packs: international (any active pack), NL national, NANP, DE national
  (DE excludes exact Dutch ``06…`` 10-digit mobiles).

``UNIVERSAL_DETECTORS`` (email, IBAN, credit card, IP) always run; locale
detectors are selected by ``languages=`` in the scrub layer.
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
    "ip",
    "bsn",
    "ssn",
    "tax_id",
    "phone",
    "address",
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
    r"(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}"
)


def _scrub_email(text: str) -> tuple[str, int]:
    return _replace_matches(text, EMAIL_RE, "[EMAIL]")


email_detector = Detector(type="email", scrub=_scrub_email)

IBAN_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30}\b"),
    re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{1,4}){3,8}\b"),
    re.compile(r"\b[a-z]{2}\d{2}(?:[ ]?[a-z0-9]{1,4}){3,8}\b"),
)


def _iban_valid(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).upper()
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
    count = 0
    for pattern in IBAN_RES:
        out, n = _replace_matches(out, pattern, "[IBAN]", _iban_valid)
        count += n
    return out, count


iban_detector = Detector(type="iban", scrub=_scrub_iban)

CREDIT_CARD_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4}\b"),
    re.compile(r"\b\d{4}[ -]\d{6}[ -]\d{5}\b"),
    re.compile(r"\b\d{13,19}\b"),
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
    count = 0
    for pattern in CREDIT_CARD_RES:
        out, n = _replace_matches(
            out,
            pattern,
            "[CREDIT_CARD]",
            lambda m: _luhn_valid(re.sub(r"[ -]", "", m)),
        )
        count += n
    return out, count


credit_card_detector = Detector(type="credit_card", scrub=_scrub_credit_card)

IPV4_RE = re.compile(
    r"(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
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


def _ip_valid(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _scrub_ip(text: str) -> tuple[str, int]:
    out, count = _replace_matches(text, IPV4_RE, "[IP]", _ip_valid)
    out, n = _replace_matches(out, IPV6_RE, "[IP]", _ip_valid)
    return out, count + n


ip_detector = Detector(type="ip", scrub=_scrub_ip)

BSN_RE = re.compile(r"\b\d{8,9}\b")


def _bsn_valid(digits: str) -> bool:
    if len(digits) < 8 or len(digits) > 9:
        return False
    padded = digits.zfill(9)
    if padded == "000000000":
        return False
    weights = (9, 8, 7, 6, 5, 4, 3, 2, -1)
    total = sum((ord(padded[i]) - 48) * weights[i] for i in range(9))
    return total % 11 == 0


def _scrub_bsn(text: str) -> tuple[str, int]:
    return _replace_matches(text, BSN_RE, "[BSN]", _bsn_valid)


bsn_detector = Detector(type="bsn", scrub=_scrub_bsn)

SSN_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b\d{9}\b"),
)


def _ssn_valid(value: str) -> bool:
    """SSA rejects: area 000/666/9xx, group 00, serial 0000."""
    digits = value.replace("-", "")
    if len(digits) != 9 or not digits.isdigit():
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


def _digit_count(text: str) -> int:
    return sum(1 for ch in text if ch.isdigit())


PHONE_INTERNATIONAL = (
    re.compile(r"(?<![\w+])(?:\+|00)\d[\d .()-]{6,16}\d"),
    lambda m: 8 <= _digit_count(m) <= 15,
)

PHONE_NL_NATIONAL = (
    re.compile(r"(?<![\w+])0\d(?:[ .-]?\d){8}(?!\d)"),
    lambda m: _digit_count(m) == 10,
)

PHONE_EN_NANP = (
    re.compile(r"(?<![\w+])\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)"),
    lambda m: _digit_count(m) == 10,
)

PHONE_DE_NATIONAL = (
    re.compile(r"(?<![\w+])0\d(?:[ .-]?\d){8,10}(?!\d)"),
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

UNIVERSAL_DETECTORS: tuple[Detector, ...] = (
    email_detector,
    iban_detector,
    credit_card_detector,
    ip_detector,
)

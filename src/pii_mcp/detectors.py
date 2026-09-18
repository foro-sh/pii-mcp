"""Tier-1 detectors: regex + checksum where one exists.

Ported from foro-sh/platform `infra/templates/foro-pii.mts`. Detector order
matters — earlier matches become digit-free placeholders before looser
numeric detectors run.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

PiiCategory = Literal["email", "iban", "credit_card", "bsn", "phone"]


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


# Bounded quantifiers — unbounded local-part `+` is a quadratic ReDoS on long
# runs of local-part-shaped characters with no `@`.
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


def _digit_count(text: str) -> int:
    return sum(1 for ch in text if ch.isdigit())


# International E.164-ish: available whenever any language pack is active
# (locale-agnostic, but gated with packs per the languages= public API).
PHONE_INTERNATIONAL = (
    re.compile(r"(?<![\w+])(?:\+|00)\d[\d .()-]{6,16}\d"),
    lambda m: 8 <= _digit_count(m) <= 15,
)

# Dutch national: leading 0, exactly 10 digits.
PHONE_NL_NATIONAL = (
    re.compile(r"(?<![\w+])0\d(?:[ .-]?\d){8}(?!\d)"),
    lambda m: _digit_count(m) == 10,
)

# North-American 3-3-4.
PHONE_EN_NANP = (
    re.compile(r"(?<![\w+])\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)"),
    lambda m: _digit_count(m) == 10,
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

# Universal detectors — always on regardless of languages=.
UNIVERSAL_DETECTORS: tuple[Detector, ...] = (
    email_detector,
    iban_detector,
    credit_card_detector,
)

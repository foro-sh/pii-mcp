"""Language packs and scrub walk — Tier-1 only.

Universal detectors (email, IBAN, credit card) always run. Locale packs add
national IDs / phone shapes. Counts always include every PiiType key
(0 when unused), including Tier-2 placeholders.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from pii_mcp.detectors import (
    UNIVERSAL_DETECTORS,
    Detector,
    bsn_detector,
    phone_de_detector,
    phone_en_detector,
    phone_international_detector,
    phone_nl_detector,
    ssn_detector,
    tax_id_detector,
)

PiiType = Literal[
    "email",
    "iban",
    "credit_card",
    "bsn",
    "ssn",
    "tax_id",
    "phone",
    "person",
    "address",
]

PII_TYPES: tuple[PiiType, ...] = (
    "email",
    "iban",
    "credit_card",
    "bsn",
    "ssn",
    "tax_id",
    "phone",
    "person",
    "address",
)

PiiCounts = dict[PiiType, int]

LanguageCode = Literal["en", "nl", "de"]
DEFAULT_LANGUAGES: tuple[LanguageCode, ...] = ("en", "nl")

# Same bound as foro-proxy MAX_SCRUB_BYTES — oversize withholds, never forwards.
MAX_SCRUB_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 200

_KNOWN_LANGUAGES: frozenset[str] = frozenset({"en", "nl", "de"})


@dataclass(frozen=True)
class ScrubReport:
    """Counts/found only — never carries plaintext."""

    found: bool
    counts: PiiCounts


class PiiScrubError(Exception):
    """Fail-closed signal: caller must withhold, never forward unscrubbed text."""

    status_code = 500

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.name = "PiiScrubError"


def empty_pii_counts() -> PiiCounts:
    return {t: 0 for t in PII_TYPES}


def total_pii_count(counts: PiiCounts) -> int:
    return sum(counts[t] for t in PII_TYPES)


def _normalize_languages(languages: Sequence[str] | None) -> tuple[LanguageCode, ...]:
    if languages is None:
        return DEFAULT_LANGUAGES
    if not languages:
        return ()
    out: list[LanguageCode] = []
    seen: set[str] = set()
    for raw in languages:
        code = raw.lower()
        if code not in _KNOWN_LANGUAGES:
            raise ValueError(
                f"unknown language {raw!r}; supported: {sorted(_KNOWN_LANGUAGES)}"
            )
        if code not in seen:
            seen.add(code)
            out.append(code)  # type: ignore[arg-type]
    return tuple(out)


def _detectors_for(languages: Sequence[str] | None) -> tuple[Detector, ...]:
    langs = _normalize_languages(languages)
    pack: list[Detector] = list(UNIVERSAL_DETECTORS)
    # National IDs (checksum / rule-backed) before fuzzy phone.
    # BSN before SSN: overlapping 9-digit shapes prefer the stronger check.
    if "nl" in langs:
        pack.append(bsn_detector)
    if "de" in langs:
        pack.append(tax_id_detector)
    if "en" in langs:
        pack.append(ssn_detector)
    # Phone: international when any pack is on; locale forms per pack.
    if langs:
        pack.append(phone_international_detector)
    if "nl" in langs:
        pack.append(phone_nl_detector)
    if "en" in langs:
        pack.append(phone_en_detector)
    if "de" in langs:
        pack.append(phone_de_detector)
    return tuple(pack)


def _utf8_size(text: str) -> int:
    return len(text.encode("utf-8"))


def _payload_string_bytes(value: Any, depth: int = 0) -> int:
    if depth > MAX_DEPTH:
        raise PiiScrubError(f"payload nests past the {MAX_DEPTH}-level scrub limit")
    if isinstance(value, str):
        return _utf8_size(value)
    if isinstance(value, list):
        return sum(_payload_string_bytes(item, depth + 1) for item in value)
    if isinstance(value, dict):
        return sum(_payload_string_bytes(item, depth + 1) for item in value.values())
    return 0


def scrub_text(
    text: str,
    *,
    languages: Sequence[str] | None = None,
    _check_size: bool = True,
) -> dict[str, Any]:
    """Mask Tier-1 PII in a string. Returns ``{text, found, counts}``."""
    if not isinstance(text, str):
        raise TypeError("scrub_text expects a str")
    if _check_size and _utf8_size(text) > MAX_SCRUB_BYTES:
        raise PiiScrubError(
            f"scrub input exceeds the {MAX_SCRUB_BYTES}-byte size cap"
        )

    counts = empty_pii_counts()
    out = text
    for detector in _detectors_for(languages):
        out, n = detector.scrub(out)
        counts[detector.type] += n
    return {"text": out, "found": total_pii_count(counts) > 0, "counts": counts}


def _tier1_walk(
    value: Any,
    counts: PiiCounts,
    depth: int,
    languages: Sequence[str] | None,
) -> Any:
    if depth > MAX_DEPTH:
        raise PiiScrubError(f"payload nests past the {MAX_DEPTH}-level scrub limit")
    if isinstance(value, str):
        # Size already enforced for the whole payload in scrub_payload.
        result = scrub_text(value, languages=languages, _check_size=False)
        for t in PII_TYPES:
            counts[t] += result["counts"][t]
        return result["text"]
    if isinstance(value, list):
        return [_tier1_walk(item, counts, depth + 1, languages) for item in value]
    if isinstance(value, dict):
        return {
            key: _tier1_walk(item, counts, depth + 1, languages)
            for key, item in value.items()
        }
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise PiiScrubError(
        "payload contains a non-plain object that cannot be safely scrubbed"
    )


def scrub_payload(
    payload: Any,
    *,
    languages: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Walk a JSON-like payload and mask string leaves. Fails closed on errors."""
    # Size check before walk (string leaves only — matches scrub cost).
    if _payload_string_bytes(payload) > MAX_SCRUB_BYTES:
        raise PiiScrubError(
            f"scrub input exceeds the {MAX_SCRUB_BYTES}-byte size cap"
        )
    counts = empty_pii_counts()
    scrubbed = _tier1_walk(payload, counts, 0, languages)
    return {
        "payload": scrubbed,
        "found": total_pii_count(counts) > 0,
        "counts": counts,
    }


def merge_counts(parts: Iterable[PiiCounts]) -> PiiCounts:
    merged = empty_pii_counts()
    for part in parts:
        for t in PII_TYPES:
            merged[t] += part[t]
    return merged

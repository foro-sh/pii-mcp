"""Language packs and scrub walk for pattern-based detectors.

Universal detectors (key-aware person/address, email, IBAN, credit card, BIC,
MAC, IMEI, IP, location) always run. Locale packs add national IDs / phone
shapes / NL and UK postcodes / kentekens / VAT IDs / passport numbers. Counts
always include every ``PiiType`` key (0 when unused). ``person`` is pattern-
free: it only fires when a value sits right after a recognized field name
(issue #52); in-process NER is out of scope. ``address`` counts street +
house number hits, NL / UK postcodes, and key-aware street/postcode/place
hits.

``_scrub_walk`` applies the same field-name dictionary structurally: a dict
value is masked whole, by its key, before recursing (see
``detectors.key_field_category``), so ``{"last_name": "Grabbe"}`` is caught
even though the string leaf ``"Grabbe"`` alone carries no ``key:`` context
for ``scrub_text``'s pattern pass to see.

``MAX_SCRUB_BYTES`` matches foro-proxy (32 MiB). Oversize raises
``PiiScrubError`` so callers withhold rather than forward unscrubbed text.

Detector pack order (see ``_detectors_for``): universal → international phone
(when any pack is active, before national IDs so ``+31(0)6…`` is not eaten by
SSN) → UK NHS number when ``en`` (its ``3-3-4`` shape is a NANP number, and
an NL trunk-``0`` phone match can start in its middle group) → locale phone
forms (before BSN takes the subscriber part of ``040 78703244``) →
checksum/rule-backed national IDs (DE IdNr before BSN, BSN before SSN when
both packs are on, US ITIN before SSN; DE USt-IdNr and NL BTW before BSN,
DE/NL passport after) → street + house number per pack (en, de, nl) →
postcode per pack → kenteken when ``nl``.

MCP binary content is left unscrubbed (foro-pii ``binaryKey`` parity): on an
object with ``type`` of ``image`` or ``audio`` and a string ``data``, that
``data`` field is passed through; on an object with string ``uri`` and string
``blob``, ``blob`` is passed through. Sibling string fields are still scrubbed.
Matched by shape, not key alone, so a ``data`` field elsewhere is scrubbed.
Binary leaves are also excluded from the ``MAX_SCRUB_BYTES`` string-leaf sum.

Optional Rust acceleration: when ``pii_mcp._native`` is importable (shipped in
platform wheels, or built via maturin), ``scrub_text`` / ``scrub_payload``
prefer it. Set ``PII_MCP_BACKEND=python`` to force the pure-Python path;
``native`` requires the extension. Pure ``py3-none-any`` / sdist installs stay
hatchling-only — no Rust toolchain required.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Literal, TypedDict

from pii_mcp.detectors import (
    UNIVERSAL_DETECTORS,
    Detector,
    bsn_detector,
    de_passport_detector,
    de_vat_detector,
    itin_detector,
    key_field_category,
    looks_like_name,
    nhs_detector,
    nino_detector,
    nl_license_plate_detector,
    nl_passport_detector,
    nl_postcode_detector,
    nl_vat_detector,
    phone_de_detector,
    phone_en_detector,
    phone_international_detector,
    phone_nl_detector,
    ssn_detector,
    street_de_detector,
    street_en_detector,
    street_nl_detector,
    tax_id_detector,
    uk_postcode_detector,
)

PiiType = Literal[
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
]

PII_TYPES: tuple[PiiType, ...] = (
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
)

PiiCounts = dict[PiiType, int]


class ScrubTextResult(TypedDict):
    text: str
    found: bool
    counts: PiiCounts


class ScrubPayloadResult(TypedDict):
    payload: Any
    found: bool
    counts: PiiCounts

LanguageCode = Literal["en", "nl", "de"]
DEFAULT_LANGUAGES: tuple[LanguageCode, ...] = ("en", "nl")

MAX_SCRUB_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 200

_KNOWN_LANGUAGES: frozenset[str] = frozenset({"en", "nl", "de"})

try:
    from pii_mcp import _native as _native_mod
except ImportError:
    _native_mod = None


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


def using_native() -> bool:
    """Return True when the optional Rust extension will handle scrub calls."""
    return _resolve_backend() == "native"


def _resolve_backend() -> Literal["native", "python"]:
    flag = os.environ.get("PII_MCP_BACKEND", "auto").strip().lower()
    if flag in ("python", "py"):
        return "python"
    if flag in ("native", "rust"):
        if _native_mod is None:
            raise ImportError(
                "PII_MCP_BACKEND=native but pii_mcp._native is not installed; "
                "build with: maturin develop --release --manifest-path "
                "crates/pii-mcp-native/Cargo.toml"
            )
        return "native"
    if _native_mod is not None:
        return "native"
    return "python"


def _raise_native_error(exc: BaseException) -> None:
    msg = str(exc)
    if msg.startswith("PiiScrubError:"):
        raise PiiScrubError(msg.removeprefix("PiiScrubError:")) from exc
    raise exc


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
    """Build ordered detector list for ``languages`` (see module docstring)."""
    langs = _normalize_languages(languages)
    pack: list[Detector] = list(UNIVERSAL_DETECTORS)
    if langs:
        pack.append(phone_international_detector)
    if "en" in langs:
        pack.append(nhs_detector)
    # National phone forms (trunk ``0`` + area code) before bare-digit IDs, so
    # BSN does not take the subscriber part of ``040 78703244``.
    if "nl" in langs:
        pack.append(phone_nl_detector)
    if "en" in langs:
        pack.append(phone_en_detector)
    if "de" in langs:
        pack.append(phone_de_detector)
        # Before BSN: the last three groups of ``12 345 678 901`` are a
        # spaced 9-digit BSN candidate.
        pack.append(tax_id_detector)
        pack.append(de_vat_detector)
        pack.append(de_passport_detector)
    if "nl" in langs:
        # BTW-id first: its 9-digit body can itself pass the BSN elfproef.
        pack.append(nl_vat_detector)
        pack.append(bsn_detector)
        pack.append(nl_passport_detector)
    if "en" in langs:
        pack.append(nino_detector)
        pack.append(itin_detector)
        pack.append(ssn_detector)
        pack.append(street_en_detector)
        pack.append(uk_postcode_detector)
    if "de" in langs:
        pack.append(street_de_detector)
    if "nl" in langs:
        pack.append(street_nl_detector)
        pack.append(nl_postcode_detector)
        pack.append(nl_license_plate_detector)
    return tuple(pack)


def _utf8_size(text: str) -> int:
    return len(text.encode("utf-8"))


def _binary_key(value: dict[str, Any]) -> str | None:
    """Return the MCP binary field to leave unscrubbed, or ``None``.

    Matching foro-pii: ``data`` when ``type`` is ``image`` or ``audio`` and
    ``data`` is a string; ``blob`` when both ``uri`` and ``blob`` are strings.
    """
    if value.get("type") in ("image", "audio") and isinstance(value.get("data"), str):
        return "data"
    if isinstance(value.get("uri"), str) and isinstance(value.get("blob"), str):
        return "blob"
    return None


def _payload_string_bytes(value: Any, depth: int = 0) -> int:
    """Sum UTF-8 sizes of scrubbed string leaves only (matches scrub cost)."""
    if depth > MAX_DEPTH:
        raise PiiScrubError(f"payload nests past the {MAX_DEPTH}-level scrub limit")
    if isinstance(value, str):
        return _utf8_size(value)
    if isinstance(value, list):
        return sum(_payload_string_bytes(item, depth + 1) for item in value)
    if isinstance(value, dict):
        skip = _binary_key(value)
        return sum(
            _payload_string_bytes(item, depth + 1)
            for key, item in value.items()
            if key != skip
        )
    return 0


def scrub_text(
    text: str,
    *,
    languages: Sequence[str] | None = None,
    _check_size: bool = True,
) -> ScrubTextResult:
    """Mask pattern-detectable PII in a string. Returns ``{text, found, counts}``.

    Raises ``PiiScrubError`` when ``_check_size`` and input exceeds
    ``MAX_SCRUB_BYTES``.
    """
    if not isinstance(text, str):
        raise TypeError("scrub_text expects a str")

    if _resolve_backend() == "native" and _check_size:
        assert _native_mod is not None
        try:
            if languages is None:
                return dict(_native_mod.scrub_text(text))
            return dict(
                _native_mod.scrub_text(text, languages=list(languages))
            )
        except Exception as exc:  # noqa: BLE001 — remap native errors
            _raise_native_error(exc)
            raise

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


def _scrub_walk(
    value: Any,
    counts: PiiCounts,
    depth: int,
    languages: Sequence[str] | None,
) -> Any:
    """Recurse JSON-like values; string leaves are scrubbed (size already checked)."""
    if depth > MAX_DEPTH:
        raise PiiScrubError(f"payload nests past the {MAX_DEPTH}-level scrub limit")
    if isinstance(value, str):
        result = scrub_text(value, languages=languages, _check_size=False)
        for t in PII_TYPES:
            counts[t] += result["counts"][t]
        return result["text"]
    if isinstance(value, list):
        return [_scrub_walk(item, counts, depth + 1, languages) for item in value]
    if isinstance(value, dict):
        skip = _binary_key(value)
        out: dict[str, Any] = {}
        for key, item in value.items():
            if key == skip:
                out[key] = item
                continue
            if isinstance(item, str) and item:
                field = key_field_category(key)
                if field is not None:
                    category, ambiguous = field
                    if not ambiguous or looks_like_name(item):
                        counts[category] += 1
                        out[key] = f"[{category.upper()}]"
                        continue
            out[key] = _scrub_walk(item, counts, depth + 1, languages)
        return out
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise PiiScrubError(
        "payload contains a non-plain object that cannot be safely scrubbed"
    )


def scrub_payload(
    payload: Any,
    *,
    languages: Sequence[str] | None = None,
) -> ScrubPayloadResult:
    """Walk a JSON-like payload and mask string leaves. Fails closed on errors.

    MCP binary fields (``data`` on image/audio blocks, ``blob`` on resource
    contents) are left unchanged; see the module docstring. Size is enforced
    on scrubbed string leaves before the walk. Non-plain objects and
    oversize input raise ``PiiScrubError``.
    """
    if _resolve_backend() == "native":
        assert _native_mod is not None
        try:
            if languages is None:
                return dict(_native_mod.scrub_payload(payload))
            return dict(
                _native_mod.scrub_payload(payload, languages=list(languages))
            )
        except Exception as exc:  # noqa: BLE001 — remap native errors
            _raise_native_error(exc)
            raise

    if _payload_string_bytes(payload) > MAX_SCRUB_BYTES:
        raise PiiScrubError(
            f"scrub input exceeds the {MAX_SCRUB_BYTES}-byte size cap"
        )
    counts = empty_pii_counts()
    scrubbed = _scrub_walk(payload, counts, 0, languages)
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

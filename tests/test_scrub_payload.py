"""Payload walk + fail-closed tests."""

from __future__ import annotations

from datetime import datetime

import pytest

from pii_mcp import PiiScrubError, scrub_payload


def test_nested_payload() -> None:
    result = scrub_payload(
        {
            "user": {"email": "ada@example.com", "note": "no pii here"},
            "contacts": ["reach me at +31 6 12345678", "iban NL91ABNA0417164300"],
            "count": 3,
        }
    )
    assert result["payload"] == {
        "user": {"email": "[EMAIL]", "note": "no pii here"},
        "contacts": ["reach me at [PHONE]", "iban [IBAN]"],
        "count": 3,
    }
    assert result["found"] is True
    assert result["counts"]["email"] == 1
    assert result["counts"]["phone"] == 1
    assert result["counts"]["iban"] == 1


def test_clean_payload_unchanged() -> None:
    clean = {"tool": "search", "results": [{"id": 1, "ok": True}], "next": None}
    result = scrub_payload(clean)
    assert result["payload"] == clean
    assert result["found"] is False


def test_non_string_leaves() -> None:
    result = scrub_payload(
        {"bsnAsNumber": 111222333, "flag": False, "missing": None}
    )
    assert result["payload"] == {
        "bsnAsNumber": 111222333,
        "flag": False,
        "missing": None,
    }
    assert result["found"] is False


def test_bare_string() -> None:
    result = scrub_payload("mail ada@example.com")
    assert result["payload"] == "mail [EMAIL]"


def test_depth_limit() -> None:
    deep: object = "ada@example.com"
    for _ in range(250):
        deep = [deep]
    with pytest.raises(PiiScrubError, match="nests past"):
        scrub_payload(deep)


def test_cyclic_fails_closed() -> None:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    with pytest.raises(PiiScrubError):
        scrub_payload(cyclic)


def test_non_plain_object() -> None:
    with pytest.raises(PiiScrubError, match="non-plain"):
        scrub_payload({"when": datetime.now()})


def test_languages_en_skips_bsn() -> None:
    # Valid BSN that fails SSN rules (group 00) so en pack leaves it alone.
    result = scrub_payload({"id": "100000009"}, languages=["en"])
    assert result["payload"] == {"id": "100000009"}
    assert result["counts"]["bsn"] == 0
    assert result["counts"]["ssn"] == 0


def test_languages_de_masks_tax_id() -> None:
    result = scrub_payload({"id": "36574261809"}, languages=["de"])
    assert result["payload"] == {"id": "[TAX_ID]"}
    assert result["counts"]["tax_id"] == 1

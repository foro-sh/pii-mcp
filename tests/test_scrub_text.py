"""Unit tests for Tier-1 scrub_text detectors (ported from platform pii.test.ts)."""

from __future__ import annotations

import time

import pytest

from pii_mcp import PiiScrubError, scrub_text


class TestEmail:
    def test_leaves_clean_text(self) -> None:
        result = scrub_text("The server exposes a search tool and a fetch tool.")
        assert result["text"] == "The server exposes a search tool and a fetch tool."
        assert result["found"] is False
        assert result["counts"]["email"] == 0

    def test_masks_plain_email(self) -> None:
        result = scrub_text("Contact ada@example.com for help")
        assert result["text"] == "Contact [EMAIL] for help"
        assert result["found"] is True
        assert result["counts"]["email"] == 1

    def test_masks_plus_tags_and_subdomains(self) -> None:
        result = scrub_text("to a.b+tag@mail.sub.example.co.uk now")
        assert result["text"] == "to [EMAIL] now"
        assert result["counts"]["email"] == 1

    def test_masks_every_occurrence(self) -> None:
        result = scrub_text("one@a.com, two@b.org, three@c.net")
        assert result["text"] == "[EMAIL], [EMAIL], [EMAIL]"
        assert result["counts"]["email"] == 3

    def test_ignores_bare_handle(self) -> None:
        result = scrub_text("ping @octocat about this")
        assert result["found"] is False

    def test_redos_bounded_local_part(self) -> None:
        text = "x" * 999_970 + " contact ada@example.com now"
        start = time.perf_counter()
        result = scrub_text(text)
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 5000
        assert "[EMAIL]" in result["text"]
        assert result["counts"]["email"] == 1


class TestIban:
    def test_masks_compact_valid(self) -> None:
        result = scrub_text("Pay to NL91ABNA0417164300 please")
        assert result["text"] == "Pay to [IBAN] please"
        assert result["counts"]["iban"] == 1

    def test_masks_other_country(self) -> None:
        result = scrub_text("IBAN: DE89370400440532013000")
        assert result["text"] == "IBAN: [IBAN]"
        assert result["counts"]["iban"] == 1

    def test_masks_lowercased(self) -> None:
        result = scrub_text("acct gb82west12345698765432 here")
        assert result["text"] == "acct [IBAN] here"

    def test_rejects_bad_checksum(self) -> None:
        result = scrub_text("ref NL91ABNA0417164301 noted")
        assert result["counts"]["iban"] == 0

    def test_keeps_following_word(self) -> None:
        result = scrub_text("NL91ABNA0417164300 please confirm")
        assert result["text"] == "[IBAN] please confirm"

    def test_masks_two_ibans(self) -> None:
        result = scrub_text(
            "from NL91ABNA0417164300 to DE89370400440532013000 today"
        )
        assert result["text"] == "from [IBAN] to [IBAN] today"
        assert result["counts"]["iban"] == 2

    def test_masks_space_grouped_before_phone(self) -> None:
        result = scrub_text("wire the deposit to NL91 ABNA 0417 1643 00")
        assert result["text"] == "wire the deposit to [IBAN]"
        assert result["counts"]["iban"] == 1
        assert result["counts"]["phone"] == 0

    def test_masks_space_grouped_be(self) -> None:
        result = scrub_text("Please pay to BE68 5390 0754 7034 today")
        assert result["text"] == "Please pay to [IBAN] today"
        assert result["counts"]["iban"] == 1


class TestCreditCard:
    def test_masks_compact_16(self) -> None:
        result = scrub_text("card 4111111111111111 exp 12/29")
        assert result["text"] == "card [CREDIT_CARD] exp 12/29"
        assert result["counts"]["credit_card"] == 1

    def test_masks_space_grouped(self) -> None:
        result = scrub_text("pay with 4111 1111 1111 1111 now")
        assert result["text"] == "pay with [CREDIT_CARD] now"

    def test_masks_dash_grouped(self) -> None:
        result = scrub_text("4111-1111-1111-1111")
        assert result["text"] == "[CREDIT_CARD]"

    def test_masks_amex(self) -> None:
        result = scrub_text("amex 378282246310005 ok")
        assert result["text"] == "amex [CREDIT_CARD] ok"

    def test_rejects_luhn_fail(self) -> None:
        result = scrub_text("order 1234567812345678 shipped")
        assert result["counts"]["credit_card"] == 0

    def test_does_not_glue_following(self) -> None:
        result = scrub_text("4111 1111 1111 1111 4242")
        assert result["text"] == "[CREDIT_CARD] 4242"
        assert result["counts"]["credit_card"] == 1


class TestBsn:
    def test_masks_valid_9_digit(self) -> None:
        result = scrub_text("BSN 111222333 on file")
        assert result["text"] == "BSN [BSN] on file"
        assert result["counts"]["bsn"] == 1

    def test_rejects_bad_checksum(self) -> None:
        result = scrub_text("ticket 123456789 open")
        assert result["counts"]["bsn"] == 0

    def test_no_slice_of_longer(self) -> None:
        result = scrub_text("id 11122233300")
        assert result["counts"]["bsn"] == 0

    def test_disabled_without_nl(self) -> None:
        result = scrub_text("BSN 111222333 on file", languages=["en"])
        assert result["text"] == "BSN 111222333 on file"
        assert result["counts"]["bsn"] == 0


class TestPhone:
    def test_masks_e164(self) -> None:
        result = scrub_text("call +31 6 12345678 today")
        assert result["text"] == "call [PHONE] today"
        assert result["counts"]["phone"] == 1

    def test_masks_compact_international(self) -> None:
        result = scrub_text("uk +442079460958.")
        assert result["text"] == "uk [PHONE]."

    def test_masks_00_prefix(self) -> None:
        result = scrub_text("call 0031612345678 now")
        assert result["text"] == "call [PHONE] now"

    def test_masks_dutch_national(self) -> None:
        result = scrub_text("reach 06 12345678 or 0612345678")
        assert result["text"] == "reach [PHONE] or [PHONE]"
        assert result["counts"]["phone"] == 2

    def test_masks_nanp(self) -> None:
        result = scrub_text("(415) 555-0132 / 415-555-0132 / 415.555.0132")
        assert result["text"] == "[PHONE] / [PHONE] / [PHONE]"
        assert result["counts"]["phone"] == 3

    def test_ignores_year(self) -> None:
        result = scrub_text("in 2024 we shipped 500 units")
        assert result["found"] is False

    def test_ignores_ip(self) -> None:
        result = scrub_text("host at 192.168.0.1 responds")
        assert result["counts"]["phone"] == 0

    def test_en_pack_skips_dutch_national(self) -> None:
        result = scrub_text("reach 0612345678", languages=["en"])
        # International not matching (no +/00); Dutch national is nl-only.
        assert result["counts"]["phone"] == 0

    def test_nl_pack_skips_nanp(self) -> None:
        result = scrub_text("call 415-555-0132", languages=["nl"])
        assert result["counts"]["phone"] == 0


class TestMultiple:
    def test_masks_together(self) -> None:
        result = scrub_text("mail ada@example.com or card 4111111111111111")
        assert result["text"] == "mail [EMAIL] or card [CREDIT_CARD]"
        assert result["counts"] == {
            "email": 1,
            "iban": 0,
            "credit_card": 1,
            "bsn": 0,
            "phone": 0,
            "person": 0,
            "address": 0,
        }

    def test_detector_order_card_not_phone(self) -> None:
        result = scrub_text("card 4111111111111111")
        assert result["text"] == "card [CREDIT_CARD]"
        assert result["counts"]["phone"] == 0
        assert result["counts"]["bsn"] == 0


class TestSizeCap:
    def test_oversize_fails_closed(self) -> None:
        # Avoid allocating 32MiB in CI — monkeypatch the cap.
        import pii_mcp.scrub as scrub_mod

        original = scrub_mod.MAX_SCRUB_BYTES
        scrub_mod.MAX_SCRUB_BYTES = 64
        try:
            with pytest.raises(PiiScrubError, match="size cap"):
                scrub_text("x" * 100)
        finally:
            scrub_mod.MAX_SCRUB_BYTES = original

    def test_unknown_language(self) -> None:
        with pytest.raises(ValueError, match="unknown language"):
            scrub_text("hi", languages=["de"])

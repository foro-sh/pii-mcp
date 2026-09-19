"""Edge-case probes for scrub_text: leaks, false positives, intentional skips."""

from __future__ import annotations

from pii_mcp import scrub_text


class TestIbanSeparatorGaps:
    """IBANs with non-space separators / mixed case; phone must not eat the tail."""

    def test_dashed_iban_fully_masked(self) -> None:
        result = scrub_text("Pay NL91-ABNA-0417-1643-00 please")
        assert result["text"] == "Pay [IBAN] please"
        assert result["counts"]["iban"] == 1
        assert result["counts"]["phone"] == 0

    def test_mixed_case_spaced_iban(self) -> None:
        result = scrub_text("Pay Nl91 AbNa 0417 1643 00 please")
        assert result["text"] == "Pay [IBAN] please"
        assert result["counts"]["iban"] == 1

    def test_nbsp_spaced_iban_missed(self) -> None:
        """Non-breaking spaces are not treated as IBAN group separators."""
        text = "NL91\u00a0ABNA\u00a00417\u00a01643\u00a000"
        result = scrub_text(text)
        assert result["text"] == text
        assert result["counts"]["iban"] == 0

    def test_slash_separated_iban_missed(self) -> None:
        text = "Pay NL91/ABNA/0417/1643/00 please"
        result = scrub_text(text)
        assert result["text"] == text
        assert result["counts"]["iban"] == 0


class TestCreditCardSeparatorGaps:
    def test_dot_grouped_missed(self) -> None:
        text = "card 4111.1111.1111.1111"
        result = scrub_text(text)
        assert result["text"] == text
        assert result["counts"]["credit_card"] == 0

    def test_newline_grouped_missed(self) -> None:
        text = "4111\n1111\n1111\n1111"
        result = scrub_text(text)
        assert result["text"] == text
        assert result["counts"]["credit_card"] == 0

    def test_unicode_dash_grouped_missed(self) -> None:
        text = "4111\u20131111\u20131111\u20131111"
        result = scrub_text(text)
        assert result["text"] == text
        assert result["counts"]["credit_card"] == 0

    def test_nbsp_grouped_missed(self) -> None:
        text = "4111\u00a01111\u00a01111\u00a01111"
        result = scrub_text(text)
        assert result["text"] == text
        assert result["counts"]["credit_card"] == 0


class TestFalsePositives:
    def test_semver_four_part_as_ip(self) -> None:
        """Dotted quads with small octets match IPv4 (e.g. release versions)."""
        result = scrub_text("release 1.2.3.4")
        assert result["text"] == "release [IP]"
        assert result["counts"]["ip"] == 1

    def test_decimal_price_pair_as_location(self) -> None:
        result = scrub_text("prices 12.345, 67.890 listed")
        assert result["text"] == "prices [LOCATION] listed"
        assert result["counts"]["location"] == 1

    def test_version_like_pair_as_location(self) -> None:
        result = scrub_text("v1.234, 5.678 shipped")
        assert result["text"] == "v[LOCATION] shipped"
        assert result["counts"]["location"] == 1

    def test_arbitrary_nine_char_as_passport(self) -> None:
        """NL passport is format-only; many 9-char tokens match."""
        result = scrub_text("token AB12CD345 noted", languages=["nl"])
        assert result["text"] == "token [PASSPORT] noted"
        assert result["counts"]["passport"] == 1


class TestPartialOrMissedEmail:
    def test_glued_emails_both_masked(self) -> None:
        result = scrub_text("a@b.comc@d.com")
        assert result["text"] == "[EMAIL][EMAIL]"
        assert result["counts"]["email"] == 2

    def test_url_encoded_at_missed(self) -> None:
        text = "ada%40example.com"
        result = scrub_text(text)
        assert result["text"] == text
        assert result["counts"]["email"] == 0

    def test_html_entity_at_missed(self) -> None:
        text = "ada&#64;example.com"
        result = scrub_text(text)
        assert result["text"] == text
        assert result["counts"]["email"] == 0


class TestLocaleFormatSkips:
    def test_lowercase_license_plate_missed(self) -> None:
        text = "kenteken ab-12-cd gezien"
        result = scrub_text(text, languages=["nl"])
        assert result["text"] == text
        assert result["counts"]["license_plate"] == 0

    def test_spaced_vat_missed(self) -> None:
        text = "factuur NL 000099998 B57"
        result = scrub_text(text, languages=["nl"])
        assert result["text"] == text
        assert result["counts"]["vat_id"] == 0


class TestStillWorks:
    """Sanity: common well-formed inputs remain covered."""

    def test_compact_iban_and_card(self) -> None:
        result = scrub_text(
            "iban NL91ABNA0417164300 card 4111111111111111 mail ada@example.com"
        )
        assert result["text"] == "iban [IBAN] card [CREDIT_CARD] mail [EMAIL]"
        assert result["counts"]["iban"] == 1
        assert result["counts"]["credit_card"] == 1
        assert result["counts"]["email"] == 1

    def test_spaced_iban_before_phone(self) -> None:
        result = scrub_text("wire NL91 ABNA 0417 1643 00")
        assert result["text"] == "wire [IBAN]"
        assert result["counts"]["phone"] == 0

    def test_rescrub_idempotent(self) -> None:
        once = scrub_text("ada@example.com and 4111111111111111")
        twice = scrub_text(once["text"])
        assert twice["text"] == once["text"]
        assert twice["found"] is False

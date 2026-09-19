"""Edge-case probes for scrub_text: separator variants, false positives, skips."""

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

    def test_nbsp_spaced_iban(self) -> None:
        result = scrub_text("NL91\u00a0ABNA\u00a00417\u00a01643\u00a000")
        assert result["text"] == "[IBAN]"
        assert result["counts"]["iban"] == 1

    def test_tab_spaced_iban(self) -> None:
        result = scrub_text("NL91\tABNA\t0417\t1643\t00")
        assert result["text"] == "[IBAN]"
        assert result["counts"]["iban"] == 1

    def test_slash_separated_iban(self) -> None:
        result = scrub_text("Pay NL91/ABNA/0417/1643/00 please")
        assert result["text"] == "Pay [IBAN] please"
        assert result["counts"]["iban"] == 1
        assert result["counts"]["phone"] == 0

    def test_single_hyphen_after_check_digits(self) -> None:
        result = scrub_text("wire NL91-ABNA0417164300 today")
        assert result["text"] == "wire [IBAN] today"
        assert result["counts"]["iban"] == 1

    def test_soft_hyphen_stripped(self) -> None:
        result = scrub_text("NL91\u00adABNA0417164300")
        assert result["text"] == "[IBAN]"
        assert result["counts"]["iban"] == 1


class TestCreditCardSeparatorGaps:
    def test_dot_grouped(self) -> None:
        result = scrub_text("card 4111.1111.1111.1111")
        assert result["text"] == "card [CREDIT_CARD]"
        assert result["counts"]["credit_card"] == 1

    def test_newline_grouped(self) -> None:
        result = scrub_text("4111\n1111\n1111\n1111")
        assert result["text"] == "[CREDIT_CARD]"
        assert result["counts"]["credit_card"] == 1

    def test_unicode_dash_grouped(self) -> None:
        result = scrub_text("4111\u20131111\u20131111\u20131111")
        assert result["text"] == "[CREDIT_CARD]"
        assert result["counts"]["credit_card"] == 1

    def test_nbsp_grouped(self) -> None:
        result = scrub_text("4111\u00a01111\u00a01111\u00a01111")
        assert result["text"] == "[CREDIT_CARD]"
        assert result["counts"]["credit_card"] == 1

    def test_amex_dot_grouped(self) -> None:
        result = scrub_text("amex 3782.822463.10005 ok")
        assert result["text"] == "amex [CREDIT_CARD] ok"
        assert result["counts"]["credit_card"] == 1


class TestIpMapped:
    def test_ipv4_mapped_fully_masked(self) -> None:
        result = scrub_text("peer ::ffff:192.0.2.1 ok")
        assert result["text"] == "peer [IP] ok"
        assert result["counts"]["ip"] == 1
        assert "192" not in result["text"]
        assert "ffff" not in result["text"].lower()


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


class TestLocaleFormatVariants:
    def test_lowercase_license_plate(self) -> None:
        result = scrub_text("kenteken ab-12-cd gezien", languages=["nl"])
        assert result["text"] == "kenteken [LICENSE_PLATE] gezien"
        assert result["counts"]["license_plate"] == 1

    def test_spaced_vat(self) -> None:
        result = scrub_text("factuur NL 000099998 B57", languages=["nl"])
        assert result["text"] == "factuur [VAT_ID]"
        assert result["counts"]["vat_id"] == 1

    def test_dotted_vat(self) -> None:
        result = scrub_text("factuur NL.000099998.B.57", languages=["nl"])
        assert result["text"] == "factuur [VAT_ID]"
        assert result["counts"]["vat_id"] == 1

    def test_slash_nl_phone(self) -> None:
        result = scrub_text("reach 06/12345678 today", languages=["nl"])
        assert result["text"] == "reach [PHONE] today"
        assert result["counts"]["phone"] == 1


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

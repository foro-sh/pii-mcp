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

    def test_dot_separated_iban(self) -> None:
        result = scrub_text("Pay NL91.ABNA.0417.1643.00 please")
        assert result["text"] == "Pay [IBAN] please"
        assert result["counts"]["iban"] == 1
        assert result["counts"]["phone"] == 0

    def test_double_spaced_and_crlf_iban(self) -> None:
        assert scrub_text("NL91  ABNA  0417  1643  00")["text"] == "[IBAN]"
        assert scrub_text("NL91\r\nABNA\r\n0417\r\n1643\r\n00")["text"] == "[IBAN]"

    def test_unicode_space_iban_and_card(self) -> None:
        assert scrub_text("NL91\u2007ABNA\u20070417\u20071643\u200700")["text"] == "[IBAN]"
        assert scrub_text("4111\u20091111\u20091111\u20091111")["text"] == "[CREDIT_CARD]"
        assert scrub_text("4111\r\n1111\r\n1111\r\n1111")["text"] == "[CREDIT_CARD]"

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

    def test_slash_de_phone(self) -> None:
        result = scrub_text("ruf 030/12345678 heute", languages=["de"])
        assert result["text"] == "ruf [PHONE] heute"
        assert result["counts"]["phone"] == 1

    def test_spaced_and_dotted_ssn(self) -> None:
        assert scrub_text("ssn 078 05 1120", languages=["en"])["text"] == "ssn [SSN]"
        assert scrub_text("ssn 078.05.1120", languages=["en"])["text"] == "ssn [SSN]"

    def test_spaced_and_dotted_bsn(self) -> None:
        assert scrub_text("id 111 222 333", languages=["nl"])["text"] == "id [BSN]"
        assert scrub_text("id 111.222.333", languages=["nl"])["text"] == "id [BSN]"


class TestEmailIbanGlue:
    def test_email_tld_does_not_eat_iban(self) -> None:
        result = scrub_text("ada@example.comNL91ABNA0417164300")
        assert result["text"] == "[EMAIL][IBAN]"
        assert result["counts"]["email"] == 1
        assert result["counts"]["iban"] == 1

    def test_email_then_ssn_and_bsn(self) -> None:
        assert scrub_text("ada@example.com078-05-1120", languages=["en"])["text"] == (
            "[EMAIL][SSN]"
        )
        assert scrub_text("ada@example.com111222333", languages=["nl"])["text"] == (
            "[EMAIL][BSN]"
        )

    def test_email_then_ip_mac_location(self) -> None:
        assert scrub_text("ada@example.com192.0.2.1")["text"] == "[EMAIL][IP]"
        assert scrub_text("ada@example.com2001:db8::1")["text"] == "[EMAIL][IP]"
        assert scrub_text("ada@example.comaa:bb:cc:dd:ee:ff")["text"] == "[EMAIL][MAC]"
        assert scrub_text("ada@example.com52.3676,4.9041")["text"] == "[EMAIL][LOCATION]"

    def test_card_then_iban_glue(self) -> None:
        result = scrub_text("4111111111111111NL91ABNA0417164300")
        assert result["text"] == "[CREDIT_CARD][IBAN]"
        assert result["counts"]["credit_card"] == 1
        assert result["counts"]["iban"] == 1


class TestLocationDegree:
    def test_degree_symbol(self) -> None:
        result = scrub_text("pin 52.3676°, 4.9041° downtown")
        assert result["text"] == "pin [LOCATION] downtown"
        assert result["counts"]["location"] == 1

    def test_hemisphere_letters(self) -> None:
        assert scrub_text("52.3676 N, 4.9041 E")["text"] == "[LOCATION]"


class TestSsnSlash:
    def test_slash_separated(self) -> None:
        assert scrub_text("078/05/1120", languages=["en"])["text"] == "[SSN]"


class TestIpLeadingZeros:
    def test_padded_octets(self) -> None:
        assert scrub_text("host 192.168.001.001 ok")["text"] == "host [IP] ok"


class TestInvisibleSeparators:
    def test_zwsp_iban_and_card(self) -> None:
        assert scrub_text("NL91\u200bABNA0417164300")["text"] == "[IBAN]"
        assert scrub_text("4111\u200b1111\u200b1111\u200b1111")["text"] == "[CREDIT_CARD]"
        assert scrub_text("4111\u30001111\u30001111\u30001111")["text"] == "[CREDIT_CARD]"


class TestNanpNoSpaceAfterParen:
    def test_masks_compact_parens(self) -> None:
        assert scrub_text("(415)555-0132", languages=["en"])["text"] == "[PHONE]"
        assert scrub_text("1(415)555-0132", languages=["en"])["text"] == "[PHONE]"


class TestImeiDots:
    def test_dot_grouped_imei_not_phone(self) -> None:
        result = scrub_text("device 49.015420.323751.8 registered")
        assert result["text"] == "device [IMEI] registered"
        assert result["counts"]["imei"] == 1
        assert result["counts"]["phone"] == 0


class TestNanpLeadingOne:
    def test_masks_one_prefix(self) -> None:
        result = scrub_text("call 1-415-555-0132 now", languages=["en"])
        assert result["text"] == "call [PHONE] now"
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

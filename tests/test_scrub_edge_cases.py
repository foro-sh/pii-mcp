"""Edge-case probes for scrub_text: separator variants, false positives, skips."""

from __future__ import annotations

import pytest

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


class TestCleanProseNoRedaction:
    """Sentences without PII must stay untouched (false-positive guard)."""

    @pytest.mark.parametrize(
        "text",
        [
            "The server exposes a search tool and a fetch tool.",
            "Please review the quarterly report before Friday.",
            "We shipped version 2.0 with 500 units in 2024.",
            "Meeting at 10:30 tomorrow in conference room B.",
            "Call me back after lunch if you have time.",
            "Build number 41111111 is not a card.",
            "ISO code AAAAXX2A is not a real BIC.",
            "Temperature was 21.5 degrees Celsius today.",
            "The ratio 1.0, 2.0 looks like short decimals.",
            "Git commit a1b2c3d4e5f6 looks like hex but not MAC.",
            "UUID 550e8400-e29b-41d4-a716-446655440000 is fine.",
            "Port 8080 and process pid 12345 are fine.",
            "Chapter 12 section 34 paragraph 56 is prose.",
            "RGB color #aabbcc is not a MAC address.",
            "File path /usr/local/bin/python3 is fine.",
            "JSON key email_address has no value here.",
            "The word nl91abna is incomplete IBAN-ish.",
            "Score 12.34 out of 100 is not a location.",
            "Hello world, how are you doing today?",
            "The quick brown fox jumps over the lazy dog.",
            "Status code 404 means not found.",
            "HTTP 200 OK returned successfully.",
            "Package version 1.5.1 released yesterday.",
            "Thanks for your help with the deployment yesterday.",
            "Can you summarize the meeting notes from this morning?",
            "No personal data is present in this paragraph at all.",
            "Phone the office if needed — no number given.",
            "Email the team when ready — no address given.",
            "IBAN field left blank on the form.",
            "SSN section not applicable for EU residents.",
            "Passport photo uploaded without the number.",
            "License plate recognition failed on blurry image.",
            "The checksum failed for ticket 123456789.",
            "Ticket 111111111 is a repeated digit placeholder.",
        ],
    )
    def test_clean_sentence_unchanged(self, text: str) -> None:
        result = scrub_text(text)
        assert result["text"] == text
        assert result["found"] is False

    def test_sha256_digest_not_phone(self) -> None:
        text = (
            "sha256:0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef"
        )
        result = scrub_text(text)
        assert result["text"] == text
        assert result["counts"]["phone"] == 0


class TestDetectorPatternGaps:
    def test_paren_nl_mobile(self) -> None:
        result = scrub_text("bel (06)12345678 even", languages=["nl"])
        assert result["text"] == "bel [PHONE] even"
        assert result["counts"]["phone"] == 1

    def test_paren_spaced_nl_mobile(self) -> None:
        result = scrub_text("bel (06) 12345678 even", languages=["nl"])
        assert result["text"] == "bel [PHONE] even"
        assert result["counts"]["phone"] == 1

    def test_hyphen_grouped_bsn(self) -> None:
        result = scrub_text("id 111-222-333", languages=["nl"])
        assert result["text"] == "id [BSN]"
        assert result["counts"]["bsn"] == 1

    def test_fake_sequential_ssn_ignored(self) -> None:
        assert scrub_text("ticket 123456789", languages=["en"])["counts"]["ssn"] == 0
        assert scrub_text("ticket 987654321", languages=["en"])["counts"]["ssn"] == 0
        assert scrub_text("ticket 111111111", languages=["en"])["counts"]["ssn"] == 0

    def test_real_ssn_still_masked(self) -> None:
        result = scrub_text("ssn 078-05-1120 on file", languages=["en"])
        assert result["text"] == "ssn [SSN] on file"
        assert result["counts"]["ssn"] == 1

    def test_nl_phone_before_asap_still_masked(self) -> None:
        result = scrub_text("reach 0612345678 ASAP", languages=["nl"])
        assert result["text"] == "reach [PHONE] ASAP"
        assert result["counts"]["phone"] == 1

    def test_trunk_zero_international_not_ssn(self) -> None:
        result = scrub_text("bel +31(0)612345678", languages=["nl", "en"])
        assert result["text"] == "bel [PHONE]"
        assert result["counts"]["phone"] == 1
        assert result["counts"]["ssn"] == 0

    def test_dotted_ieee_mac_not_phone(self) -> None:
        result = scrub_text("mac 01.23.45.67.89.ab online")
        assert result["text"] == "mac [MAC] online"
        assert result["counts"]["mac"] == 1
        assert result["counts"]["phone"] == 0

    def test_slash_grouped_imei(self) -> None:
        result = scrub_text("imei 49/015420/323751/8 listed")
        assert result["text"] == "imei [IMEI] listed"
        assert result["counts"]["imei"] == 1
        assert result["counts"]["phone"] == 0

    def test_compressed_ipv6_with_mid_hextets(self) -> None:
        result = scrub_text("peer 2001:db8:85a3::8a2e:370:7334 ok")
        assert result["text"] == "peer [IP] ok"
        assert result["counts"]["ip"] == 1

    def test_double_spaced_postcode(self) -> None:
        result = scrub_text("post 1012  AB Amsterdam", languages=["nl"])
        assert result["text"] == "post [ADDRESS] Amsterdam"
        assert result["counts"]["address"] == 1

    def test_upc_not_de_phone(self) -> None:
        text = "UPC 036000291452"
        result = scrub_text(text, languages=["de"])
        assert result["text"] == text
        assert result["counts"]["phone"] == 0


class TestKnownFalsePositiveLimitations:
    """Document remaining high-recall collisions (not regressions to 'fix')."""

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


class TestIpEmbeddedAndLabelled:
    def test_nat64_embedded_ipv4_masked_whole(self) -> None:
        result = scrub_text("route 64:ff9b::192.0.2.33 ok")
        assert result["text"] == "route [IP] ok"
        assert result["counts"]["ip"] == 1

    def test_compat_embedded_ipv4_masked_whole(self) -> None:
        assert scrub_text("compat ::192.0.2.33")["text"] == "compat [IP]"

    def test_ipv4_after_label_colon(self) -> None:
        result = scrub_text("host:192.168.1.10 up, IP:10.20.30.40")
        assert result["text"] == "host:[IP] up, IP:[IP]"
        assert result["counts"]["ip"] == 2


class TestMacLabelColon:
    def test_mac_after_label_colon(self) -> None:
        result = scrub_text("mac:aa:bb:cc:dd:ee:ff")
        assert result["text"] == "mac:[MAC]"
        assert result["counts"]["mac"] == 1

    def test_seven_hex_groups_not_mac(self) -> None:
        text = "ab:aa:bb:cc:dd:ee:ff"
        assert scrub_text(text)["counts"]["mac"] == 0


class TestCreditCardGroupings:
    def test_nineteen_digit_grouped(self) -> None:
        result = scrub_text("unionpay 6212 3456 7890 1234 569 ok")
        assert result["text"] == "unionpay [CREDIT_CARD] ok"
        assert result["counts"]["credit_card"] == 1
        assert result["counts"]["phone"] == 0

    def test_diners_four_six_four(self) -> None:
        result = scrub_text("diners 3056 930902 5904 ok")
        assert result["text"] == "diners [CREDIT_CARD] ok"
        assert result["counts"]["phone"] == 0

    def test_leading_four_digit_group_does_not_hide_card(self) -> None:
        """A Luhn-failing 4-4-4-4 window starting one group early must not
        consume the real card."""
        result = scrub_text("exp 2027 4111 1111 1111 1111 ok")
        assert result["text"] == "exp 2027 [CREDIT_CARD] ok"
        assert result["counts"]["credit_card"] == 1


class TestCreditCardIssuerPrefix:
    @pytest.mark.parametrize(
        "text",
        [
            "ts 1695456789014",  # Luhn-valid ms timestamp
            "isbn 9780306406157",  # Luhn-valid ISBN-13
        ],
    )
    def test_luhn_valid_non_card_prefix_kept(self, text: str) -> None:
        assert scrub_text(text)["text"] == text

    def test_fifteen_digit_any_prefix_still_masked(self) -> None:
        """UATP (1…) and compact IMEIs stay covered."""
        assert scrub_text("uatp 122000000000003")["text"] == "uatp [CREDIT_CARD]"


class TestLocationSubUnitPairs:
    def test_embedding_vector_kept(self) -> None:
        text = "embedding [0.0123, -0.0456, 0.0789, 0.1011]"
        assert scrub_text(text)["text"] == text

    def test_real_coordinate_still_masked(self) -> None:
        assert scrub_text("at 52.3676, 4.9041")["text"] == "at [LOCATION]"

    def test_hemisphere_letter_not_glued_to_following_word(self) -> None:
        assert scrub_text("at 52.3676, 4.9041 exactly")["text"] == "at [LOCATION] exactly"



class TestNationalIdUnicodeSeparators:
    """Word processors swap the typed space / hyphen for nbsp or a unicode dash."""

    @pytest.mark.parametrize(
        "text",
        [
            "BSN 111 222 333",
            "BSN 111 222 333",
            "BSN 111–222–333",
        ],
    )
    def test_bsn_unicode_separators(self, text: str) -> None:
        result = scrub_text(text, languages=["nl"])
        assert result["text"] == "BSN [BSN]"
        assert result["counts"]["bsn"] == 1

    @pytest.mark.parametrize(
        "text",
        [
            "SSN 219–09–9999",
            "SSN 219‑09‑9999",
            "SSN 219−09−9999",
            "SSN 219 09 9999",
            "SSN 219 09 9999",
        ],
    )
    def test_ssn_unicode_separators(self, text: str) -> None:
        result = scrub_text(text, languages=["en"])
        assert result["text"] == "SSN [SSN]"
        assert result["counts"]["ssn"] == 1

    def test_mixed_dash_and_space_is_not_an_ssn(self) -> None:
        # A mixed dash / space shape is not one of the SSN groupings.
        assert scrub_text("pages 219–09 9999", languages=["en"])["counts"]["ssn"] == 0


class TestGroupedGermanTaxId:
    """Steuerbescheide and payslips print the IdNr as ``12 345 678 901``."""

    @pytest.mark.parametrize(
        "text",
        ["IdNr 86 095 742 719", "IdNr 86 095 742 719", "IdNr 86095742719"],
    )
    def test_grouped_tax_id(self, text: str) -> None:
        result = scrub_text(text, languages=["de"])
        assert result["text"] == "IdNr [TAX_ID]"
        assert result["counts"]["tax_id"] == 1

    def test_grouped_tax_id_wins_over_bsn_tail(self) -> None:
        # ``482 956 513`` alone passes the BSN elfproef.
        result = scrub_text("IdNr 57 482 956 513", languages=["nl", "de"])
        assert result["text"] == "IdNr [TAX_ID]"
        assert result["counts"]["bsn"] == 0

    def test_grouped_checksum_failure_kept(self) -> None:
        text = "IdNr 86 095 742 718"
        assert scrub_text(text, languages=["de"])["text"] == text


class TestPhoneSeparatorsAndTrunk:
    """Unicode group separators and the ``(0)`` trunk in international form."""

    @pytest.mark.parametrize(
        ("text", "languages"),
        [
            ("tel +31 6 12345678", ["nl"]),
            ("tel +31 6 1234‑5678", ["nl"]),
            ("tel +31–6–12345678", ["nl"]),
            ("tel 06 12345678", ["nl"]),
            ("tel 020–123 4567", ["nl"]),
            ("tel (555) 123–4567", ["en"]),
            ("tel 555 123 4567", ["en"]),
            ("tel 030 12345678", ["de"]),
            ("tel +44 (0) 20 7946 0958", ["en"]),
            ("tel +49 (0) 30 1234 5678", ["de"]),
        ],
    )
    def test_masked_whole(self, text: str, languages: list[str]) -> None:
        result = scrub_text(text, languages=languages)
        assert result["text"] == "tel [PHONE]"
        assert result["counts"]["phone"] == 1

    def test_back_to_back_numbers_split_at_group(self) -> None:
        result = scrub_text("0031 20 1234567 0031 20 7654321", languages=["nl"])
        assert result["text"] == "[PHONE] [PHONE]"
        assert result["counts"]["phone"] == 2

    def test_trailing_group_past_fifteen_digits_left(self) -> None:
        result = scrub_text("call +31 6 12345678 12345", languages=["en"])
        assert result["text"] == "call [PHONE] 12345"

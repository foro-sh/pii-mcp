"""Unit tests for scrub_text pattern detectors (ported from platform pii.test.ts)."""

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

    def test_masks_lowercase_spaced_before_phone(self) -> None:
        result = scrub_text("wire nl91 abna 0417 1643 00")
        assert result["text"] == "wire [IBAN]"
        assert result["counts"]["iban"] == 1
        assert result["counts"]["phone"] == 0

    def test_masks_iban_inside_a_rejected_candidate(self) -> None:
        """A greedy prefix that fails the checksum must not swallow the IBAN.

        The compact pattern starts at the hex digit before ``NL`` and yields
        ``bc4545667033NL09BSLW5753882578``, whose country code ``bc`` is not in
        the registry. Resuming at that match's end steps over the real IBAN
        starting eight characters inside it.
        """
        result = scrub_text("18:c0:50:92:da:be4+4bc4545667033NL09BSLW5753882578")
        assert result["text"] == "18:c0:50:92:da:be4+4bc4545667033[IBAN]"
        assert result["counts"]["iban"] == 1

    def test_masks_iban_after_a_pseudo_country_code(self) -> None:
        """Same shape with a passport-looking run in front of the real IBAN."""
        result = scrub_text("ac@LG180UU07GB89IWQY91132044634700")
        assert result["text"] == "ac@[PASSPORT][IBAN]"
        assert result["counts"]["iban"] == 1


class TestBic:
    def test_masks_8_char(self) -> None:
        result = scrub_text("swift ABNANL2A today")
        assert result["text"] == "swift [BIC] today"
        assert result["counts"]["bic"] == 1

    def test_masks_11_char(self) -> None:
        result = scrub_text("bic INGBNL2AXXX ok")
        assert result["text"] == "bic [BIC] ok"
        assert result["counts"]["bic"] == 1

    def test_rejects_unknown_country(self) -> None:
        result = scrub_text("code AAAAXX2A noted")
        assert result["counts"]["bic"] == 0


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

    def test_masks_amex_spaced(self) -> None:
        result = scrub_text("amex 3782 822463 10005 ok")
        assert result["text"] == "amex [CREDIT_CARD] ok"
        assert result["counts"]["credit_card"] == 1

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
        """100000009: valid BSN 11-check, SSN-invalid (group 00)."""
        result = scrub_text("BSN 100000009 on file", languages=["en"])
        assert result["text"] == "BSN 100000009 on file"
        assert result["counts"]["bsn"] == 0
        assert result["counts"]["ssn"] == 0

    def test_preferred_over_ssn_when_both_packs(self) -> None:
        result = scrub_text("id 111222333", languages=["en", "nl"])
        assert result["text"] == "id [BSN]"
        assert result["counts"]["bsn"] == 1
        assert result["counts"]["ssn"] == 0


class TestDeVat:
    @pytest.mark.parametrize("value", ["DE136695976", "DE 136 695 976", "DE.136.695.976"])
    def test_masks_valid_id(self, value: str) -> None:
        result = scrub_text(f"VAT {value} on file", languages=["de"])
        assert result["text"] == "VAT [VAT_ID] on file"
        assert result["counts"]["vat_id"] == 1

    @pytest.mark.parametrize(
        "value",
        [
            "DE136695977",
            "DE036695976",
            "de136695976",
            "xDE136695976",
            "DE136695976x",
        ],
    )
    def test_rejects_invalid_id(self, value: str) -> None:
        result = scrub_text(value, languages=["de"])
        assert result["text"] == value
        assert result["counts"]["vat_id"] == 0

    def test_disabled_without_de(self) -> None:
        result = scrub_text("DE136695976", languages=["en", "nl"])
        assert result["text"] == "DE136695976"
        assert result["counts"]["vat_id"] == 0

    def test_masks_in_json(self) -> None:
        result = scrub_text('{"vat":"DE136695976"}', languages=["de"])
        assert result["text"] == '{"vat":"[VAT_ID]"}'


class TestNlVat:
    def test_masks_btw_id(self) -> None:
        result = scrub_text("factuur NL000099998B57", languages=["nl"])
        assert result["text"] == "factuur [VAT_ID]"
        assert result["counts"]["vat_id"] == 1

    def test_masks_lowercased(self) -> None:
        result = scrub_text("btw nl001631457b01", languages=["nl"])
        assert result["text"] == "btw [VAT_ID]"
        assert result["counts"]["vat_id"] == 1

    def test_disabled_without_nl(self) -> None:
        result = scrub_text("factuur NL000099998B57", languages=["en"])
        assert result["text"] == "factuur NL000099998B57"
        assert result["counts"]["vat_id"] == 0


class TestNlPassport:
    def test_masks_document_number(self) -> None:
        result = scrub_text("paspoort XR1001R58 geldig", languages=["nl"])
        assert result["text"] == "paspoort [PASSPORT] geldig"
        assert result["counts"]["passport"] == 1

    def test_masks_lowercased(self) -> None:
        result = scrub_text("paspoort xr1001r58 geldig", languages=["nl"])
        assert result["text"] == "paspoort [PASSPORT] geldig"
        assert result["counts"]["passport"] == 1

    def test_rejects_letter_o(self) -> None:
        result = scrub_text("doc XR1O01R58", languages=["nl"])
        assert result["counts"]["passport"] == 0

    def test_rejects_wrong_shape(self) -> None:
        result = scrub_text("doc 581001RXR", languages=["nl"])
        assert result["counts"]["passport"] == 0

    def test_disabled_without_nl(self) -> None:
        result = scrub_text("paspoort XR1001R58 geldig", languages=["en"])
        assert result["text"] == "paspoort XR1001R58 geldig"
        assert result["counts"]["passport"] == 0


class TestSsn:
    def test_masks_hyphenated(self) -> None:
        result = scrub_text("ssn 078-05-1120 on file", languages=["en"])
        assert result["text"] == "ssn [SSN] on file"
        assert result["counts"]["ssn"] == 1

    def test_masks_compact(self) -> None:
        result = scrub_text("ssn 078051120 on file", languages=["en"])
        assert result["text"] == "ssn [SSN] on file"
        assert result["counts"]["ssn"] == 1

    def test_rejects_invalid_area(self) -> None:
        for bad in ("000-12-3456", "666-12-3456", "900-12-3456"):
            result = scrub_text(f"ref {bad}", languages=["en"])
            assert result["counts"]["ssn"] == 0, bad

    def test_rejects_invalid_group_or_serial(self) -> None:
        assert scrub_text("ref 123-00-1234", languages=["en"])["counts"]["ssn"] == 0
        assert scrub_text("ref 123-45-0000", languages=["en"])["counts"]["ssn"] == 0

    def test_disabled_without_en(self) -> None:
        result = scrub_text("ssn 078-05-1120 on file", languages=["nl"])
        assert result["text"] == "ssn 078-05-1120 on file"
        assert result["counts"]["ssn"] == 0


class TestItin:
    def test_masks_grouped(self) -> None:
        for value in ("912-70-1234", "900 50 1234", "999\u201394\u20130001"):
            result = scrub_text(f"itin {value} on file", languages=["en"])
            assert result["text"] == "itin [TAX_ID] on file", value
            assert result["counts"]["tax_id"] == 1
            assert result["counts"]["ssn"] == 0

    def test_masks_inside_json_and_csv(self) -> None:
        assert scrub_text('{"tin": "950-99-0001"}', languages=["en"])["text"] == (
            '{"tin": "[TAX_ID]"}'
        )
        assert scrub_text("a,912-70-1234,b", languages=["en"])["text"] == "a,[TAX_ID],b"

    def test_rejects_non_itin_group(self) -> None:
        for bad in ("912-49-1234", "912-66-1234", "912-89-1234", "912-93-1234"):
            result = scrub_text(f"ref {bad}", languages=["en"])
            assert result["counts"]["tax_id"] == 0, bad

    def test_ignores_compact_and_dotted(self) -> None:
        for value in ("912701234", "912.70.1234", "912/70/1234"):
            result = scrub_text(f"ref {value}", languages=["en"])
            assert result["text"] == f"ref {value}", value

    def test_disabled_without_en(self) -> None:
        result = scrub_text("itin 912-70-1234", languages=["nl"])
        assert result["counts"]["tax_id"] == 0


class TestTaxId:
    def test_masks_valid_idnr(self) -> None:
        result = scrub_text("IdNr 36574261809 gespeichert", languages=["de"])
        assert result["text"] == "IdNr [TAX_ID] gespeichert"
        assert result["counts"]["tax_id"] == 1

    def test_rejects_bad_checksum(self) -> None:
        result = scrub_text("IdNr 36574261890", languages=["de"])
        assert result["counts"]["tax_id"] == 0

    def test_rejects_leading_zero(self) -> None:
        result = scrub_text("IdNr 01234567897", languages=["de"])
        assert result["counts"]["tax_id"] == 0

    def test_disabled_without_de(self) -> None:
        result = scrub_text("IdNr 36574261809", languages=["en"])
        assert result["text"] == "IdNr 36574261809"
        assert result["counts"]["tax_id"] == 0


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

    def test_masks_german_national(self) -> None:
        result = scrub_text("ruf 030 12345678 oder 0151 23456789", languages=["de"])
        assert result["text"] == "ruf [PHONE] oder [PHONE]"
        assert result["counts"]["phone"] == 2

    def test_ignores_year(self) -> None:
        result = scrub_text("in 2024 we shipped 500 units")
        assert result["found"] is False

    def test_ignores_ip_as_phone(self) -> None:
        result = scrub_text("host at 192.168.0.1 responds")
        assert result["counts"]["phone"] == 0
        assert result["counts"]["ip"] == 1
        assert result["text"] == "host at [IP] responds"

    def test_en_pack_skips_dutch_national(self) -> None:
        result = scrub_text("reach 0612345678", languages=["en"])
        assert result["counts"]["phone"] == 0

    def test_nl_pack_skips_nanp(self) -> None:
        result = scrub_text("call 415-555-0132", languages=["nl"])
        assert result["counts"]["phone"] == 0

    def test_de_pack_skips_nanp_and_nl(self) -> None:
        assert scrub_text("call 415-555-0132", languages=["de"])["counts"]["phone"] == 0
        assert scrub_text("reach 0612345678", languages=["de"])["counts"]["phone"] == 0

    def test_en_pack_skips_german_national(self) -> None:
        result = scrub_text("ruf 03012345678", languages=["en"])
        assert result["counts"]["phone"] == 0


class TestIp:
    def test_masks_ipv4(self) -> None:
        result = scrub_text("client 203.0.113.42 connected")
        assert result["text"] == "client [IP] connected"
        assert result["counts"]["ip"] == 1

    def test_masks_private_ipv4(self) -> None:
        result = scrub_text("bind 10.0.0.1 and 192.168.1.1")
        assert result["text"] == "bind [IP] and [IP]"
        assert result["counts"]["ip"] == 2

    def test_rejects_octet_out_of_range(self) -> None:
        result = scrub_text("bad 999.1.1.1 address")
        assert result["counts"]["ip"] == 0

    def test_masks_ipv6_full(self) -> None:
        result = scrub_text("peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334 ok")
        assert result["text"] == "peer [IP] ok"
        assert result["counts"]["ip"] == 1

    def test_masks_ipv6_compressed(self) -> None:
        result = scrub_text("loopback ::1 and docs 2001:db8::1")
        assert result["text"] == "loopback [IP] and docs [IP]"
        assert result["counts"]["ip"] == 2

    def test_ignores_time_like_colons(self) -> None:
        result = scrub_text("meeting at 10:30 tomorrow")
        assert result["counts"]["ip"] == 0


class TestMac:
    def test_masks_colon_form(self) -> None:
        result = scrub_text("sta aa:bb:cc:dd:ee:ff associated")
        assert result["text"] == "sta [MAC] associated"
        assert result["counts"]["mac"] == 1

    def test_masks_dash_form(self) -> None:
        result = scrub_text("nic AA-BB-CC-DD-EE-FF up")
        assert result["text"] == "nic [MAC] up"
        assert result["counts"]["mac"] == 1

    def test_masks_cisco_dotted(self) -> None:
        result = scrub_text("host aabb.ccdd.eeff online")
        assert result["text"] == "host [MAC] online"
        assert result["counts"]["mac"] == 1

    def test_does_not_eat_ipv6(self) -> None:
        result = scrub_text("peer 2001:db8::1 ok")
        assert result["counts"]["mac"] == 0
        assert result["counts"]["ip"] == 1


class TestImei:
    def test_masks_hyphen_grouped(self) -> None:
        result = scrub_text("device 49-015420-323751-8 registered")
        assert result["text"] == "device [IMEI] registered"
        assert result["counts"]["imei"] == 1

    def test_masks_space_grouped(self) -> None:
        result = scrub_text("imei 49 015420 323751 8 ok")
        assert result["text"] == "imei [IMEI] ok"
        assert result["counts"]["imei"] == 1

    def test_masks_8_6_1(self) -> None:
        result = scrub_text("tac 49015420-323751-8 listed")
        assert result["text"] == "tac [IMEI] listed"
        assert result["counts"]["imei"] == 1

    def test_rejects_bad_luhn(self) -> None:
        result = scrub_text("device 49-015420-323751-9 registered")
        assert result["counts"]["imei"] == 0

    def test_compact_stays_under_credit_card(self) -> None:
        """Bare 15-digit Luhn collides with Amex; credit_card owns compact form."""
        result = scrub_text("amex 378282246310005 charged")
        assert result["counts"]["credit_card"] == 1
        assert result["counts"]["imei"] == 0


class TestLocation:
    def test_masks_amsterdam_coords(self) -> None:
        result = scrub_text("pin 52.3676, 4.9041 downtown")
        assert result["text"] == "pin [LOCATION] downtown"
        assert result["counts"]["location"] == 1

    def test_masks_negative_lon(self) -> None:
        result = scrub_text("at 40.7128, -74.0060 now")
        assert result["text"] == "at [LOCATION] now"
        assert result["counts"]["location"] == 1

    def test_rejects_out_of_range(self) -> None:
        result = scrub_text("bad 91.0000, 4.9041 coords")
        assert result["counts"]["location"] == 0

    def test_ignores_short_decimals(self) -> None:
        result = scrub_text("versions 1.0, 2.0 shipped")
        assert result["counts"]["location"] == 0

    def test_masks_the_first_valid_pair_not_the_leftmost(self) -> None:
        """A rejected pair must not hand the scan an overlapping window.

        ``0.5741, -0.9633`` is the leftmost match but both components are
        within 1.0, so it is open ocean / an embedding vector. The scan
        resumes after the rejected match, so the overlapping window
        ``-0.9633,-37.45816`` is never considered and ``-37.45816,41.605875``
        is masked.
        """
        result = scrub_text("scale 0.5741, -0.9633,-37.45816,41.605875")
        assert result["text"] == "scale 0.5741, -0.9633,[LOCATION]"
        assert result["counts"]["location"] == 1


class TestNlPostcode:
    def test_masks_spaced(self) -> None:
        result = scrub_text("woonachtig te 1012 AB Amsterdam", languages=["nl"])
        assert result["text"] == "woonachtig te [ADDRESS] Amsterdam"
        assert result["counts"]["address"] == 1

    def test_masks_compact(self) -> None:
        result = scrub_text("postcode 2511VA", languages=["nl"])
        assert result["text"] == "postcode [ADDRESS]"
        assert result["counts"]["address"] == 1

    def test_ignores_lowercase_letters(self) -> None:
        """Uppercase letters only — avoids year/word false positives."""
        result = scrub_text("in 2024 we shipped; ssn 078-05-1120 on file", languages=["nl"])
        assert result["counts"]["address"] == 0
        assert "2024 we" in result["text"]
        assert "1120 on" in result["text"]

    def test_rejects_sa_sd_ss(self) -> None:
        for letters in ("SA", "SD", "SS"):
            result = scrub_text(f"code 1234 {letters}", languages=["nl"])
            assert result["counts"]["address"] == 0, letters

    def test_disabled_without_nl(self) -> None:
        result = scrub_text("woonachtig te 1012 AB Amsterdam", languages=["en"])
        assert result["text"] == "woonachtig te 1012 AB Amsterdam"
        assert result["counts"]["address"] == 0


class TestUkPostcode:
    @pytest.mark.parametrize(
        "value",
        [
            "M1 1AE",  # A9
            "B33 8TH",  # A99
            "W1A 0AX",  # A9A
            "SW1A 1AA",  # AA9A
            "NW1 6XE",  # AA9
            "GU30 7RS",  # AA99
            "E1W 1AA",  # AA9A
            "JE2 3AA",  # Channel Islands
            "GY1 1AA",
            "ZE1 0AA",  # Shetland
            "NR1 3PS",
            "EC1A 1BB",
        ],
    )
    def test_masks_every_outward_shape(self, value: str) -> None:
        result = scrub_text(f"postcode {value}", languages=["en"])
        assert result["text"] == "postcode [ADDRESS]"
        assert result["counts"]["address"] == 1

    def test_masks_the_non_geographic_outward_code(self) -> None:
        result = scrub_text("GIR 0AA", languages=["en"])
        assert result["text"] == "[ADDRESS]"
        assert result["counts"]["address"] == 1

    def test_masks_across_whitespace_runs(self) -> None:
        for separator in (" ", "  ", "\t", "\u00a0", "\u202f"):
            value = f"postcode NW1{separator}6XE"
            result = scrub_text(value, languages=["en"])
            assert result["text"] == "postcode [ADDRESS]", repr(separator)
            assert result["counts"]["address"] == 1, repr(separator)

    def test_masks_postcode_after_a_street_address(self) -> None:
        result = scrub_text(
            "Ship to 221B Baker Street, London NW1 6XE", languages=["en"]
        )
        assert result["text"] == "Ship to [ADDRESS], London [ADDRESS]"
        assert result["counts"]["address"] == 2

    def test_masks_inside_json(self) -> None:
        result = scrub_text(
            '{"postcode": "EC1A 1BB", "city": "London"}', languages=["en"]
        )
        assert result["text"] == '{"postcode": "[ADDRESS]", "city": "London"}'

    def test_masks_inside_csv(self) -> None:
        result = scrub_text("id,SW1A 1AA,2024-01-15,active", languages=["en"])
        assert result["text"] == "id,[ADDRESS],2024-01-15,active"

    @pytest.mark.parametrize(
        "value",
        [
            "_NW1 6XE",
            "NW1 6XE_",
            "__NW1 6XE__",
            "\u00e9NW1 6XE",
            "NW1 6XE\u00e9",
            "\u0416NW1 6XE",
            "NW1 6XE\u0663",
        ],
    )
    def test_masks_when_the_neighbour_is_not_ascii_alphanumeric(
        self, value: str
    ) -> None:
        """Boundary is ``(?<![A-Za-z0-9])``, not ``\\b``, in every backend."""
        result = scrub_text(value, languages=["en"])
        assert result["counts"]["address"] == 1, value
        assert "[ADDRESS]" in result["text"], value

    @pytest.mark.parametrize("value", ["A4 2PK", "PS5 1TB", "A1 2PK"])
    def test_rejects_areas_that_do_not_exist(self, value: str) -> None:
        result = scrub_text(f"part {value} in stock", languages=["en"])
        assert result["counts"]["address"] == 0, value
        assert value in result["text"]

    @pytest.mark.parametrize(
        "value",
        [
            "AB12C 3DE",
            "M12C 3DE",
            "LA23J 2DX",
            "SW123 4AB",
        ],
    )
    def test_rejects_outward_shapes_that_do_not_exist(self, value: str) -> None:
        result = scrub_text(f"order {value} shipped", languages=["en"])
        assert result["counts"]["address"] == 0, value

    @pytest.mark.parametrize(
        "value",
        [
            "NW16XE",
            "nw1 6xe",
            "XNW1 6XE",
            "1NW1 6XE",
            "NW1 6XEa",
        ],
    )
    def test_ignores_out_of_scope_shapes(self, value: str) -> None:
        result = scrub_text(f"ref {value} end", languages=["en"])
        assert result["counts"]["address"] == 0, value

    def test_disabled_without_en(self) -> None:
        result = scrub_text("postcode NW1 6XE", languages=["nl"])
        assert result["text"] == "postcode NW1 6XE"
        assert result["counts"]["address"] == 0


class TestStreetAddress:
    @pytest.mark.parametrize(
        ("text", "lang", "expected"),
        [
            ("woont op Kerkstraat 12, 1234 AB Amsterdam", "nl", "woont op [ADDRESS], [ADDRESS] Amsterdam"),
            ("adres: Van Baerlestraat 12-3.", "nl", "adres: [ADDRESS]."),
            ("Sint-Jansstraat 4a", "nl", "[ADDRESS]"),
            ("ship to 221B Baker Street, London", "en", "ship to [ADDRESS], London"),
            ("1600 Pennsylvania Avenue NW", "en", "[ADDRESS] NW"),
            ("at 10 Downing St. today", "en", "at [ADDRESS] today"),
            ("12 Baker Street Station", "en", "[ADDRESS] Station"),
            ("Hauptstraße 5a, 10115 Berlin", "de", "[ADDRESS], 10115 Berlin"),
            ("Kölner Str. 5", "de", "[ADDRESS]"),
            ("Frankfurter Allee 12", "de", "[ADDRESS]"),
            ("Johann-Sebastian-Bach-Straße 5", "de", "[ADDRESS]"),
            ("Kaiser-Wilhelm-Platz 3", "de", "[ADDRESS]"),
            ("Hauptstr.5, Berlin", "de", "[ADDRESS], Berlin"),
            ("Kerkstraat  12", "nl", "[ADDRESS]"),
            ("Kerkstraat\t12", "nl", "[ADDRESS]"),
            ("Kerkstraat\u202f12", "nl", "[ADDRESS]"),
            ("Kerkstraat 12bis", "nl", "[ADDRESS]"),
            ("ship to 221-223 Baker Street", "en", "ship to [ADDRESS]"),
            ("Berliner\u00a0Straße 17", "de", "[ADDRESS]"),
            ("Berliner  Straße 17", "de", "[ADDRESS]"),
            ("Der Hauptstraße 5", "de", "Der [ADDRESS]"),
            ("Nieuwmarkt 4", "nl", "[ADDRESS]"),
            ("Binnenhof 1", "nl", "[ADDRESS]"),
            ("Jaagpad 3", "nl", "[ADDRESS]"),
            ("Reichpietschufer 60", "de", "[ADDRESS]"),
            ("Grote Markt 1", "nl", "[ADDRESS]"),
            ("Oude Gracht 12", "nl", "[ADDRESS]"),
            ("Laan van Meerdervoort 52", "nl", "[ADDRESS]"),
            ("Laan van Nieuw Oost-Indië 5", "nl", "[ADDRESS]"),
            ("Hohenzollernring 12", "de", "[ADDRESS]"),
            ("Kerkstraat nr. 12", "nl", "[ADDRESS]"),
            ("Kerkstr. 12", "nl", "[ADDRESS]"),
            ("Hauptstraße Nr. 5", "de", "[ADDRESS]"),
            ("123 Main Dr", "en", "[ADDRESS]"),
            ("5 Elm Ct.", "en", "[ADDRESS]"),
            ("12 Park Row", "en", "[ADDRESS]"),
            ("lives at 221B Baker Street.", "en", "lives at [ADDRESS]."),
            ("Birkhahnstraße, 676", "de", "[ADDRESS]"),
            ("Adresse: Kerkstraat, 12", "nl", "Adresse: [ADDRESS]"),
            ("518, Hollywater Road, Liphook", "en", "[ADDRESS], Liphook"),
            ("474, Lexington Drive, Colorado Springs", "en", "[ADDRESS], Colorado Springs"),
            ("Kerkstraat,\u00a012", "nl", "[ADDRESS]"),
            ("Kerkstraat,  12", "nl", "[ADDRESS]"),
            ("Hauptstr., 12", "de", "[ADDRESS]"),
            ("Berliner Straße, 17", "de", "[ADDRESS]"),
            ("Laan van Meerdervoort, 52", "nl", "[ADDRESS]"),
            ("Kerkstraat, nr. 12", "nl", "[ADDRESS]"),
            ("221B, Baker Street", "en", "[ADDRESS]"),
        ],
    )
    def test_masks_street_and_house_number(self, text: str, lang: str, expected: str) -> None:
        result = scrub_text(text, languages=[lang])
        assert result["text"] == expected
        assert result["counts"]["address"] == expected.count("[ADDRESS]")

    @pytest.mark.parametrize(
        ("text", "lang", "expected"),
        [
            ("Chapter 12, Main Street", "en", "Chapter [ADDRESS]"),
            ("Sections 3, Park Lane and 4", "en", "Sections [ADDRESS] and 4"),
            ("Kerkstraat, 2024", "nl", "[ADDRESS]"),
        ],
    )
    def test_comma_form_over_masks_like_the_comma_less_form(
        self, text: str, lang: str, expected: str
    ) -> None:
        """A street word plus a number is masked whichever separator joins them.

        Rejecting a year here would have to reject ``Kerkstraat 2024`` too,
        which leaks four-digit house numbers. Recall comes first.
        """
        assert scrub_text(text.replace(",", ""), languages=[lang])["counts"]["address"] == 1
        assert scrub_text(text, languages=[lang])["text"] == expected

    def test_csv_comma_is_a_field_separator(self) -> None:
        """A comma needs a space behind it, so CSV columns are not house numbers.

        Without the space rule, a bare street name in one column takes the next
        column's date as its number (``id,Kerkstraat,2024-01-15`` ->
        ``id,[ADDRESS]-15``), which the ``street_name`` clean samples forbid.
        """
        csv = "id,Kerkstraat,2024-01-15,active"
        assert scrub_text(csv, languages=["nl"])["text"] == csv
        assert scrub_text("Kerkstraat, 12", languages=["nl"])["counts"]["address"] == 1

    @pytest.mark.parametrize(
        ("text", "lang"),
        [
            ("de Kerkstraat is afgesloten", "nl"),
            ("Mr Baker Street", "en"),
            ("Amsterdam 2024", "nl"),
            ("Hier Platz 5", "de"),
            ("Wieder Platz 2 für Bayern", "de"),
            ("Der Weg 3 ist frei", "de"),
            ("Oder Ring 3", "de"),
            ("The Park 12 tickets", "nl"),
            ("Theme Park 2 opens", "nl"),
            ("Safe Haven 3 is out", "nl"),
            ("took 12 Main Streetcar", "en"),
            ("Auf Platz 3 landete", "de"),
            ("Spring 2024", "de"),
            ("3 new road maps", "en"),
            ("Foo, 12", "nl"),
            ("Foo, 12", "de"),
            ("12, Foo", "en"),
            ("de Kerkstraat, afgesloten", "nl"),
            ("Kerkstraat,12", "nl"),
            ("Birkhahnstraße,676", "de"),
            ("id,518,Hollywater Road,x", "en"),
        ],
    )
    def test_ignores_bare_names_and_lookalikes(self, text: str, lang: str) -> None:
        result = scrub_text(text, languages=[lang])
        assert result["text"] == text
        assert result["counts"]["address"] == 0

    def test_gated_by_language_pack(self) -> None:
        assert scrub_text("Kerkstraat 12", languages=["en"])["counts"]["address"] == 0
        assert scrub_text("12 Baker Street", languages=["nl"])["counts"]["address"] == 0
        assert scrub_text("Hauptstraße 5", languages=["en", "nl"])["counts"]["address"] == 0

    def test_long_capitalized_run_is_linear(self) -> None:
        text = "Aaaa " * 50_000 + "a" * 100_000
        started = time.perf_counter()
        scrub_text(text, languages=["en", "nl", "de"])
        assert time.perf_counter() - started < 5


class TestNlLicensePlate:
    def test_masks_sidecode_4(self) -> None:
        result = scrub_text("auto X-123-YZ wacht, kenteken AB-12-CD gezien", languages=["nl"])
        assert result["text"] == "auto [LICENSE_PLATE] wacht, kenteken [LICENSE_PLATE] gezien"
        assert result["counts"]["license_plate"] == 2

    def test_masks_sidecode_6(self) -> None:
        result = scrub_text("plaat 12-AB-CD geparkeerd", languages=["nl"])
        assert result["text"] == "plaat [LICENSE_PLATE] geparkeerd"
        assert result["counts"]["license_plate"] == 1

    def test_rejects_sa_sd_ss(self) -> None:
        for plate in ("12-SA-34", "AB-SD-12", "12-SS-AB"):
            result = scrub_text(f"ref {plate}", languages=["nl"])
            assert result["counts"]["license_plate"] == 0, plate

    def test_disabled_without_nl(self) -> None:
        result = scrub_text("kenteken AB-12-CD gezien", languages=["en"])
        assert result["text"] == "kenteken AB-12-CD gezien"
        assert result["counts"]["license_plate"] == 0


class TestMultiple:
    def test_masks_together(self) -> None:
        result = scrub_text("mail ada@example.com or card 4111111111111111")
        assert result["text"] == "mail [EMAIL] or card [CREDIT_CARD]"
        assert result["counts"] == {
            "email": 1,
            "iban": 0,
            "credit_card": 1,
            "bic": 0,
            "mac": 0,
            "imei": 0,
            "ip": 0,
            "location": 0,
            "bsn": 0,
            "ssn": 0,
            "tax_id": 0,
            "vat_id": 0,
            "passport": 0,
            "phone": 0,
            "person": 0,
            "address": 0,
            "license_plate": 0,
        }

    def test_detector_order_card_not_phone(self) -> None:
        result = scrub_text("card 4111111111111111")
        assert result["text"] == "card [CREDIT_CARD]"
        assert result["counts"]["phone"] == 0
        assert result["counts"]["bsn"] == 0


class TestSizeCap:
    def test_oversize_fails_closed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import pii_mcp.scrub as scrub_mod

        monkeypatch.setenv("PII_MCP_BACKEND", "python")
        original = scrub_mod.MAX_SCRUB_BYTES
        scrub_mod.MAX_SCRUB_BYTES = 64
        try:
            with pytest.raises(PiiScrubError, match="size cap"):
                scrub_text("x" * 100)
        finally:
            scrub_mod.MAX_SCRUB_BYTES = original

    def test_unknown_language(self) -> None:
        with pytest.raises(ValueError, match="unknown language"):
            scrub_text("hi", languages=["fr"])

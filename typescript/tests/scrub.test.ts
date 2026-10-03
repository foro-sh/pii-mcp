import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { emailDetector } from "../src/detectors.js";
import { resetNativeCache } from "../src/native.js";
import {
  PiiScrubError,
  scrubPayload,
  scrubText,
  usingNative,
} from "../src/scrub.js";

const originalBackend = process.env.PII_MCP_BACKEND;

beforeEach(() => {
  // Preserve an explicit native/js override from the test runner (CI).
  if (originalBackend === undefined) {
    process.env.PII_MCP_BACKEND = "js";
  } else {
    process.env.PII_MCP_BACKEND = originalBackend;
  }
  resetNativeCache();
});

afterEach(() => {
  if (originalBackend === undefined) {
    delete process.env.PII_MCP_BACKEND;
  } else {
    process.env.PII_MCP_BACKEND = originalBackend;
  }
  resetNativeCache();
});

describe("scrubText", () => {
  it("leaves clean text", () => {
    const result = scrubText(
      "The server exposes a search tool and a fetch tool.",
    );
    expect(result.text).toBe(
      "The server exposes a search tool and a fetch tool.",
    );
    expect(result.found).toBe(false);
    expect(result.counts.email).toBe(0);
  });

  it("masks email, iban, and card", () => {
    const result = scrubText(
      "mail ada@example.com pay NL91ABNA0417164300 card 4111111111111111",
    );
    expect(result.text).toBe("mail [EMAIL] pay [IBAN] card [CREDIT_CARD]");
    expect(result.counts.email).toBe(1);
    expect(result.counts.iban).toBe(1);
    expect(result.counts.credit_card).toBe(1);
  });

  it("masks dashed and mixed-case spaced IBANs", () => {
    const dashed = scrubText("Pay NL91-ABNA-0417-1643-00 please");
    expect(dashed.text).toBe("Pay [IBAN] please");
    expect(dashed.counts.iban).toBe(1);
    expect(dashed.counts.phone).toBe(0);

    const mixed = scrubText("Pay Nl91 AbNa 0417 1643 00 please");
    expect(mixed.text).toBe("Pay [IBAN] please");
    expect(mixed.counts.iban).toBe(1);

    const slash = scrubText("Pay NL91/ABNA/0417/1643/00 please");
    expect(slash.text).toBe("Pay [IBAN] please");
    expect(slash.counts.iban).toBe(1);
  });

  it("masks an IBAN inside a rejected greedy candidate", () => {
    const hex = scrubText("18:c0:50:92:da:be4+4bc4545667033NL09BSLW5753882578");
    expect(hex.text).toBe("18:c0:50:92:da:be4+4bc4545667033[IBAN]");
    expect(hex.counts.iban).toBe(1);

    const passport = scrubText("ac@LG180UU07GB89IWQY91132044634700");
    expect(passport.text).toBe("ac@[PASSPORT][IBAN]");
    expect(passport.counts.iban).toBe(1);
  });

  it("masks glued emails as two hits", () => {
    const result = scrubText("a@b.comc@d.com");
    expect(result.text).toBe("[EMAIL][EMAIL]");
    expect(result.counts.email).toBe(2);
  });

  it("masks dotted cards, mapped IPs, spaced VAT, and lowercase plates", () => {
    expect(scrubText("card 4111.1111.1111.1111").text).toBe("card [CREDIT_CARD]");
    expect(scrubText("peer ::ffff:192.0.2.1 ok").text).toBe("peer [IP] ok");
    expect(scrubText("factuur NL 000099998 B57", { languages: ["nl"] }).text).toBe(
      "factuur [VAT_ID]",
    );
    expect(scrubText("kenteken ab-12-cd", { languages: ["nl"] }).text).toBe(
      "kenteken [LICENSE_PLATE]",
    );
    expect(scrubText("reach 06/12345678", { languages: ["nl"] }).text).toBe(
      "reach [PHONE]",
    );
  });

  it("masks dotted IBAN, email+IBAN glue, spaced SSN/BSN, and dotted IMEI", () => {
    expect(scrubText("NL91.ABNA.0417.1643.00").text).toBe("[IBAN]");
    expect(scrubText("ada@example.comNL91ABNA0417164300").text).toBe(
      "[EMAIL][IBAN]",
    );
    expect(scrubText("078 05 1120", { languages: ["en"] }).text).toBe("[SSN]");
    expect(scrubText("111.222.333", { languages: ["nl"] }).text).toBe("[BSN]");
    expect(scrubText("49.015420.323751.8").text).toBe("[IMEI]");
    expect(scrubText("1-415-555-0132", { languages: ["en"] }).text).toBe("[PHONE]");
  });

  it("masks card|IBAN glue, email|SSN glue, degree location, compact NANP, double-spaced IBAN", () => {
    expect(scrubText("4111111111111111NL91ABNA0417164300").text).toBe(
      "[CREDIT_CARD][IBAN]",
    );
    expect(scrubText("ada@example.com078-05-1120", { languages: ["en"] }).text).toBe(
      "[EMAIL][SSN]",
    );
    expect(scrubText("52.3676°, 4.9041°").text).toBe("[LOCATION]");
    expect(scrubText("(415)555-0132", { languages: ["en"] }).text).toBe("[PHONE]");
    expect(scrubText("NL91  ABNA  0417  1643  00").text).toBe("[IBAN]");
  });

  it("masks email|IP/MAC/location glue, slash SSN, padded IP, hemisphere location", () => {
    expect(scrubText("ada@example.com192.0.2.1").text).toBe("[EMAIL][IP]");
    expect(scrubText("ada@example.comaa:bb:cc:dd:ee:ff").text).toBe("[EMAIL][MAC]");
    expect(scrubText("ada@example.com52.3676,4.9041").text).toBe(
      "[EMAIL][LOCATION]",
    );
    expect(scrubText("078/05/1120", { languages: ["en"] }).text).toBe("[SSN]");
    expect(scrubText("192.168.001.001").text).toBe("[IP]");
    expect(scrubText("52.3676 N, 4.9041 E").text).toBe("[LOCATION]");
    expect(scrubText("NL91\u200bABNA0417164300").text).toBe("[IBAN]");
  });

  it("masks embedded-IPv4 IPv6 whole and IPv4 after a label colon", () => {
    expect(scrubText("route 64:ff9b::192.0.2.33 ok").text).toBe("route [IP] ok");
    expect(scrubText("compat ::192.0.2.33").text).toBe("compat [IP]");
    expect(scrubText("host:192.168.1.10 up, IP:10.20.30.40").text).toBe(
      "host:[IP] up, IP:[IP]",
    );
  });

  it("masks MAC after a label colon but not a slice of a longer hex run", () => {
    expect(scrubText("mac:aa:bb:cc:dd:ee:ff").text).toBe("mac:[MAC]");
    expect(scrubText("ab:aa:bb:cc:dd:ee:ff").counts.mac).toBe(0);
  });

  it("masks 19-digit and Diners card groupings and cards after a 4-digit group", () => {
    expect(scrubText("unionpay 6212 3456 7890 1234 569 ok").text).toBe(
      "unionpay [CREDIT_CARD] ok",
    );
    expect(scrubText("diners 3056 930902 5904 ok").text).toBe("diners [CREDIT_CARD] ok");
    expect(scrubText("exp 2027 4111 1111 1111 1111 ok").text).toBe(
      "exp 2027 [CREDIT_CARD] ok",
    );
  });

  it("keeps Luhn-valid numbers without a card issuer prefix", () => {
    expect(scrubText("ts 1695456789014").text).toBe("ts 1695456789014");
    expect(scrubText("isbn 9780306406157").text).toBe("isbn 9780306406157");
    expect(scrubText("uatp 122000000000003").text).toBe("uatp [CREDIT_CARD]");
  });

  it("keeps sub-unit decimal pairs and ends a location before a following word", () => {
    const vec = "embedding [0.0123, -0.0456, 0.0789, 0.1011]";
    expect(scrubText(vec).text).toBe(vec);
    expect(scrubText("at 52.3676, 4.9041 exactly").text).toBe("at [LOCATION] exactly");
  });

  it("masks BSN with nl pack and prefers it over SSN", () => {
    const result = scrubText("id 111222333", { languages: ["en", "nl"] });
    expect(result.text).toBe("id [BSN]");
    expect(result.counts.bsn).toBe(1);
    expect(result.counts.ssn).toBe(0);
  });

  it("skips BSN without nl", () => {
    const result = scrubText("BSN 100000009 on file", { languages: ["en"] });
    expect(result.text).toBe("BSN 100000009 on file");
    expect(result.counts.bsn).toBe(0);
  });

  it("masks SSN with en pack", () => {
    const result = scrubText("ssn 078-05-1120 on file", { languages: ["en"] });
    expect(result.text).toBe("ssn [SSN] on file");
    expect(result.counts.ssn).toBe(1);
  });

  it("masks grouped US ITIN as tax_id with en pack", () => {
    for (const value of [
      "912-70-1234",
      "900 50 1234",
      "999\u201394\u20130001",
    ]) {
      const result = scrubText(`itin ${value} on file`, { languages: ["en"] });
      expect(result.text).toBe("itin [TAX_ID] on file");
      expect(result.counts.tax_id).toBe(1);
      expect(result.counts.ssn).toBe(0);
    }
    expect(
      scrubText('{"tin": "950-99-0001"}', { languages: ["en"] }).text,
    ).toBe('{"tin": "[TAX_ID]"}');
  });

  it("leaves non-ITIN groups and compact 9xx digits alone", () => {
    for (const value of [
      "912-89-1234",
      "912-93-1234",
      "912701234",
      "912.70.1234",
    ]) {
      const text = `ref ${value}`;
      expect(scrubText(text, { languages: ["en"] }).text).toBe(text);
    }
  });

  it("masks German tax id with de pack", () => {
    const result = scrubText("IdNr 36574261809 gespeichert", {
      languages: ["de"],
    });
    expect(result.text).toBe("IdNr [TAX_ID] gespeichert");
    expect(result.counts.tax_id).toBe(1);
  });

  it("leaves clean prose without redacting", () => {
    const samples = [
      "Please review the quarterly report before Friday.",
      "Meeting at 10:30 tomorrow in conference room B.",
      "No personal data is present in this paragraph at all.",
      "The checksum failed for ticket 123456789.",
      "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ];
    for (const text of samples) {
      const result = scrubText(text);
      expect(result.text).toBe(text);
      expect(result.found).toBe(false);
    }
  });

  it("masks parenthesized NL mobile and hyphen BSN", () => {
    expect(scrubText("bel (06)12345678 even", { languages: ["nl"] }).text).toBe(
      "bel [PHONE] even",
    );
    expect(scrubText("id 111-222-333", { languages: ["nl"] }).text).toBe(
      "id [BSN]",
    );
  });

  it("rejects obviously fake compact SSNs", () => {
    expect(scrubText("ticket 123456789", { languages: ["en"] }).counts.ssn).toBe(
      0,
    );
    expect(scrubText("ticket 111111111", { languages: ["en"] }).counts.ssn).toBe(
      0,
    );
  });

    it("masks trunk-zero NL international before SSN", () => {
      const result = scrubText("bel +31(0)612345678", {
        languages: ["nl", "en"],
      });
      expect(result.text).toBe("bel [PHONE]");
      expect(result.counts.phone).toBe(1);
      expect(result.counts.ssn).toBe(0);
    });

    it("masks dotted IEEE MAC and slash IMEI", () => {
      expect(scrubText("mac 01.23.45.67.89.ab").text).toBe("mac [MAC]");
      expect(
        scrubText("imei 49/015420/323751/8 listed").text,
      ).toBe("imei [IMEI] listed");
    });

    it("masks compressed IPv6 with mid hextets", () => {
      expect(
        scrubText("peer 2001:db8:85a3::8a2e:370:7334 ok").text,
      ).toBe("peer [IP] ok");
    });

    it("masks phones and IP without treating IP as phone", () => {
    const result = scrubText("call +31 6 12345678 host 192.168.0.1");
    expect(result.text).toBe("call [PHONE] host [IP]");
    expect(result.counts.phone).toBe(1);
    expect(result.counts.ip).toBe(1);
  });

  it("masks MAC, location, NL postcode and plate", () => {
    const result = scrubText(
      "sta aa:bb:cc:dd:ee:ff pin 52.3676, 4.9041 post 1012 AB plate AB-12-CD",
      { languages: ["nl"] },
    );
    expect(result.text).toBe(
      "sta [MAC] pin [LOCATION] post [ADDRESS] plate [LICENSE_PLATE]",
    );
  });

  it.each([
    ["woont op Kerkstraat 12, 1234 AB Amsterdam", "nl", "woont op [ADDRESS], [ADDRESS] Amsterdam"],
    ["adres: Van Baerlestraat 12-3.", "nl", "adres: [ADDRESS]."],
    ["Sint-Jansstraat 4a", "nl", "[ADDRESS]"],
    ["ship to 221B Baker Street, London", "en", "ship to [ADDRESS], London"],
    ["1600 Pennsylvania Avenue NW", "en", "[ADDRESS] NW"],
    ["at 10 Downing St. today", "en", "at [ADDRESS] today"],
    ["12 Baker Street Station", "en", "[ADDRESS] Station"],
    ["Hauptstraße 5a, 10115 Berlin", "de", "[ADDRESS], 10115 Berlin"],
    ["Kölner Str. 5", "de", "[ADDRESS]"],
    ["Frankfurter Allee 12", "de", "[ADDRESS]"],
    ["Johann-Sebastian-Bach-Straße 5", "de", "[ADDRESS]"],
    ["Kaiser-Wilhelm-Platz 3", "de", "[ADDRESS]"],
    ["Hauptstr.5, Berlin", "de", "[ADDRESS], Berlin"],
    ["Kerkstraat  12", "nl", "[ADDRESS]"],
    ["Kerkstraat\t12", "nl", "[ADDRESS]"],
    ["Kerkstraat\u202f12", "nl", "[ADDRESS]"],
    ["Kerkstraat 12bis", "nl", "[ADDRESS]"],
    ["ship to 221-223 Baker Street", "en", "ship to [ADDRESS]"],
    ["Berliner\u00a0Straße 17", "de", "[ADDRESS]"],
    ["Berliner  Straße 17", "de", "[ADDRESS]"],
    ["Der Hauptstraße 5", "de", "Der [ADDRESS]"],
    ["Nieuwmarkt 4", "nl", "[ADDRESS]"],
    ["Binnenhof 1", "nl", "[ADDRESS]"],
    ["Jaagpad 3", "nl", "[ADDRESS]"],
    ["Reichpietschufer 60", "de", "[ADDRESS]"],
    ["Grote Markt 1", "nl", "[ADDRESS]"],
    ["Oude Gracht 12", "nl", "[ADDRESS]"],
    ["Laan van Meerdervoort 52", "nl", "[ADDRESS]"],
    ["Laan van Nieuw Oost-Indië 5", "nl", "[ADDRESS]"],
    ["Hohenzollernring 12", "de", "[ADDRESS]"],
    ["Kerkstraat nr. 12", "nl", "[ADDRESS]"],
    ["Kerkstr. 12", "nl", "[ADDRESS]"],
    ["Hauptstraße Nr. 5", "de", "[ADDRESS]"],
    ["123 Main Dr", "en", "[ADDRESS]"],
    ["5 Elm Ct.", "en", "[ADDRESS]"],
    ["12 Park Row", "en", "[ADDRESS]"],
    ["lives at 221B Baker Street.", "en", "lives at [ADDRESS]."],
  ])("masks street address %j (%s)", (text, lang, expected) => {
    const result = scrubText(text, { languages: [lang] });
    expect(result.text).toBe(expected);
    expect(result.counts.address).toBe(expected.split("[ADDRESS]").length - 1);
  });

  it.each([
    ["de Kerkstraat is afgesloten", "nl"],
    ["Mr Baker Street", "en"],
    ["Amsterdam 2024", "nl"],
    ["Hier Platz 5", "de"],
    ["Wieder Platz 2 für Bayern", "de"],
    ["Der Weg 3 ist frei", "de"],
    ["Oder Ring 3", "de"],
    ["The Park 12 tickets", "nl"],
    ["Theme Park 2 opens", "nl"],
    ["Safe Haven 3 is out", "nl"],
    ["took 12 Main Streetcar", "en"],
    ["Auf Platz 3 landete", "de"],
    ["Spring 2024", "de"],
    ["3 new road maps", "en"],
  ])("leaves street lookalike %j (%s)", (text, lang) => {
    const result = scrubText(text, { languages: [lang] });
    expect(result.text).toBe(text);
    expect(result.counts.address).toBe(0);
  });

  it("gates street addresses by language pack", () => {
    expect(scrubText("Kerkstraat 12", { languages: ["en"] }).counts.address).toBe(0);
    expect(scrubText("12 Baker Street", { languages: ["nl"] }).counts.address).toBe(0);
    expect(scrubText("Hauptstraße 5", { languages: ["en", "nl"] }).counts.address).toBe(0);
  });

  it("masks grouped IMEI and NL passport", () => {
    const result = scrubText(
      "device 49-015420-323751-8 paspoort XR1001R58",
      { languages: ["nl"] },
    );
    expect(result.text).toBe("device [IMEI] paspoort [PASSPORT]");
    expect(result.counts.imei).toBe(1);
    expect(result.counts.passport).toBe(1);
  });

  it("masks lowercased NL passport", () => {
    const result = scrubText("paspoort xr1001r58", { languages: ["nl"] });
    expect(result.text).toBe("paspoort [PASSPORT]");
    expect(result.counts.passport).toBe(1);
  });

  it("masks BSN and SSN groups split by nbsp or unicode dashes", () => {
    for (const text of ["111\xa0222\xa0333", "111\u202f222\u202f333", "111\u2013222\u2013333"]) {
      const result = scrubText(`BSN ${text}`, { languages: ["nl"] });
      expect(result.text).toBe("BSN [BSN]");
    }
    for (const text of [
      "219\u201309\u20139999",
      "219\u201109\u20119999",
      "219\u221209\u22129999",
      "219\xa009\xa09999",
      "219\u200909\u20099999",
    ]) {
      const result = scrubText(`SSN ${text}`, { languages: ["en"] });
      expect(result.text).toBe("SSN [SSN]");
    }
    expect(
      scrubText("pages 219\u201309 9999", { languages: ["en"] }).counts.ssn,
    ).toBe(0);
  });

  it("masks grouped German tax ids ahead of a BSN-shaped tail", () => {
    for (const text of ["86 095 742 719", "86\xa0095\xa0742\xa0719"]) {
      const result = scrubText(`IdNr ${text}`, { languages: ["de"] });
      expect(result.text).toBe("IdNr [TAX_ID]");
    }
    const both = scrubText("IdNr 57 482 956 513", { languages: ["nl", "de"] });
    expect(both.text).toBe("IdNr [TAX_ID]");
    expect(both.counts.bsn).toBe(0);
    expect(scrubText("IdNr 86 095 742 718", { languages: ["de"] }).text).toBe(
      "IdNr 86 095 742 718",
    );
  });

  it("masks phones with unicode separators or a (0) trunk whole", () => {
    const cases: [string, string[]][] = [
      ["+31\xa06\xa012345678", ["nl"]],
      ["+31 6 1234\u20115678", ["nl"]],
      ["+31\u20136\u201312345678", ["nl"]],
      ["06\xa012345678", ["nl"]],
      ["020\u2013123\xa04567", ["nl"]],
      ["(555) 123\u20134567", ["en"]],
      ["555\u2009123\u20094567", ["en"]],
      ["030\xa012345678", ["de"]],
      ["+44 (0) 20 7946 0958", ["en"]],
      ["+49 (0) 30 1234 5678", ["de"]],
    ];
    for (const [text, languages] of cases) {
      const result = scrubText(`tel ${text}`, { languages });
      expect(result.text).toBe("tel [PHONE]");
      expect(result.counts.phone).toBe(1);
    }
    expect(
      scrubText("Tel +49 (0) 30 - 1234 - 5678901 x", { languages: ["de"] }).text,
    ).toBe("Tel [PHONE] x");
    expect(scrubText("tel +31 20\u22121234567", { languages: ["nl"] }).text).toBe(
      "tel [PHONE]",
    );
    expect(scrubText("See (+33 1 35 39 12 00) x", { languages: ["en"] }).text).toBe(
      "See ([PHONE]) x",
    );
    expect(scrubText("call 0049 33204 1234567 now", { languages: ["de"] }).text).toBe(
      "call [PHONE] now",
    );
    // Past 15 digits a run holds more than one number: masked whole.
    for (const text of [
      "Tel +31 (20) 123 4567 (06) 12345678 x",
      "Tel +31 20 1234567 0031 6 12345678 x",
      "Tel +31 20 1234567 020 7654321 x",
      "Tel +31 6 12345678 06-12345678 x",
      "Tel +31-20-1234567-0031-6-12345678 x",
      "Tel 0031 20 1234567 0031 20 7654321 x",
      "Tel +44 20 7946 0958 - 2024 x",
      "Tel +44 20 7946 0958 12345 67890 x",
      "Tel +32 2 123 45 67 02 765 43 21 x",
      "Tel +44 (0) 20 - 7946 - 0958 - 020 - 7946 - 0959 x",
      "Tel +44 (0) 20 7946 0958 (0) 20 7946 0959 (0) 20 7946 0960 (0) 20 7946 0961 x",
    ]) {
      expect(scrubText(text, { languages: ["en", "nl"] }).text).toBe("Tel [PHONE] x");
    }
  });

  it("masks degrees-minutes-seconds coordinate pairs", () => {
    for (const value of [
      `52°22'3.4"N 4°54'14.8"E`,
      "52° 22′ 03″ N, 4° 54′ 14″ E",
      `33°52'4"S 151°12'26"W`,
      "N 52° 22.057' E 004° 54.246'",
      "N 52° 22.057', E 4° 54.246'",
      "52°22'N\n4°54'E",
      "N 52° 22.057'\r\nE 4° 54.246'",
      "52°\u202f22\u2032\u202fN 4°\u202f54\u2032\u202fE",
      "52°22'N\u20094°54'E",
      "52°22'N\u30004°54'E",
      "52°22'N\u20074°54'E",
      "52°22'N\u20284°54'E",
      "52°22'N\u20294°54'E",
      "52°22'N\f4°54'E",
      "52°22'N\v4°54'E",
      "52°22'N\x854°54'E",
      "52°22,5'N 4°54,2'O",
      "52º22'3''N 4º54'14''E",
    ]) {
      const result = scrubText(`at ${value} today`);
      expect(result.text).toBe("at [LOCATION] today");
      expect(result.counts.location).toBe(1);
    }
    for (const text of [
      `lat 52°22'3"N only`,
      `95°22'3"N 4°54'14"E`,
      `52°72'3"N 4°54'14"E`,
      "angle 45° 30' and 12° 5'",
      "12°C at 5' N",
      "\u0665\u0662°22'N 4°54'E",
      "52°\x1c22'N 4°54'E",
    ]) {
      expect(scrubText(text).text).toBe(text);
    }
    expect(scrubText("N 52°22' E 4°54'\n3''rd line").text).toBe("[LOCATION]\n3''rd line");
    expect(scrubText(`N 52°22' E 4°54' 12"x`).text).toBe(`[LOCATION] 12"x`);
  });

  it("masks internationalized email addresses", () => {
    for (const value of [
      "josé@example.com",
      "ada@münchen.de",
      "ада@пример.рф",
      "zoë.müller@bücher.example.de",
    ]) {
      const result = scrubText(`mail ${value} ok`);
      expect(result.text).toBe("mail [EMAIL] ok");
      expect(result.counts.email).toBe(1);
    }
    expect(scrubText("ada@münchen.deNL91ABNA0417164300").text).toBe(
      "[EMAIL][IBAN]",
    );
    expect(scrubText("x@y.c0m").text).toBe("x@y.c0m");
    expect(scrubText("x".repeat(70) + "@example.com").text).toBe("x".repeat(6) + "[EMAIL]");
    expect(scrubText("mail \u{1d49c}bc@example.com ok").text).toBe("mail [EMAIL] ok");
    // The JS detector itself (scrubText may route to native): per-"@" walk.
    expect(emailDetector.scrub("x".repeat(70) + "@example.com").text).toBe(
      "x".repeat(6) + "[EMAIL]",
    );
    expect(emailDetector.scrub("mail \u{1d49c}bc@example.com ok").text).toBe(
      "mail [EMAIL] ok",
    );
    expect(emailDetector.scrub("a@x.com.b@y.com").text).toBe("[EMAIL][EMAIL]");
    {
      const text = "a@ex.com." + "1".repeat(63) + "." + "1".repeat(63) + ".xx@y";
      expect(scrubText(text).text).toBe("[EMAIL]" + text.slice("a@ex.com".length));
    }
    {
      // Capped shortening walk: a long domain with a glued TLD stays fast.
      const start = performance.now();
      expect(scrubText("a@" + "b.".repeat(20000) + "c".repeat(30)).text).toBe(
        "[EMAIL]" + "c".repeat(6),
      );
      expect(performance.now() - start).toBeLessThan(5000);
    }
    for (const text of [
      ("\u7530\u4e2d".repeat(40) + "@a.b").repeat(5000),
      "a.b@".repeat(20000),
      "a@".repeat(100000),
    ]) {
      const start = performance.now();
      emailDetector.scrub(text);
      expect(performance.now() - start).toBeLessThan(5000);
    }
    expect(scrubText("x@y.\u216b\u216b x").text).toBe("[EMAIL] x");
    expect(scrubText("ada@example.de\u00bd x").text).toBe("[EMAIL] x");
    // Astral TLD chars: the end walk never splits a surrogate pair.
    expect(scrubText("ada@x.de\u{10107}abc9").text).toBe("[EMAIL]9");
    expect(scrubText("mail ada@example.\u{1d41c}\u{1d428}\u{1d426}2024 x").text).toBe(
      "mail [EMAIL]2024 x",
    );
    expect(scrubText("ada@example.com\u216b1@b").text).toBe("[EMAIL]1@b");
    // Letters glued after the TLD: masked as found instead of dropped.
    for (const glue of ["a".repeat(30), "\ua188".repeat(30), "\ua98f".repeat(30)]) {
      const text = scrubText(`mail ada@example.com${glue}`).text;
      expect(text.startsWith("mail [EMAIL]")).toBe(true);
      expect(text).not.toContain("@");
    }
    for (const [text, expected] of [
      [
        "\u8bf7\u53d1\u9001\u81f3ada@example.com\u4ee5\u4fbf\u56de\u590d",
        "[EMAIL]\u4ee5\u4fbf\u56de\u590d",
      ],
      ["mail ada@example.com\u4eca\u65e5", "mail [EMAIL]\u4eca\u65e5"],
      ["mail ada@example.com" + "\u314b".repeat(30), "mail [EMAIL]" + "\u314b".repeat(30)],
      ["mail ada@example.com\u{20000}", "mail [EMAIL]\u{20000}"],
      ["mail \u7530\u4e2d@example.jp ok", "mail [EMAIL] ok"],
      ["mail \u7530\u4e2d.\u592a\u90ce@example.jp ok", "mail [EMAIL] ok"],
      ["mail \u7530\u4e2d123@example.jp ok", "mail [EMAIL] ok"],
      ["mail \u7530\u4e2d.taro@example.jp ok", "mail [EMAIL] ok"],
      ["mail taro\u7530\u4e2d@example.jp ok", "mail [EMAIL] ok"],
      ["mail \uae40\ucca0\uc218@example.kr ok", "mail [EMAIL] ok"],
      ["mail \u5f20\u4f1f@\u516c\u53f8.\u4e2d\u56fd ok", "mail [EMAIL] ok"],
      ["mail ada@example.\u0e44\u0e17\u0e22 ok", "mail [EMAIL] ok"],
      [
        "\u0e2d\u0e35\u0e40\u0e21\u0e25ada@example.com\u0e04\u0e23\u0e31\u0e1a",
        "\u0e2d\u0e35[EMAIL]\u0e04\u0e23\u0e31\u0e1a",
      ],
    ]) {
      const result = scrubText(text!);
      expect(result.text).toBe(expected);
      expect(result.counts.email).toBe(1);
    }
  });

  it("masks Huawei/H3C dash-grouped MACs but not digit-only part numbers", () => {
    for (const value of ["00e0-fc12-3456", "AABB-CCDD-EEFF", "5489-98ab-cdef"]) {
      const result = scrubText(`mac ${value} up`);
      expect(result.text).toBe("mac [MAC] up");
      expect(result.counts.mac).toBe(1);
    }
    expect(scrubText("mac 00E0-fc12-3456 up").text).toBe("mac [MAC] up");
    expect(scrubText("Device MAC is 00e0-fc12-3456.").text).toBe("Device MAC is [MAC].");
    expect(scrubText("v 00e0-fc12-3456.bin").counts.mac).toBe(0);
    expect(scrubText("mac:ж00e0-fc12-3456").text).toBe("mac:ж[MAC]");
    for (const text of [
      "part 1234-5678-9012 shipped",
      "id 4d95a28a-0833-4533-82c1-de09362e46d1",
      "ref aabb-ccdd-eeff-0011",
    ]) {
      expect(scrubText(text).counts.mac).toBe(0);
    }
  });

  it("rejects unknown language", () => {
    expect(() => scrubText("hi", { languages: ["fr"] })).toThrow(
      /unknown language/,
    );
  });

  it.each([
    ["M1 1AE"],
    ["B33 8TH"],
    ["W1A 0AX"],
    ["SW1A 1AA"],
    ["NW1 6XE"],
    ["GU30 7RS"],
    ["E1W 1AA"],
    ["JE2 3AA"],
    ["GY1 1AA"],
    ["ZE1 0AA"],
    ["NR1 3PS"],
    ["EC1A 1BB"],
  ])("masks every UK postcode outward shape (%s)", (value) => {
    const result = scrubText(`postcode ${value}`, { languages: ["en"] });
    expect(result.text).toBe("postcode [ADDRESS]");
    expect(result.counts.address).toBe(1);
  });

  it("masks the non-geographic UK outward code", () => {
    const result = scrubText("GIR 0AA", { languages: ["en"] });
    expect(result.text).toBe("[ADDRESS]");
    expect(result.counts.address).toBe(1);
  });

  it.each([[" "], ["  "], ["\t"], ["\u00a0"], ["\u202f"]])(
    "masks a UK postcode across a whitespace run (%j)",
    (separator) => {
      const result = scrubText(`postcode NW1${separator}6XE`, {
        languages: ["en"],
      });
      expect(result.text).toBe("postcode [ADDRESS]");
      expect(result.counts.address).toBe(1);
    },
  );

  it("masks a UK postcode after a street address", () => {
    const result = scrubText("Ship to 221B Baker Street, London NW1 6XE", {
      languages: ["en"],
    });
    expect(result.text).toBe("Ship to [ADDRESS], London [ADDRESS]");
    expect(result.counts.address).toBe(2);
  });

  it("masks a UK postcode inside JSON", () => {
    const result = scrubText('{"postcode": "EC1A 1BB", "city": "London"}', {
      languages: ["en"],
    });
    expect(result.text).toBe('{"postcode": "[ADDRESS]", "city": "London"}');
  });

  it("masks a UK postcode inside CSV", () => {
    const result = scrubText("id,SW1A 1AA,2024-01-15,active", {
      languages: ["en"],
    });
    expect(result.text).toBe("id,[ADDRESS],2024-01-15,active");
  });

  it.each([["A4 2PK"], ["PS5 1TB"], ["A1 2PK"]])(
    "rejects UK postcode areas that do not exist (%s)",
    (value) => {
      const result = scrubText(`part ${value} in stock`, { languages: ["en"] });
      expect(result.counts.address).toBe(0);
      expect(result.text).toContain(value);
    },
  );

  it.each([["AB12C 3DE"], ["M12C 3DE"], ["LA23J 2DX"], ["SW123 4AB"]])(
    "rejects UK outward shapes that do not exist (%s)",
    (value) => {
      expect(
        scrubText(`order ${value} shipped`, { languages: ["en"] }).counts.address,
      ).toBe(0);
    },
  );

  it.each([
    ["_NW1 6XE"],
    ["NW1 6XE_"],
    ["__NW1 6XE__"],
    ["\u00e9NW1 6XE"],
    ["NW1 6XE\u00e9"],
    ["\u0416NW1 6XE"],
    ["NW1 6XE\u0663"],
  ])("masks when the neighbour is not ASCII alphanumeric (%s)", (value) => {
    const result = scrubText(value, { languages: ["en"] });
    expect(result.counts.address).toBe(1);
    expect(result.text).toContain("[ADDRESS]");
  });

  it.each([
    ["NW16XE"],
    ["nw1 6xe"],
    ["XNW1 6XE"],
    ["1NW1 6XE"],
    ["NW1 6XEa"],
  ])("ignores UK postcode shapes out of scope (%s)", (value) => {
    expect(scrubText(`ref ${value} end`, { languages: ["en"] }).counts.address).toBe(0);
  });

  it("disables the UK postcode detector without the en pack", () => {
    const result = scrubText("postcode NW1 6XE", { languages: ["nl"] });
    expect(result.text).toBe("postcode NW1 6XE");
    expect(result.counts.address).toBe(0);
  });

  it("fails closed on oversize input", async () => {
    const { scrubTextJs } = await import("../src/scrub-js.js");
    const { MAX_SCRUB_BYTES, PiiScrubError: Err } = await import(
      "../src/types.js"
    );
    expect(MAX_SCRUB_BYTES).toBe(32 * 1024 * 1024);
    // Keep the fixture small enough for CI while still exceeding a temporary
    // local cap by constructing bytes > MAX via repeated multi-byte chars when
    // affordable; otherwise assert the public error type remains catchable.
    const oversize = "é".repeat(Math.ceil(MAX_SCRUB_BYTES / 2) + 1);
    expect(Buffer.byteLength(oversize, "utf8")).toBeGreaterThan(MAX_SCRUB_BYTES);
    expect(() => scrubTextJs(oversize)).toThrow(Err);
  });
});

describe("German USt-IdNr (de vat)", () => {
  it("masks compact and grouped forms", () => {
    expect(scrubText("USt-IdNr. DE136695976", { languages: ["de"] }).text).toBe(
      "USt-IdNr. [VAT_ID]",
    );
    expect(scrubText("DE 136 695 976 on the invoice", { languages: ["de"] }).text).toBe(
      "[VAT_ID] on the invoice",
    );
    expect(scrubText("DE 136.695.976 on the invoice", { languages: ["de"] }).text).toBe(
      "[VAT_ID] on the invoice",
    );
    expect(scrubText("vat de 136 695 976", { languages: ["de"] }).text).toBe(
      "vat [VAT_ID]",
    );
  });

  it("rejects a wrong check digit or a leading zero", () => {
    expect(scrubText("DE136695977 is not issued", { languages: ["de"] }).text).toBe(
      "DE136695977 is not issued",
    );
    expect(scrubText("DE036695976 is not issued", { languages: ["de"] }).text).toBe(
      "DE036695976 is not issued",
    );
  });

  it("masks inside JSON and CSV", () => {
    expect(scrubText('{"vat": "DE136695976"}', { languages: ["de"] }).text).toBe(
      '{"vat": "[VAT_ID]"}',
    );
    expect(scrubText("name,vat\nAcme,DE 136 695 976", { languages: ["de"] }).text).toBe(
      "name,vat\nAcme,[VAT_ID]",
    );
  });

  it("is disabled without the de pack", () => {
    expect(scrubText("USt-IdNr. DE136695976", { languages: ["en"] }).text).toBe(
      "USt-IdNr. DE136695976",
    );
  });
});

describe("scrubPayload", () => {
  it("walks nested payloads", () => {
    const result = scrubPayload({
      user: { email: "ada@example.com", note: "no pii here" },
      contacts: ["reach me at +31 6 12345678", "iban NL91ABNA0417164300"],
      count: 3,
    });
    expect(result.payload).toEqual({
      user: { email: "[EMAIL]", note: "no pii here" },
      contacts: ["reach me at [PHONE]", "iban [IBAN]"],
      count: 3,
    });
    expect(result.found).toBe(true);
  });

  it("fails closed on non-plain objects", () => {
    expect(() => scrubPayload({ when: new Date() })).toThrow(PiiScrubError);
  });

  it("fails closed past depth limit", () => {
    let deep: unknown = "ada@example.com";
    for (let i = 0; i < 250; i++) {
      deep = [deep];
    }
    expect(() => scrubPayload(deep)).toThrow(/nests past/);
  });
});

describe("native backend", () => {
  it("reports whether the napi addon is in use under auto", () => {
    delete process.env.PII_MCP_BACKEND;
    resetNativeCache();
    expect(typeof usingNative()).toBe("boolean");
  });

  it("uses native when available and backend=auto", () => {
    delete process.env.PII_MCP_BACKEND;
    resetNativeCache();
    if (!usingNative()) {
      return;
    }
    const result = scrubText("Contact ada@example.com for help");
    expect(result.text).toBe("Contact [EMAIL] for help");
    expect(result.counts.email).toBe(1);
  });

  it("honors PII_MCP_BACKEND=native when the addon is built", () => {
    process.env.PII_MCP_BACKEND = "native";
    resetNativeCache();
    try {
      expect(usingNative()).toBe(true);
      const result = scrubText("Pay NL91ABNA0417164300");
      expect(result.text).toBe("Pay [IBAN]");
      expect(result.counts.iban).toBe(1);
    } catch (err) {
      if (
        err instanceof Error &&
        err.message.includes("napi addon is not installed")
      ) {
        return;
      }
      throw err;
    }
  });

  it.skipIf(process.env.PII_MCP_NER_MODEL)(
    "fails closed when ner is requested without a ner build or model",
    () => {
      const reason = /`ner` feature|PII_MCP_NER_MODEL/;
      expect(() => scrubText("Ada Lovelace", { ner: true })).toThrow(reason);
      expect(() => scrubPayload({ to: "Ada Lovelace" }, { ner: true })).toThrow(reason);
    },
  );

  it.skipIf(!process.env.PII_MCP_NER_MODEL)(
    "masks person names with ner on a ner build",
    (ctx) => {
      process.env.PII_MCP_BACKEND = "native";
      resetNativeCache();
      let result;
      try {
        result = scrubText("Mail Ada Lovelace at ada@example.com", { ner: true });
      } catch (err) {
        if (err instanceof PiiScrubError && err.message.includes("`ner` feature")) {
          ctx.skip();
        }
        throw err;
      }
      expect(result.text).toBe("Mail [PERSON] at [EMAIL]");
      expect(result.counts.person).toBe(1);
      expect(result.counts.email).toBe(1);
      const payload = scrubPayload({ to: ["Jan de Vries"] }, { ner: true });
      expect(payload.payload).toEqual({ to: ["[PERSON]"] });
    },
  );

  it("forces js backend even when native is present", () => {
    process.env.PII_MCP_BACKEND = "js";
    resetNativeCache();
    expect(usingNative()).toBe(false);
    const result = scrubText("Contact ada@example.com for help");
    expect(result.text).toBe("Contact [EMAIL] for help");
  });
});

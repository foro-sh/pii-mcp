import { afterEach, beforeEach, describe, expect, it } from "vitest";
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
      scrubText("0031 20 1234567 0031 20 7654321", { languages: ["nl"] }).text,
    ).toBe("[PHONE] [PHONE]");
    expect(scrubText("call +31 6 12345678 12345", { languages: ["en"] }).text).toBe(
      "call [PHONE] 12345",
    );
    for (const text of [
      "Tel +31 (20) 123 4567 (06) 12345678",
      "Tel +31 20 1234567 0031 6 12345678",
    ]) {
      expect(scrubText(text, { languages: ["nl"] }).text).toBe("Tel [PHONE] [PHONE]");
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
    for (const [text, expected] of [
      ["+31 20 1234567 020 7654321", "[PHONE] [PHONE]"],
      ["+31 6 12345678 06-12345678", "[PHONE] [PHONE]"],
      ["+31-20-1234567-0031-6-12345678", "[PHONE]-[PHONE]"],
    ]) {
      expect(scrubText(text!, { languages: ["nl"] }).text).toBe(expected);
    }
  });

  it("masks degrees-minutes-seconds coordinate pairs", () => {
    for (const value of [
      `52°22'3.4"N 4°54'14.8"E`,
      "52° 22′ 03″ N, 4° 54′ 14″ E",
      `33°52'4"S 151°12'26"W`,
      "N 52° 22.057' E 004° 54.246'",
      "N 52° 22.057', E 4° 54.246'",
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
    ]) {
      expect(scrubText(text).text).toBe(text);
    }
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
    for (const [text, expected] of [
      [
        "\u8bf7\u53d1\u9001\u81f3ada@example.com\u4ee5\u4fbf\u56de\u590d",
        "[EMAIL]\u4ee5\u4fbf\u56de\u590d",
      ],
      ["mail ada@example.com\u4eca\u65e5", "mail [EMAIL]\u4eca\u65e5"],
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

  it("forces js backend even when native is present", () => {
    process.env.PII_MCP_BACKEND = "js";
    resetNativeCache();
    expect(usingNative()).toBe(false);
    const result = scrubText("Contact ada@example.com for help");
    expect(result.text).toBe("Contact [EMAIL] for help");
  });
});

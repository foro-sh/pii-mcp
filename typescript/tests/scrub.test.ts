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

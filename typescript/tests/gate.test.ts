/**
 * Gate entry and vendored artifact: foro Tier 1 parity, binary skip, freshness.
 */
import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { describe, expect, it, vi } from "vitest";
import {
  MAX_DEPTH,
  MAX_SCRUB_BYTES,
  PiiScrubError,
  scrubPayload,
  scrubText,
} from "../src/gate.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = join(root, "..");
const artifactPath = join(root, "gate", "pii-gate.mjs");

const pack = JSON.parse(
  readFileSync(join(repoRoot, "eval", "fixtures", "foro_tier1.json"), "utf8"),
) as {
  default_languages: Array<"en" | "nl" | "de">;
  cases: Array<{
    id: string;
    input: string;
    expect_text?: string;
    expect_counts: Record<string, number>;
  }>;
};

describe("gate module (src)", () => {
  it("exports size and depth caps matching the contract", () => {
    expect(MAX_SCRUB_BYTES).toBe(32 * 1024 * 1024);
    expect(MAX_DEPTH).toBe(200);
  });

  for (const case_ of pack.cases) {
    it(`foro fixture via gate module: ${case_.id}`, () => {
      const result = scrubText(case_.input, {
        languages: pack.default_languages,
      });
      if (case_.expect_text !== undefined) {
        expect(result.text).toBe(case_.expect_text);
      }
      for (const [key, want] of Object.entries(case_.expect_counts)) {
        expect(result.counts[key as keyof typeof result.counts]).toBe(want);
      }
    });
  }

  it("skips MCP image/audio data and resource blobs; counts ignore them", () => {
    const imageData = "AAAA4111111111111111BBBBada@example.comCCCC";
    const audioData = "ZZZZ NL91ABNA0417164300 YYYY";
    const blobData = "WWWW +31 6 12345678 XXXX";
    const result = scrubPayload({
      content: [
        { type: "image", data: imageData, alt: "bob@example.com" },
        {
          type: "audio",
          data: audioData,
          transcript: "card 4111111111111111",
        },
      ],
      contents: [
        {
          uri: "file:///secret.bin",
          blob: blobData,
          name: "contact ada@example.com",
        },
      ],
    });
    const payload = result.payload as {
      content: Array<Record<string, string>>;
      contents: Array<Record<string, string>>;
    };
    expect(payload.content[0]!.data).toBe(imageData);
    expect(payload.content[0]!.alt).toBe("[EMAIL]");
    expect(payload.content[1]!.data).toBe(audioData);
    expect(payload.content[1]!.transcript).toBe("card [CREDIT_CARD]");
    expect(payload.contents[0]!.blob).toBe(blobData);
    expect(payload.contents[0]!.name).toBe("contact [EMAIL]");
    expect(result.counts.email).toBe(2);
    expect(result.counts.credit_card).toBe(1);
    expect(result.counts.iban).toBe(0);
    expect(result.counts.phone).toBe(0);
  });

  it("rejects leftover ner option", () => {
    expect(() =>
      scrubText("hi", { ner: true } as { languages?: never }),
    ).toThrow(PiiScrubError);
  });

  it("throws PiiScrubError on non-plain objects", () => {
    expect(() => scrubPayload({ when: new Date() })).toThrow(PiiScrubError);
  });
});

describe("replace option (reversible pseudonymisation)", () => {
  it("substitutes a caller token for a masked value in text", () => {
    const result = scrubText("contact ada@example.com", {
      replace: (type, value) => `[${type.toUpperCase()}_TOKEN:${value}]`,
    });
    expect(result.text).toBe("contact [EMAIL_TOKEN:ada@example.com]");
    expect(result.counts.email).toBe(1);
  });

  it("substitutes across a nested payload, leaving structure intact", () => {
    const result = scrubPayload(
      { rows: [{ email: "ada@example.com" }, { email: "bob@example.com" }] },
      { replace: (_type, value) => `[EMAIL_${value}]` },
    );
    expect(result.payload).toEqual({
      rows: [{ email: "[EMAIL_ada@example.com]" }, { email: "[EMAIL_bob@example.com]" }],
    });
    expect(result.counts.email).toBe(2);
  });

  it("can assign stable per-caller tokens by tracking a map itself", () => {
    const seen = new Map<string, string>();
    let next = 0;
    const replace = (type: string, value: string): string => {
      const key = `${type}:${value}`;
      let token = seen.get(key);
      if (token === undefined) {
        next += 1;
        token = `[${type.toUpperCase()}_${next}]`;
        seen.set(key, token);
      }
      return token;
    };
    const result = scrubText("ada@example.com, bob@example.com, ada@example.com", { replace });
    expect(result.text).toBe("[EMAIL_1], [EMAIL_2], [EMAIL_1]");
  });

  it("shields a replace() result from a detector that runs later in the same pass", () => {
    // email runs before iban/credit_card in UNIVERSAL_DETECTORS; a naive
    // splice would let either re-match the substituted text.
    const result = scrubText("contact ada@example.com", {
      replace: () => "token NL91ABNA0417164300 card 4111 1111 1111 1111",
    });
    expect(result.text).toBe("contact token NL91ABNA0417164300 card 4111 1111 1111 1111");
    expect(result.counts.email).toBe(1);
    expect(result.counts.iban).toBe(0);
    expect(result.counts.credit_card).toBe(0);
  });

  it("tolerates a replace() that itself calls back into scrubText", () => {
    const result = scrubText("outer bob@example.com", {
      replace: (_type, _value) => {
        const inner = scrubText("inner ada@example.com", { types: ["email"] });
        return `[${inner.text}]`;
      },
    });
    expect(result.text).toBe("outer [inner [EMAIL]]");
    expect(result.counts.email).toBe(1);
  });

  it("leaves an allow-listed value unmasked and never calls replace for it", () => {
    const replace = vi.fn((_type: string, value: string) => `[TOKEN:${value}]`);
    const result = scrubText("ada@example.com", { allow: ["ada@example.com"], replace });
    expect(result.text).toBe("ada@example.com");
    expect(replace).not.toHaveBeenCalled();
  });

  it("the vendored artifact honours replace identically to the source module", async () => {
    const gate = await import(artifactPath);
    const result = gate.scrubText("contact ada@example.com", {
      replace: (type: string, value: string) => `[${type.toUpperCase()}_TOKEN:${value}]`,
    });
    expect(result.text).toBe("contact [EMAIL_TOKEN:ada@example.com]");
    expect(result.counts.email).toBe(1);
  });
});

describe("gate artifact (pii-gate.mjs)", () => {
  it("exists and has only node: imports", () => {
    expect(existsSync(artifactPath)).toBe(true);
    const body = readFileSync(artifactPath, "utf8");
    const imports = [...body.matchAll(/from\s+["']([^"']+)["']/g)].map(
      (m) => m[1] ?? "",
    );
    expect(imports.length).toBeGreaterThan(0);
    expect(imports.every((spec) => spec.startsWith("node:"))).toBe(true);
  });

  it("matches a fresh build:gate output", () => {
    const before = createHash("sha256")
      .update(readFileSync(artifactPath))
      .digest("hex");
    execFileSync(process.execPath, ["scripts/build-gate.mjs"], {
      cwd: root,
      stdio: "pipe",
    });
    const after = createHash("sha256")
      .update(readFileSync(artifactPath))
      .digest("hex");
    expect(after).toBe(before);
  });

  it("runs foro Tier 1 fixtures without package imports", async () => {
    const gate = await import(artifactPath);
    for (const case_ of pack.cases) {
      const result = gate.scrubText(case_.input, {
        languages: pack.default_languages,
      });
      if (case_.expect_text !== undefined) {
        expect(result.text, case_.id).toBe(case_.expect_text);
      }
      for (const [key, want] of Object.entries(case_.expect_counts)) {
        expect(result.counts[key], case_.id).toBe(want);
      }
    }
  });
});

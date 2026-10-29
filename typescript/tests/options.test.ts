/**
 * ``types`` / ``allow`` scrub options, shared with Python and Rust.
 * Source: eval/fixtures/scrub_options.json
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import * as gate from "../src/gate.js";
import * as root from "../src/index.js";
import { PII_TYPES, emptyPiiCounts } from "../src/types.js";

type Case = {
  name: string;
  text?: string;
  payload?: unknown;
  options: { types?: string[]; allow?: string[] };
  expected?: { text?: string; payload?: unknown; counts: Record<string, number> };
  error?: string;
};

const cases = JSON.parse(
  readFileSync(
    join(dirname(fileURLToPath(import.meta.url)), "..", "..", "eval", "fixtures", "scrub_options.json"),
    "utf8",
  ),
) as Case[];

for (const [entry, api] of [
  ["package root", root],
  ["gate", gate],
] as const) {
  describe(`scrub options (${entry})`, () => {
    for (const c of cases) {
      it(c.name, () => {
        const run = () =>
          c.text !== undefined
            ? api.scrubText(c.text, c.options)
            : api.scrubPayload(c.payload, c.options);
        if (c.error !== undefined) {
          expect(run).toThrow(c.error);
          return;
        }
        const result = run();
        if (c.text !== undefined) {
          expect((result as { text: string }).text).toBe(c.expected!.text);
        } else {
          expect((result as { payload: unknown }).payload).toEqual(c.expected!.payload);
        }
        expect(result.counts).toEqual({ ...emptyPiiCounts(), ...c.expected!.counts });
        expect(result.found).toBe(Object.keys(c.expected!.counts).length > 0);
      });
    }
  });
}

describe("protect tokens", () => {
  it("restores many protected values in one string", () => {
    const emails = Array.from({ length: 50 }, (_, i) => `u${i}@x.com`);
    const text = emails.join(" ");
    expect(root.scrubText(text, { allow: emails }).text).toBe(text);
  });

  it("fails closed when no private-use code point is free", () => {
    let text = "a@b.com ";
    for (let code = 0xe000; code <= 0xf8ff; code += 1) text += String.fromCharCode(code);
    expect(() => root.scrubText(text, { allow: ["a@b.com"] })).toThrow(root.PiiScrubError);
    expect(root.scrubText(text, { allow: ["c@d.com"] }).counts.email).toBe(1);
  });

  it("accepts every PII type", () => {
    expect(root.scrubText("a@b.com", { types: [...PII_TYPES] }).text).toBe("[EMAIL]");
  });
});

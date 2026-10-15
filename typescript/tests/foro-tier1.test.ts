/**
 * Adoption-gate fixtures from foro-pii Tier 1 (shared JSON pack).
 * Source: eval/fixtures/foro_tier1.json
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { scrubText } from "../src/index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const pack = JSON.parse(
  readFileSync(join(root, "eval", "fixtures", "foro_tier1.json"), "utf8"),
) as {
  default_languages: Array<"en" | "nl" | "de">;
  cases: Array<{
    id: string;
    input: string;
    expect_text: string;
    expect_counts: Record<string, number>;
  }>;
};

describe("foro Tier 1 fixtures", () => {
  for (const case_ of pack.cases) {
    it(case_.id, () => {
      const result = scrubText(case_.input, {
        languages: pack.default_languages,
      });
      expect(result.text).toBe(case_.expect_text);
      for (const [key, want] of Object.entries(case_.expect_counts)) {
        expect(result.counts[key as keyof typeof result.counts]).toBe(want);
      }
    });
  }
});

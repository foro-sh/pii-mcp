/**
 * Gate entry and vendored artifact: foro Tier 1 parity, binary skip, freshness.
 */
import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
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

  it("skips MCP image data while scrubbing siblings", () => {
    const data = "AAAA4111111111111111BBBBada@example.comCCCC";
    const result = scrubPayload({
      content: [{ type: "image", data, alt: "bob@example.com" }],
    });
    const block = (result.payload as { content: Array<Record<string, string>> })
      .content[0]!;
    expect(block.data).toBe(data);
    expect(block.alt).toBe("[EMAIL]");
  });

  it("throws PiiScrubError on non-plain objects", () => {
    expect(() => scrubPayload({ when: new Date() })).toThrow(PiiScrubError);
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

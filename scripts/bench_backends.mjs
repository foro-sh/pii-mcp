#!/usr/bin/env node
/**
 * Side-by-side scrub performance: pure TypeScript vs optional Rust napi.
 *
 * Build a release addon first (debug builds look slower than JS):
 *
 *   cd typescript && npm run build && npm run build:native
 *   node scripts/bench_backends.mjs
 */

import { createRequire } from "node:module";
import { performance } from "node:perf_hooks";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const tsRoot = join(root, "typescript");

// Load from built dist so we exercise the published entry shape.
const {
  scrubText,
  scrubPayload,
  usingNative,
  resetNativeCache,
} = await import(join(tsRoot, "dist/index.js"));

function requireNative() {
  delete process.env.PII_MCP_BACKEND;
  resetNativeCache();
  if (!usingNative()) {
    console.error(
      "napi addon not installed; build with:\n" +
        "  cd typescript && npm run build:native",
    );
    process.exit(1);
  }
}

function timeMs(fn, rounds, warmup = 3) {
  for (let i = 0; i < warmup; i++) fn();
  const samples = [];
  for (let i = 0; i < rounds; i++) {
    const start = performance.now();
    fn();
    samples.push(performance.now() - start);
  }
  return samples;
}

function median(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
}

function mean(samples) {
  return samples.reduce((a, b) => a + b, 0) / samples.length;
}

function fmt(samples) {
  return `median=${median(samples).toFixed(3).padStart(8)} ms  mean=${mean(samples).toFixed(3).padStart(8)} ms`;
}

function speedup(js, rust) {
  const ratio = median(js) / median(rust);
  if (ratio >= 1) return `${ratio.toFixed(2).padStart(5)}× Rust`;
  return `${(1 / ratio).toFixed(2).padStart(5)}× JS`;
}

function withBackend(backend, fn, rounds) {
  const previous = process.env.PII_MCP_BACKEND;
  process.env.PII_MCP_BACKEND = backend;
  resetNativeCache();
  try {
    return timeMs(fn, rounds);
  } finally {
    if (previous === undefined) delete process.env.PII_MCP_BACKEND;
    else process.env.PII_MCP_BACKEND = previous;
    resetNativeCache();
  }
}

requireNative();

const mixed =
  "Contact ada@example.com or pay NL91ABNA0417164300 with " +
  "4111111111111111 from 203.0.113.42 / +31 6 12345678 / " +
  "BSN 111222333 / ssn 078-05-1120 / IdNr 36574261809 / " +
  "postcode 1012 AB";
const clean = "The server exposes a search tool and a fetch tool. ".repeat(20);
const sparseBlock = "lorem ipsum dolor sit amet ".repeat(40) + mixed + "\n";
const large100k = sparseBlock.repeat(Math.max(1, Math.floor(100_000 / sparseBlock.length)));
const large1m = sparseBlock.repeat(Math.max(1, Math.floor(1_000_000 / sparseBlock.length)));
const payload = {
  user: { email: "ada@example.com", note: clean },
  contacts: [mixed, clean, "reach 06 12345678"],
  items: Array.from({ length: 50 }, (_, i) => ({
    id: i,
    bio: i % 10 === 0 ? mixed : clean,
  })),
};

const cases = [
  ["short clean text", () => scrubText(clean), 300],
  [
    "short mixed PII (en+nl+de)",
    () => scrubText(mixed, { languages: ["en", "nl", "de"] }),
    300,
  ],
  ["100 KiB sparse PII", () => scrubText(large100k), 50],
  ["1 MiB sparse PII", () => scrubText(large1m), 12],
  [
    "nested JSON payload",
    () => scrubPayload(payload, { languages: ["en", "nl", "de"] }),
    100,
  ],
  [
    "1k× tiny scrubText calls",
    () => {
      for (let i = 0; i < 1000; i++) scrubText(mixed);
    },
    25,
  ],
];

console.log("pii-mcp backend benchmark (TypeScript vs Rust native)\n");
const header = `${"case".padEnd(28)} ${"TypeScript".padEnd(40)} ${"Rust".padEnd(40)} relative`;
console.log(header);
console.log("-".repeat(header.length));

const rows = [];
for (const [name, fn, rounds] of cases) {
  const js = withBackend("js", fn, rounds);
  const rust = withBackend("native", fn, rounds);
  console.log(
    `${name.padEnd(28)} ${fmt(js).padEnd(40)} ${fmt(rust).padEnd(40)} ${speedup(js, rust)}`,
  );
  rows.push({
    name,
    js: median(js),
    rust: median(rust),
    ratio: median(js) / median(rust),
  });
}

console.log(
  "\nNote: medians over repeated rounds after warmup. " +
    "Relative = median(TypeScript) / median(Rust).",
);

// Markdown table for README paste.
console.log("\n## README table\n");
console.log("| Case | TypeScript | Rust | Speedup |");
console.log("|------|------------|------|---------|");
for (const row of rows) {
  console.log(
    `| ${row.name} | ${row.js.toFixed(3)} ms | ${row.rust.toFixed(3)} ms | ${row.ratio.toFixed(1)}× |`,
  );
}

// Keep require referenced so bundlers don't drop createRequire import.
void require;

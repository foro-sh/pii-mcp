#!/usr/bin/env node
/**
 * Compare pure JS and native (Rust napi) scrub output on mixed inputs.
 *
 * Build first:
 *
 *   cd typescript && npm run build && npm run build:native && npm run parity
 *
 * Prints the first 10 mismatches and exits 1 if any remain.
 */

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomInt, randomBytes } from "node:crypto";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const tsRoot = join(root, "typescript");

const { scrubText, usingNative, resetNativeCache } = await import(
  join(tsRoot, "dist/index.js")
);

const NOISE = "0123456789abcdefABx:.,;-/ @+()\n";

const FIXTURES = [
  // emails
  "ada@example.com",
  "bob+tag@example.org",
  "user.name@sub.example.co.uk",
  // IBANs (documented test / well-known valid)
  "NL91ABNA0417164300",
  "NL91 ABNA 0417 1643 00",
  "DE89370400440532013000",
  "GB29NWBK60161331966075",
  // cards
  "4111111111111111",
  "4111 1111 1111 1111",
  "5500000000000004",
  // phones
  "+31612345678",
  "06-12345678",
  "+1 (415) 555-2671",
  "+49 30 123456",
  // postcodes
  "1234 AB",
  "1012 JS",
  "SW1A 1AA",
  "EC1A 1BB",
  // streets
  "Kerkstraat 12",
  "221B Baker Street",
  "Hauptstraße 5a",
  // clean / near-misses
  "hello world",
  "REF-4111-1111-1111-1111",
  "isbn 9780306406157",
  "order 1695456789014",
];

const LANGS = ["en", "nl", "de"];

function pick(arr) {
  return arr[randomInt(arr.length)];
}

function noise(max = 6) {
  const n = randomInt(max + 1);
  let out = "";
  for (let i = 0; i < n; i++) {
    out += NOISE[randomInt(NOISE.length)];
  }
  return out;
}

function sample() {
  const parts = [];
  const count = 1 + randomInt(4);
  for (let i = 0; i < count; i++) {
    const roll = randomInt(100);
    if (roll < 55) {
      parts.push(pick(FIXTURES));
    } else if (roll < 75) {
      parts.push(noise());
    } else {
      parts.push(randomBytes(2).toString("hex"));
    }
  }
  return parts.join("");
}

function withBackend(backend, text) {
  const previous = process.env.PII_MCP_BACKEND;
  process.env.PII_MCP_BACKEND = backend;
  resetNativeCache();
  try {
    return scrubText(text, { languages: LANGS }).text;
  } finally {
    if (previous === undefined) delete process.env.PII_MCP_BACKEND;
    else process.env.PII_MCP_BACKEND = previous;
    resetNativeCache();
  }
}

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

function main() {
  const n = Number.parseInt(process.argv[2] ?? "5000", 10);
  if (!Number.isFinite(n) || n <= 0) {
    console.error(`usage: node scripts/parity.mjs [n]  (n > 0, got ${process.argv[2]})`);
    process.exit(2);
  }
  requireNative();

  let mismatches = 0;
  for (let i = 0; i < n; i++) {
    const text = sample();
    const js = withBackend("js", text);
    const native = withBackend("native", text);
    if (js !== native) {
      mismatches += 1;
      if (mismatches <= 10) {
        console.log(`${JSON.stringify(text)}\n  js ${JSON.stringify(js)}\n  native ${JSON.stringify(native)}`);
      }
    }
  }

  console.log(`mismatches ${mismatches} / ${n}`);
  process.exit(mismatches ? 1 : 0);
}

main();

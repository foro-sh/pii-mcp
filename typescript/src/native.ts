/**
 * Optional N-API loader for the shared ``pii-core`` crate.
 *
 * Built via ``npm run build:native`` (napi-rs → ``typescript/native/``).
 * When the addon is missing, callers fall back to the pure TypeScript path.
 *
 * Loads the platform ``.node`` binary directly (not the napi-generated
 * ``index.js``) so ``"type": "module"`` in package.json does not break require.
 */

import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export type NativeCounts = Record<string, number>;

export interface NativeScrubTextResult {
  text: string;
  found: boolean;
  counts: NativeCounts;
}

export interface NativeScrubPayloadResult {
  payload: unknown;
  found: boolean;
  counts: NativeCounts;
}

export interface NativeBinding {
  scrubText: (
    text: string,
    languages?: string[] | undefined | null,
  ) => NativeScrubTextResult;
  scrubPayload: (
    payload: unknown,
    languages?: string[] | undefined | null,
  ) => NativeScrubPayloadResult;
}

const require = createRequire(import.meta.url);

function isMusl(): boolean {
  if (process.platform !== "linux") {
    return false;
  }
  try {
    const report = process.report?.getReport?.() as
      | { header?: { glibcVersionRuntime?: string } }
      | undefined;
    if (report?.header && "glibcVersionRuntime" in report.header) {
      return !report.header.glibcVersionRuntime;
    }
  } catch {
    // fall through — default to gnu (most CI / server images)
  }
  return false;
}

function platformTriple(): string | null {
  const { platform, arch } = process;
  if (platform === "darwin" && arch === "arm64") return "darwin-arm64";
  if (platform === "darwin" && arch === "x64") return "darwin-x64";
  if (platform === "linux" && arch === "arm64") {
    return isMusl() ? "linux-arm64-musl" : "linux-arm64-gnu";
  }
  if (platform === "linux" && arch === "x64") {
    return isMusl() ? "linux-x64-musl" : "linux-x64-gnu";
  }
  if (platform === "win32" && arch === "x64") return "win32-x64-msvc";
  return null;
}

function candidatePaths(): string[] {
  const here = dirname(fileURLToPath(import.meta.url));
  const roots = [join(here, "..", "native"), join(here, ".."), join(here, "native")];
  const triple = platformTriple();
  const names = [
    ...(triple !== null ? [`pii-mcp.${triple}.node`] : []),
    "pii-mcp.node",
  ];
  const out: string[] = [];
  for (const root of roots) {
    for (const name of names) {
      out.push(join(root, name));
    }
  }
  return out;
}

let cached: NativeBinding | null | undefined;

/**
 * Load the optional napi addon, or ``null`` when it is not built/installable.
 */
export function loadNative(): NativeBinding | null {
  if (cached !== undefined) {
    return cached;
  }
  for (const path of candidatePaths()) {
    try {
      cached = require(path) as NativeBinding;
      return cached;
    } catch {
      // try next candidate
    }
  }
  cached = null;
  return null;
}

/** Test helper: clear the cached binding so env/backend flips can re-resolve. */
export function resetNativeCache(): void {
  cached = undefined;
}

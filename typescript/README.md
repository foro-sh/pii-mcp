# pii-mcp (TypeScript)

Pattern-based PII scrubbing for MCP servers (regex + checksums). Same detectors
as the Python package: emails, IBANs, cards, BICs, MACs, IMEIs, IPs, coordinates,
BSNs, US SSNs and ITINs, UK National Insurance and NHS numbers, German tax
IDs, Dutch BTW-ids, Dutch passport/ID numbers, phones, street + house number
addresses, Dutch and UK postcodes, and Dutch license plates. Language packs:
`en`, `nl`, and opt-in `de`.

FastMCP middleware stays Python-only (`pii_mcp.fastmcp`); this package is the
core scrub API for Node/TypeScript callers.

## Install

```bash
npm install pii-mcp
```

Default installs are pure TypeScript (no Rust toolchain). A registry
`npm install pii-mcp` is JS-only until optional native artifacts ship.

### Optional Rust core

Accelerate scrubbing with the shared `pii-core` crate via N-API from a clone of
this repo (same core as the Python PyO3 addon — one detector implementation
across runtimes):

```bash
cd typescript
npm install
npm run build
npm run build:native   # requires a Rust toolchain; needs ../crates/pii-core
```

When the napi addon is loadable, `scrubText` / `scrubPayload` use it.
Force the JS path with `PII_MCP_BACKEND=js`. Require native with
`PII_MCP_BACKEND=native`.

Person names in prose are out of band (Presidio or another NER sidecar). The
`person` count stays `0` until key-aware masking lands (issue #52). See the
[main README](../README.md#scope).

#### Performance (TypeScript vs Rust release)
Medians from `scripts/bench_backends.mjs` on macOS arm64 / Node 22
(release napi build; debug builds are not representative). V8’s regex engine
is already fast, so napi wins are modest on larger/mixed inputs; tiny calls can
favor pure JS because FFI overhead dominates:

| Case | TypeScript | Rust | Speedup |
|------|------------|------|---------|
| Short clean text | 0.024 ms | 0.026 ms | 0.9× |
| Short mixed PII | 0.014 ms | 0.011 ms | 1.2× |
| 100 KiB sparse PII | 2.03 ms | 1.84 ms | 1.1× |
| 1 MiB sparse PII | 20.6 ms | 20.7 ms | 1.0× |
| Nested JSON payload | 1.28 ms | 1.12 ms | 1.1× |
| 1k× tiny `scrubText` | 9.82 ms | 10.5 ms | 0.9× |

```bash
cd typescript && npm run build && npm run build:native
node ../scripts/bench_backends.mjs
```

## Core

```ts
import { scrubText, scrubPayload, usingNative } from "pii-mcp";

scrubText("mail ada@example.com");
scrubPayload({ email: "ada@example.com" }, { languages: ["en"] });
usingNative(); // true when the napi addon is active
```

For a runnable Node example, see [`examples/node/`](../examples/node/).

## Gate (foro user containers)

For a sync, pattern-only scrubber with **zero npm dependencies** in the image
(no napi, no NER), use the vendored artifact or the `pii-mcp/gate` export:

```bash
cd typescript && npm run build:gate   # writes gate/pii-gate.mjs
```

```ts
import { scrubPayload, scrubText, PiiScrubError } from "pii-mcp/gate";
// or COPY gate/pii-gate.mjs into the image and import that file directly
```

Contract (placeholders, caps, binary skip, fail-closed rules):
[`docs/tier1-gate.md`](../docs/tier1-gate.md). Hybrid packaging: vendored JS for
the gate; optional native for the API process.

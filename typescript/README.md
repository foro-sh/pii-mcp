# pii-mcp (TypeScript)

Pattern-based PII scrubbing for MCP servers (regex + checksums). Same detectors
as the Python package: emails, IBANs, cards, BICs, MACs, IPs, coordinates, BSNs,
US SSNs, German tax IDs, Dutch BTW-ids, phones, Dutch postcodes, and Dutch
license plates. Language packs: `en`, `nl`, and opt-in `de`.

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

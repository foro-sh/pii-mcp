# pii-mcp (TypeScript)

Pattern-based PII redaction for MCP servers (regex + checksums). Same detectors
as the Python package: emails, IBANs, cards, BICs, MACs, IMEIs, IPs, coordinates,
BSNs, US SSNs and ITINs, UK National Insurance and NHS numbers, German tax
IDs, Dutch BTW-ids, Dutch passport/ID numbers, phones, street + house number
addresses, Dutch and UK postcodes, Dutch license plates, and names/addresses
that sit right after a recognized EN/NL/DE field name (`last_name`, `vorname`,
`straße`, `plz`, …). Language packs: `en`, `nl`, and opt-in `de`.

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

`person` is key-aware only (issue #52): a value right after a recognized
field name (`name`, `first_name`, `vorname`, `naam`, …) is masked; there is no
pattern for a bare name on its own. Prose NER is out of band: Tier 1 (this package, no model)
in live MCP gates; Tier 2 (Presidio or another NER sidecar) on API paths.
Do not run a second in-process NER beside Presidio. Details:
[Using with foro / Presidio](https://github.com/foro-sh/pii-mcp#using-with-foro--presidio).

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

User-container gates must **COPY** the vendored file — do not `npm install`
inside the gate image:

```bash
cd typescript && npm run build:gate   # writes gate/pii-gate.mjs
# dockerfile: COPY typescript/gate/pii-gate.mjs …/foro-pii.mjs
```

```ts
import { scrubPayload, scrubText, PiiScrubError } from "./foro-pii.mjs";
```

For Node apps that already depend on this package (API process, not the gate
image), `import { … } from "pii-mcp/gate"` is the same JS-only surface without
loading napi.

Contract (placeholders, caps, binary skip, fail-closed rules):
[`docs/tier1-gate.md`](../docs/tier1-gate.md). Hybrid packaging: vendored JS for
the gate; optional native for the API process.

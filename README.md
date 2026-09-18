# pii-mcp

Pattern-based PII scrubbing for MCP servers (regex + checksums). Mask emails,
IBANs, cards, BICs, MACs, IPs, coordinates, BSNs, US SSNs, German tax IDs,
Dutch BTW-ids, phones, Dutch postcodes, and Dutch license plates in tool
results — not NER for person names or full street addresses. Language packs:
`en`, `nl`, and opt-in `de`.

Aligned with AP examples of persoonsgegevens where pattern/checksum detection
can reach them (contact/financial IDs, online identifiers including IP/MAC,
locatiegegevens as coordinates, BSN, kenteken). Names, free-text health data,
and full street addresses need NER and are out of scope here.

Packages:

| Runtime | Path | Install |
|---------|------|---------|
| Python | `src/pii_mcp` | `pip install pii-mcp` |
| TypeScript | `typescript/` | `npm install pii-mcp` |
| Rust core | `crates/pii-core` | shared by both (PyO3 / N-API) |

## Install (Python)

```bash
pip install "pii-mcp[fastmcp]"   # FastMCP >= 3.0.0
# or
pip install pii-mcp              # core only (pure Python, no Rust toolchain)
```

### Optional Rust core (Python)

Default installs stay pure Python. To accelerate scrubbing with the shared
`pii-core` crate (PyO3), build the optional extension locally:

```bash
pip install -e ".[native]"
maturin develop --release --manifest-path crates/pii-mcp-native/Cargo.toml
```

When `pii_mcp._native` is importable, `scrub_text` / `scrub_payload` use it.
Force the Python path with `PII_MCP_BACKEND=python`.

#### Performance (Python vs Rust release)

Medians from `scripts/bench_backends.py` on macOS arm64 / CPython 3.14.7
(release native build; debug builds are not representative):

| Case | Python | Rust | Speedup |
|------|--------|------|---------|
| Short clean text | 0.234 ms | 0.023 ms | 10.2× |
| Short mixed PII | 0.058 ms | 0.007 ms | 8.9× |
| 100 KiB sparse PII | 20.4 ms | 2.0 ms | 10.2× |
| 1 MiB sparse PII | 203 ms | 20.4 ms | 10.0× |
| Nested JSON payload | 12.4 ms | 1.2 ms | 10.3× |
| 1k× tiny `scrub_text` | 54.3 ms | 6.8 ms | 8.0× |

```bash
python scripts/bench_backends.py
```

## FastMCP (Python)

```python
from fastmcp import FastMCP
from pii_mcp.fastmcp import PiiScrubMiddleware

mcp = FastMCP("MyServer")
mcp.add_middleware(PiiScrubMiddleware())  # languages=["en", "nl"] by default
# mcp.add_middleware(PiiScrubMiddleware(languages=["en", "nl", "de"]))
```

Results only. On scrub failure or oversize, the result is withheld — never forwarded unmasked.

## Core (Python)

```python
from pii_mcp import scrub_text, scrub_payload

scrub_text("mail ada@example.com")
scrub_payload({"email": "ada@example.com"}, languages=["en"])
```

## Install (TypeScript)

```bash
npm install pii-mcp
```

Default installs stay pure TypeScript. To use the same `pii-core` crate via
N-API from a clone of this repo (shared with Python’s PyO3 addon):

```bash
cd typescript
npm install
npm run build
npm run build:native   # requires a Rust toolchain; needs ../crates/pii-core
```

Published `npm install pii-mcp` is JS-only until optional native artifacts ship.
When a locally built napi addon is loadable, `scrubText` / `scrubPayload` use it.
Force the JS path with `PII_MCP_BACKEND=js`. See [`typescript/README.md`](typescript/README.md).

#### Performance (TypeScript vs Rust release)

Medians from `scripts/bench_backends.mjs` on macOS arm64 / Node 22
(release napi build). V8 is already fast, so napi wins are modest on
larger/mixed inputs; tiny calls can favor pure JS (FFI overhead):

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

### Core (TypeScript)

```ts
import { scrubText, scrubPayload, usingNative } from "pii-mcp";

scrubText("mail ada@example.com");
scrubPayload({ email: "ada@example.com" }, { languages: ["en"] });
usingNative();
```

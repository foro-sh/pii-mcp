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

## Install

```bash
pip install "pii-mcp[fastmcp]"   # FastMCP >= 3.0.0
# or
pip install pii-mcp              # core only (pure Python, no Rust toolchain)
```

### Optional Rust core

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
| Short clean text | 0.233 ms | 0.026 ms | 9.1× |
| Short mixed PII | 0.057 ms | 0.009 ms | 6.3× |
| 100 KiB sparse PII | 20.3 ms | 2.1 ms | 9.7× |
| 1 MiB sparse PII | 205 ms | 21.5 ms | 9.5× |
| Nested JSON payload | 12.3 ms | 1.3 ms | 9.8× |
| 1k× tiny `scrub_text` | 53.4 ms | 8.1 ms | 6.6× |

```bash
python scripts/bench_backends.py
```

## FastMCP

```python
from fastmcp import FastMCP
from pii_mcp.fastmcp import PiiScrubMiddleware

mcp = FastMCP("MyServer")
mcp.add_middleware(PiiScrubMiddleware())  # languages=["en", "nl"] by default
# mcp.add_middleware(PiiScrubMiddleware(languages=["en", "nl", "de"]))
```

Results only. On scrub failure or oversize, the result is withheld — never forwarded unmasked.

## Core

```python
from pii_mcp import scrub_text, scrub_payload

scrub_text("mail ada@example.com")
scrub_payload({"email": "ada@example.com"}, languages=["en"])
```

# pii-mcp

**Scrub PII before it reaches the model.**

Pattern-based redaction for [MCP](https://modelcontextprotocol.io/) tool results
(regex + checksums). Drop-in FastMCP middleware — no cloud NER, no shipping
payloads to a third-party redactor. Language packs: `en`, `nl`, and opt-in `de`.

[![PyPI](https://img.shields.io/pypi/v/pii-mcp.svg)](https://pypi.org/project/pii-mcp/)
[![npm](https://img.shields.io/npm/v/pii-mcp.svg)](https://www.npmjs.com/package/pii-mcp)
[![CI](https://github.com/foro-sh/pii-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/foro-sh/pii-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Why

Agent stacks leak structured identifiers through tool results: emails, IBANs,
cards, national IDs. `pii-mcp` masks those at the MCP boundary so they never
reach the model. On scrub failure or oversize input, the result is **withheld**
— never forwarded unmasked.

## Demo

```python
from pii_mcp import scrub_text

scrub_text(
    "Contact ada@example.com — IBAN NL91 ABNA 0417 1643 00 — card 4111111111111111"
)
# → Contact [EMAIL] — IBAN [IBAN] — card [CREDIT_CARD]
```

## Quick start

```bash
pip install "pii-mcp[fastmcp]"   # FastMCP >= 3.0.0
# or: pip install pii-mcp        # core only (Rust-accelerated wheels on supported platforms)
# or: npm install pii-mcp
```

```python
from fastmcp import FastMCP
from pii_mcp.fastmcp import PiiScrubMiddleware

mcp = FastMCP("MyServer")
mcp.add_middleware(PiiScrubMiddleware())  # languages=["en", "nl"] by default
# mcp.add_middleware(PiiScrubMiddleware(languages=["en", "nl", "de"]))
```

```python
from pii_mcp import scrub_text, scrub_payload

scrub_text("mail ada@example.com")
scrub_payload({"email": "ada@example.com"}, languages=["en"])
```

## Scope

Masks emails, IBANs, cards, BICs, MACs, IMEIs, IPs, coordinates, BSNs, US SSNs,
German tax IDs, Dutch BTW-ids, Dutch passport/ID numbers, phones, Dutch
postcodes, and Dutch license plates — **not** NER for person names or full
street addresses.

Aligned with
[AP: wat zijn persoonsgegevens](https://www.autoriteitpersoonsgegevens.nl/themas/basis-avg/privacy-en-persoonsgegevens/wat-zijn-persoonsgegevens)
where pattern/checksum detection can reach them. Names, free-text health data
(allergies), photos/audio/video, unstructured klant-/personeelsnummers, and
full street addresses need NER or media handling and stay out of scope.

### AP coverage (pattern layer)

| AP example / category                         | Detector                               | Notes                         |
| --------------------------------------------- | -------------------------------------- | ----------------------------- |
| e-mail / contact                              | `email`, `phone`                       |                               |
| IP-adres                                      | `ip`                                   | Indirect identifier           |
| Locatiegegevens                               | `location`                             | Decimal lat/lon               |
| Financiële gegevens                           | `iban`, `credit_card`, `bic`, `vat_id` |                               |
| BSN / nationaal ID                            | `bsn`, `passport`                      | Passport/NIK format (nl pack) |
| Online / device IDs                           | `mac`, `imei`                          | IMEI: grouped forms + Luhn    |
| Adres (structured)                            | `address`                              | NL postcode only              |
| Kenteken                                      | `license_plate`                        | nl pack                       |
| Naam, pasfoto, allergieën, koopgedrag, camera | —                                      | NER / media                   |

## Packages

| Runtime    | Path              | Install                       |
| ---------- | ----------------- | ----------------------------- |
| Python     | `src/pii_mcp`     | `pip install pii-mcp`         |
| TypeScript | `typescript/`     | `npm install pii-mcp`         |
| Rust core  | `crates/pii-core` | shared by both (PyO3 / N-API) |

## Install (Python)

```bash
pip install "pii-mcp[fastmcp]"   # FastMCP >= 3.0.0
# or
pip install pii-mcp              # core; platform wheels include Rust acceleration
```

### Rust core (Python)

Published platform wheels ship `pii_mcp._native` (PyO3 over `pii-core`). Pip
prefers those on supported OS/arch; elsewhere (or with `--no-binary`) you get
the pure-Python hatchling wheel/sdist and the same scrub API.

When `_native` is importable, `scrub_text` / `scrub_payload` use it. Force the
Python path with `PII_MCP_BACKEND=python`; require native with
`PII_MCP_BACKEND=native`.

Local development from a clone (optional):

```bash
pip install -e ".[native]"
maturin develop --release --manifest-path crates/pii-mcp-native/Cargo.toml
```

#### Performance (Python vs Rust release)

Medians from `scripts/bench_backends.py` on macOS arm64 / CPython 3.14.7
(release native build; debug builds are not representative):

| Case                  | Python   | Rust     | Speedup |
| --------------------- | -------- | -------- | ------- |
| Short clean text      | 0.234 ms | 0.023 ms | 10.2×   |
| Short mixed PII       | 0.058 ms | 0.007 ms | 8.9×    |
| 100 KiB sparse PII    | 20.4 ms  | 2.0 ms   | 10.2×   |
| 1 MiB sparse PII      | 203 ms   | 20.4 ms  | 10.0×   |
| Nested JSON payload   | 12.4 ms  | 1.2 ms   | 10.3×   |
| 1k× tiny `scrub_text` | 54.3 ms  | 6.8 ms   | 8.0×    |

```bash
python scripts/bench_backends.py
```

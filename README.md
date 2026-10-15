# pii-mcp

Pattern-based PII redaction for MCP servers (regex + checksums). Masks emails,
IBANs, cards, BICs, MACs, IMEIs, IPs, coordinates, BSNs, US SSNs and ITINs, UK
National Insurance and NHS numbers, German tax IDs, Dutch BTW-ids, Dutch
passport/ID numbers, phones, street + house number addresses, Dutch and UK
postcodes, and Dutch license plates in tool results.
Language packs: `en`, `nl`, and opt-in `de`.

[![PyPI](https://img.shields.io/pypi/v/pii-mcp.svg)](https://pypi.org/project/pii-mcp/)
[![npm](https://img.shields.io/npm/v/pii-mcp.svg)](https://www.npmjs.com/package/pii-mcp)
[![CI](https://github.com/foro-sh/pii-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/foro-sh/pii-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/foro-sh/pii-mcp?style=social)](https://github.com/foro-sh/pii-mcp)

If pii-mcp saves you time, a ⭐ helps others find it.

## Example

```python
from pii_mcp import scrub_text

scrub_text(
    "Contact ada@example.com. IBAN NL91 ABNA 0417 1643 00. card 4111111111111111"
)
# Contact [EMAIL]. IBAN [IBAN]. card [CREDIT_CARD]
```

For runnable scripts including a FastMCP server and payload scrubbing, see the [`examples/`](examples/) directory.

## Install

```bash
pip install "pii-mcp[fastmcp]"   # FastMCP >= 3.0.0
# or
pip install pii-mcp              # core; platform wheels include Rust acceleration
# or
npm install pii-mcp
```

### FastMCP

```python
from fastmcp import FastMCP
from pii_mcp.fastmcp import PiiScrubMiddleware

mcp = FastMCP("MyServer")
mcp.add_middleware(PiiScrubMiddleware())  # languages=["en", "nl"] by default
# mcp.add_middleware(PiiScrubMiddleware(languages=["en", "nl", "de"]))
```

Results only. On scrub failure or oversize, the result is withheld, never
forwarded unmasked.

### Core

```python
from pii_mcp import scrub_text, scrub_payload

scrub_text("mail ada@example.com")
scrub_payload({"email": "ada@example.com"}, languages=["en"])
```

## Scope

Pattern Tier 1 only: structured identifiers that regex and checksums can
reach. Aligned with
[AP: wat zijn persoonsgegevens](https://www.autoriteitpersoonsgegevens.nl/themas/basis-avg/privacy-en-persoonsgegevens/wat-zijn-persoonsgegevens)
where that layer applies. Free-text health data (allergies), photos/audio/
video, and unstructured klant-/personeelsnummers stay out of scope.

`person` is pattern / key-aware when available (issue #52); until then the
count stays `0`. Prose name NER is out of band — this package does not ship
an in-process NER model. Decimal/DMS `location` coordinates stay here;
free-text place names do not.

### Using with foro / Presidio

| Layer | Owner |
| ----- | ----- |
| Pattern / checksum / language packs / MCP middleware | this package (Tier 1) |
| PERSON / LOCATION NER on API paths | Presidio or another NER sidecar (Tier 2) |

Live MCP gates in user containers should run Tier 1 only (no model). On
platforms such as foro, keep NER in one Presidio sidecar on API paths — do
not stack a second in-process NER beside it.

### AP coverage (pattern layer)

| AP example / category                         | Detector                               | Notes                           |
| --------------------------------------------- | -------------------------------------- | ------------------------------- |
| e-mail / contact                              | `email`, `phone`                       | Incl. Unicode (EAI/IDN) email   |
| IP-adres                                      | `ip`                                   | Indirect identifier             |
| Locatiegegevens                               | `location`                             | Decimal and DMS lat/lon         |
| Financiële gegevens                           | `iban`, `credit_card`, `bic`, `vat_id` | NL BTW / DE USt-IdNr            |
| BSN / nationaal ID                            | `bsn`, `passport`                      | Passport/NIK format (nl pack)   |
| Nationaal ID (US / UK)                        | `ssn`, `tax_id`                        | US SSN/ITIN, UK NINO (en pack)  |
| Gezondheidsgegevens (health ID)               | `ssn`                                  | UK NHS number, grouped (en)     |
| Online / device IDs                           | `mac`, `imei`                          | IMEI: grouped forms + Luhn      |
| Adres                                         | `address`                              | Street + number; NL/UK postcode |
| Kenteken                                      | `license_plate`                        | nl pack                         |
| Naam                                          | `person`                               | Pattern/key-aware when available (#52); prose NER out of band |
| Pasfoto, allergieën, koopgedrag, camera       |                                        | Media / free text               |

## Packages

| Runtime    | Path              | Install                       |
| ---------- | ----------------- | ----------------------------- |
| Python     | `src/pii_mcp`     | `pip install pii-mcp`         |
| TypeScript | `typescript/`     | `npm install pii-mcp`         |
| Rust core  | `crates/pii-core` | shared by both (PyO3 / N-API) |

## Rust core (Python)

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

### Performance (Python vs Rust release)

Medians from `scripts/bench_backends.py` on macOS arm64 / CPython 3.14.7
(release native build; debug builds are not representative):

| Case                  | Python   | Rust     | Speedup |
| --------------------- | -------- | -------- | ------- |
| Short clean text      | 0.234 ms | 0.023 ms | 10.2x   |
| Short mixed PII       | 0.058 ms | 0.007 ms | 8.9x    |
| 100 KiB sparse PII    | 20.4 ms  | 2.0 ms   | 10.2x   |
| 1 MiB sparse PII      | 203 ms   | 20.4 ms  | 10.0x   |
| Nested JSON payload   | 12.4 ms  | 1.2 ms   | 10.3x   |
| 1k x tiny `scrub_text` | 54.3 ms  | 6.8 ms   | 8.0x    |

```bash
python scripts/bench_backends.py
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup, how to add a detector, and the checks a PR must pass.

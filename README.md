# pii-mcp

Pattern-based PII scrubbing for MCP servers (regex + checksums), with an
optional NER pass for person names in the Rust backend. Masks emails, IBANs,
cards, BICs, MACs, IMEIs, IPs, coordinates, BSNs, US SSNs and ITINs, German
tax IDs, Dutch BTW-ids, Dutch passport/ID numbers, phones, street + house
number addresses, Dutch and UK postcodes, and Dutch license plates in tool
results.
Language packs: `en`, `nl`, and opt-in `de`.

[![PyPI](https://img.shields.io/pypi/v/pii-mcp.svg)](https://pypi.org/project/pii-mcp/)
[![npm](https://img.shields.io/npm/v/pii-mcp.svg)](https://www.npmjs.com/package/pii-mcp)
[![CI](https://github.com/foro-sh/pii-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/foro-sh/pii-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

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

Aligned with
[AP: wat zijn persoonsgegevens](https://www.autoriteitpersoonsgegevens.nl/themas/basis-avg/privacy-en-persoonsgegevens/wat-zijn-persoonsgegevens)
where pattern/checksum detection can reach them. Person names need the
opt-in NER build ([below](#person-names-optional-ner)). Free-text health data
(allergies), photos/audio/video, and unstructured klant-/personeelsnummers
stay out of scope.

### AP coverage (pattern layer)

| AP example / category                         | Detector                               | Notes                           |
| --------------------------------------------- | -------------------------------------- | ------------------------------- |
| e-mail / contact                              | `email`, `phone`                       | Incl. Unicode (EAI/IDN) email   |
| IP-adres                                      | `ip`                                   | Indirect identifier             |
| Locatiegegevens                               | `location`                             | Decimal and DMS lat/lon         |
| Financiële gegevens                           | `iban`, `credit_card`, `bic`, `vat_id` | NL BTW-id; DE USt-IdNr (de pack) |
| BSN / nationaal ID                            | `bsn`, `passport`                      | Passport/NIK format (nl pack)   |
| Online / device IDs                           | `mac`, `imei`                          | IMEI: grouped forms + Luhn      |
| Adres                                         | `address`                              | Street + number; NL/UK postcode |
| Kenteken                                      | `license_plate`                        | nl pack                         |
| Naam                                          | `person`                               | Opt-in NER build only           |
| Pasfoto, allergieën, koopgedrag, camera       |                                        | Media / free text               |

## Person names (optional NER)

`ner=True` runs an XLM-R token classifier
([`Davlan/xlm-roberta-base-ner-hrl`](https://huggingface.co/Davlan/xlm-roberta-base-ner-hrl),
AFL-3.0; EN/NL/DE among its languages) after the pattern detectors and masks
person names as `[PERSON]`. It runs in the Rust core on
[candle](https://github.com/huggingface/candle) (CPU, fp32) and is off by
default: published wheels and the npm package are built without it, and no
weights ship with any package.

Build with the `ner` feature:

```bash
maturin develop --release --features ner                  # Python
(cd typescript && npm run build:native -- --features ner) # Node
cargo build -p pii-core --features ner                    # Rust
```

Download the pinned weights (1.1 GB) and the matching XLM-R tokenizer (MIT)
into one directory, and point `PII_MCP_NER_MODEL` at it:

```bash
mkdir -p ner-model && cd ner-model
M=https://huggingface.co/Davlan/xlm-roberta-base-ner-hrl/resolve/253f557bd8249b8515114cfd7f71974fe5fa4d2f
T=https://huggingface.co/FacebookAI/xlm-roberta-base/resolve/e73636d4f797dec63c3081bb6ed5c7b0bb3f2089
curl -fL -O "$M/config.json" -O "$M/model.safetensors" -O "$T/tokenizer.json"
export PII_MCP_NER_MODEL="$PWD"
```

```python
scrub_text("Mail Ada Lovelace at ada@example.com", ner=True)
# {'text': 'Mail [PERSON] at [EMAIL]', ...}
```

- Pattern hits are masked first; the NER pass never re-tags a placeholder, so
  nothing is counted twice.
- `PII_MCP_NER_THRESHOLD` (default `0.9`) is the minimum person probability
  per token. The default favors precision; lower it (for example `0.5`) to
  mask more names at the cost of more false positives.
- `ner=True` raises `PiiScrubError` when the build has no `ner` feature, the
  backend is pure Python / TypeScript, or the model directory is missing or
  invalid. Text is never returned with the NER pass silently skipped.

Cost on macOS arm64 (M4 Pro), `scripts/bench_backends.py` with
`PII_MCP_NER_MODEL` set:

| Case               | Regex only | `ner=True` |
| ------------------ | ---------- | ---------- |
| Short mixed PII    | 0.028 ms   | 67 ms      |
| 2 KiB tool result  | 0.22 ms    | 532 ms     |
| 16 KiB tool result | 2.3 ms     | 4.6 s      |

Inference time grows with input length, at about 0.3 s per KiB here: a 1 MiB
tool result takes about 5 minutes. Use `ner=True` for results of a few KiB,
not for bulk text. Model load takes 2.0 s once per process; peak RSS is about
2.4 GB. Inference is fp32 only: candle's XLM-R implementation builds its
attention mask in F32, so fp16 weights do not run.

On the eval (`PII_MCP_NER_MODEL=<dir> python eval/score.py --ner`, EN/NL/DE
names in 15 contexts), `person` scores recall 0.987 and precision 0.931. Most
false positives are company names such as `Albert Heijn`. The address
generators only produce the street shapes the patterns support, so the
address recall of 1.0 covers those shapes only; precision is measured with
the `en`, `nl` and `de` packs against bare street names and company names.
Words that end in a street suffix and are followed by a number (`Keypad 3`,
`Supermarkt 24`) are masked on purpose, since dropping those suffixes leaks
real addresses such as `Nieuwmarkt 4`.

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

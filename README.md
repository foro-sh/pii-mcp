# pii-mcp

Tier-1 PII scrubbing for MCP servers. Primary DX: one-line [FastMCP](https://gofastmcp.com/) middleware that masks structured PII in tool (and resource/prompt) **results** — no tool-handler changes, no foro.sh sidecar.

This is **not** full foro.sh Data protection: no Tier-2 NER (Presidio), no hosted gate metrics. Sync regex + checksum detectors only (email, IBAN, credit card, Dutch BSN, phone).

## Install

```bash
pip install "pii-mcp[fastmcp]"
```

Core scrubbers need no FastMCP:

```bash
pip install pii-mcp
```

**FastMCP version floor:** `fastmcp>=3.0.0` (middleware hooks `on_call_tool` / `on_read_resource` / `on_get_prompt` and `ToolResult` with `content` / `structured_content`). CI exercises this floor.

## FastMCP one-liner

```python
from fastmcp import FastMCP
from pii_mcp.fastmcp import PiiScrubMiddleware

mcp = FastMCP("MyServer")
mcp.add_middleware(
    PiiScrubMiddleware(
        languages=["en", "nl"],  # default: both
        on_scrub=lambda report: print(report.counts),  # optional; counts only
    )
)
```

Under the hood the middleware:

1. Runs `await call_next(context)`
2. Walks outbound `result.content` (text blocks) and `result.structured_content`
3. On scrub failure or oversize: **fail closed** — returns a withheld result (never forwards unmasked text)
4. Calls `on_scrub(ScrubReport)` after a successful scrub (no plaintext)

Also scrubs `on_read_resource` and `on_get_prompt`. Does **not** scrub tool arguments or `on_list_tools` schemas.

### Withheld result example

If input exceeds the 32 MiB scrub cap (or the walk fails), clients see:

```text
Tool result withheld: it could not be scrubbed for PII.
```

## Language packs

| Layer | Detectors | When |
|-------|-----------|------|
| Universal | email, IBAN, credit card | Always |
| `nl` | Dutch BSN; Dutch national phones; international (+/00) | `"nl"` in `languages` |
| `en` | North-American phones; international (+/00) | `"en"` in `languages` |

Default is `["en", "nl"]`. `languages=["en"]` does **not** mask Dutch BSN checksum hits.

## Library helpers (any MCP stack)

```python
from pii_mcp import scrub_text, scrub_payload

scrub_text("mail ada@example.com", languages=["en"])
# → {"text": "mail [EMAIL]", "found": True, "counts": {...}}

scrub_payload({"email": "ada@example.com"})
# → {"payload": {"email": "[EMAIL]"}, "found": True, "counts": {...}}
```

## Safety

- **Results only (v0)** — outbound tool/resource/prompt payloads
- **Redact, don't block** — mask in place (`[EMAIL]`, `[IBAN]`, …) and return per-type counts
- **Fail closed** — never return unscrubbed text on walk/parse/oversize failure
- **32 MiB** scrub input cap
- ReDoS-safe detector regexes (bounded quantifiers)

## Development

```bash
pip install -e ".[dev]"
pytest
```

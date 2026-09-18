# pii-mcp

Tier-1 PII scrubbing for MCP servers. Mask emails, IBANs, cards, BSNs, US SSNs,
German tax IDs, and phones in tool results — not full foro.sh Data protection
(no Tier-2 NER). Language packs: `en`, `nl`, and opt-in `de`.

## Install

```bash
pip install "pii-mcp[fastmcp]"   # FastMCP >= 3.0.0
# or
pip install pii-mcp              # core only
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

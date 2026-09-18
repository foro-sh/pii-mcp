# pii-mcp (TypeScript)

Pattern-based PII scrubbing for MCP servers (regex + checksums). Same detectors
as the Python package: emails, IBANs, cards, BICs, MACs, IPs, coordinates, BSNs,
US SSNs, German tax IDs, Dutch BTW-ids, phones, Dutch postcodes, and Dutch
license plates. Language packs: `en`, `nl`, and opt-in `de`.

## Install

```bash
npm install pii-mcp
```

Default installs are pure TypeScript (no Rust toolchain).

### Optional Rust core

Accelerate scrubbing with the shared `pii-core` crate via N-API:

```bash
cd typescript
npm install
npm run build:native   # requires a Rust toolchain
```

When the napi addon is loadable, `scrubText` / `scrubPayload` use it.
Force the JS path with `PII_MCP_BACKEND=js`. Require native with
`PII_MCP_BACKEND=native`.

## FastMCP

```ts
import { FastMCP } from "@prefecthq/fastmcp-ts/server";
import { PiiScrubMiddleware } from "pii-mcp/fastmcp";

const server = new FastMCP({ name: "MyServer", version: "1.0.0" });
server.use(new PiiScrubMiddleware()); // languages=["en","nl"] by default
// server.use(new PiiScrubMiddleware({ languages: ["en", "nl", "de"] }));
```

Results only. On scrub failure or oversize, the result is withheld — never
forwarded unmasked.

## Core

```ts
import { scrubText, scrubPayload, usingNative } from "pii-mcp";

scrubText("mail ada@example.com");
scrubPayload({ email: "ada@example.com" }, { languages: ["en"] });
usingNative(); // true when the napi addon is active
```

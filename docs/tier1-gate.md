# Tier 1 gate contract

Versioned API for foro user-container gates (`foro-proxy`) that replace the
hand-maintained `foro-pii.mts` copy. Pattern/checksum detectors only — no
Presidio, spaCy, or candle in the gate process.

**Packaging recommendation (hybrid):** ship the vendored pure-JS artifact for
the gate image; keep optional native napi for the API process. Matches the
zero-npm-deps container constraint without dropping Rust acceleration where
glibc/musl wheels are available.

Platform follow-up: [foro-sh/platform#1154](https://github.com/foro-sh/platform/issues/1154).

## Artifact

| Path | Role |
|------|------|
| `typescript/gate/pii-gate.mjs` | Generated single-file ESM (zero npm packages; Node built-ins only). **This** is what the gate image COPYs — not an `npm install`. |
| `typescript/src/gate.ts` | Source entry; also published as `pii-mcp/gate` for Node apps that already install the package (API process). |

Regenerate after detector changes:

```bash
cd typescript && npm run build:gate
```

CI / local tests fail if the committed artifact drifts from sources.

## Exports

| Name | Kind | Notes |
|------|------|--------|
| `scrubText(text, options?)` | function | Returns `{ text, found, counts }`. |
| `scrubPayload(payload, options?)` | function | Returns `{ payload, found, counts }`. |
| `PiiScrubError` | class | Fail-closed signal; `statusCode === 500`. Callers must not forward unscrubbed input. |
| `MAX_SCRUB_BYTES` | const | `32 * 1024 * 1024` (32 MiB). UTF-8 size of scrubbed string leaves. |
| `MAX_DEPTH` | const | `200`. Nesting past this throws `PiiScrubError`. |
| `PII_TYPES` | const | Every count key (always present, `0` when unused). |
| `emptyPiiCounts()` / `totalPiiCount()` / `mergeCounts()` | helpers | Same shape as the main package. |
| `DEFAULT_LANGUAGES` | const | `["en", "nl"]`. |
| `normalizeLanguages(languages)` | function | Unknown codes throw. |
| `normalizeTypes(types)` | function | Unknown types throw; `null` means every type. |

`options.languages` defaults to `DEFAULT_LANGUAGES` when omitted/`null`. Pass
`[]` for universal detectors only (no locale phone/ID packs).

`options.types` limits masking to the listed `PII_TYPES` (omitted/`null`:
all of them; `[]`: none). `options.allow` lists values that are never masked,
compared case-insensitively to the whole detected value; it never exempts a
`secret`. A hit left unmasked by either option is not counted, but its text is
still shielded from later detectors, so turning `phone` off does not let the
BSN detector mask a phone number's digits. With neither option set, output is
unchanged.

There is no `ner` option on the gate surface. Person-name NER stays Tier 2
(Presidio on platform-internal paths).

## Placeholders

| Detector family | Placeholder |
|-----------------|-------------|
| email | `[EMAIL]` |
| IBAN | `[IBAN]` |
| credit card | `[CREDIT_CARD]` |
| BSN | `[BSN]` |
| phone | `[PHONE]` |
| (other packs) | `[BIC]`, `[MAC]`, `[IMEI]`, `[IP]`, `[LOCATION]`, `[SSN]`, `[TAX_ID]`, `[VAT_ID]`, `[PASSPORT]`, `[ADDRESS]`, `[LICENSE_PLATE]`, … |
| secret (universal) | `[SECRET]` (after `Bearer`, only the credential) |

Coverage is a **superset** of current foro-pii Tier 1 (email, IBAN, card, BSN,
phone). Adoption fixtures: `eval/fixtures/foro_tier1.json`.

## Counts shape

`counts` is a `Record<PiiType, number>` with every `PII_TYPES` key present.
`found` is `totalPiiCount(counts) > 0`. `person` stays `0` on the gate (no NER).

## Binary field skip

During `scrubPayload` walks, leave these fields unchanged (siblings still
scrubbed):

- `data` when `type` is `"image"` or `"audio"` and `data` is a string
- `blob` when both `uri` and `blob` are strings

Matched by shape, not key alone. Binary leaves are excluded from the
`MAX_SCRUB_BYTES` string-leaf sum.

## Fail-closed rules

Throw `PiiScrubError` (never return the original payload) when:

- UTF-8 string-leaf bytes exceed `MAX_SCRUB_BYTES`
- Nesting exceeds `MAX_DEPTH`
- A non-plain object (Date, Map, class instance, …) appears in the walk

## Proxy integration (platform)

`foro-proxy` should call `scrubPayload` on `content`, `structuredContent`,
`contents`, `messages`, and `completion` fields of live MCP traffic. Import the
vendored file — do not add an `npm install` of this package inside the gate
image.

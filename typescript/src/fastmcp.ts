/**
 * FastMCP middleware: scrub outbound tool/resource/prompt results.
 *
 * Optional peer: ``@prefecthq/fastmcp-ts``. Implements the FastMCP ``Middleware``
 * hook shape without a hard runtime dependency.
 *
 * Results only — does not scrub tool arguments or list_tools schemas.
 * Fail closed: any scrub/walk error withholds the result (never forwards
 * unmasked text). Scrubs text content, structured payloads, and ``_meta``.
 * Binary resource bodies are left as-is; their meta is still scrubbed.
 */

import {
  DEFAULT_LANGUAGES,
  PiiScrubError,
  emptyPiiCounts,
  mergeCounts,
  scrubPayload,
  scrubText,
  totalPiiCount,
  type PiiCounts,
  type ScrubReport,
} from "./scrub.js";

export const WITHHELD_TEXT =
  "Tool result withheld: it could not be scrubbed for PII.";
export const WITHHELD_RESOURCE_TEXT =
  "Resource withheld: it could not be scrubbed for PII.";
export const WITHHELD_PROMPT_TEXT =
  "Prompt withheld: it could not be scrubbed for PII.";

export type OnScrub = (report: ScrubReport) => void;

export type PiiScrubMiddlewareOptions = {
  languages?: readonly string[] | null;
  onScrub?: OnScrub;
};

type Next<R = unknown> = () => Promise<R>;

type MiddlewareContext = {
  readonly method: string;
  readonly request: unknown;
};

type TextBlock = { type: "text"; text: string; [key: string]: unknown };

type ContentBlock = TextBlock | { type: string; [key: string]: unknown };

type CallToolResult = {
  content?: ContentBlock[];
  structuredContent?: unknown;
  _meta?: unknown;
  isError?: boolean;
  [key: string]: unknown;
};

type ResourceContents = {
  uri?: string;
  mimeType?: string;
  text?: string;
  blob?: string;
  _meta?: unknown;
  [key: string]: unknown;
};

type ReadResourceResult = {
  contents?: ResourceContents[];
  _meta?: unknown;
  [key: string]: unknown;
};

type PromptMessage = {
  role: string;
  content: ContentBlock | ContentBlock[];
  [key: string]: unknown;
};

type GetPromptResult = {
  description?: string;
  messages?: PromptMessage[];
  _meta?: unknown;
  [key: string]: unknown;
};

function reportFromCounts(counts: PiiCounts): ScrubReport {
  return { found: totalPiiCount(counts) > 0, counts };
}

function isTextBlock(block: ContentBlock): block is TextBlock {
  return block.type === "text" && typeof block.text === "string";
}

function scrubTextBlocks(
  blocks: ContentBlock[],
  languages: readonly string[] | null | undefined,
): { blocks: ContentBlock[]; counts: PiiCounts } {
  const counts = emptyPiiCounts();
  const out: ContentBlock[] = [];
  for (const block of blocks) {
    if (isTextBlock(block)) {
      const result = scrubText(block.text, { languages });
      for (const t of Object.keys(result.counts) as (keyof PiiCounts)[]) {
        counts[t] += result.counts[t];
      }
      out.push({ ...block, text: result.text });
    } else {
      out.push(block);
    }
  }
  return { blocks: out, counts };
}

function scrubMeta(
  meta: unknown,
  languages: readonly string[] | null | undefined,
): { meta: unknown; counts: PiiCounts } {
  if (meta === undefined || meta === null) {
    return { meta, counts: emptyPiiCounts() };
  }
  if (typeof meta === "string") {
    const result = scrubText(meta, { languages });
    return { meta: result.text, counts: result.counts };
  }
  const result = scrubPayload(meta, { languages });
  return { meta: result.payload, counts: result.counts };
}

function looksLikeToolResult(value: unknown): value is CallToolResult {
  return (
    value !== null &&
    typeof value === "object" &&
    Array.isArray((value as CallToolResult).content)
  );
}

function looksLikeResourceResult(value: unknown): value is ReadResourceResult {
  return (
    value !== null &&
    typeof value === "object" &&
    Array.isArray((value as ReadResourceResult).contents)
  );
}

function looksLikePromptResult(value: unknown): value is GetPromptResult {
  return (
    value !== null &&
    typeof value === "object" &&
    Array.isArray((value as GetPromptResult).messages)
  );
}

function unwrapToolResult(value: unknown): {
  result: CallToolResult;
  wrap: (next: CallToolResult) => unknown;
} {
  if (
    value !== null &&
    typeof value === "object" &&
    "result" in value &&
    looksLikeToolResult((value as { result: unknown }).result)
  ) {
    const wrapper = value as { result: CallToolResult };
    return {
      result: wrapper.result,
      wrap: (next) => {
        const proto = Object.getPrototypeOf(wrapper);
        if (proto !== null && proto !== Object.prototype) {
          return Object.assign(Object.create(proto), wrapper, { result: next });
        }
        return { ...wrapper, result: next };
      },
    };
  }
  if (looksLikeToolResult(value)) {
    return { result: value, wrap: (next) => next };
  }
  throw new PiiScrubError(
    "tool result is not a scrubbable CallToolResult shape",
  );
}

/**
 * Redact pattern-based PII in outbound MCP results (tools, resources, prompts).
 */
export class PiiScrubMiddleware {
  private readonly languages: readonly string[];
  private readonly onScrub: OnScrub | undefined;

  constructor(options: PiiScrubMiddlewareOptions = {}) {
    this.languages =
      options.languages !== undefined && options.languages !== null
        ? [...options.languages]
        : [...DEFAULT_LANGUAGES];
    this.onScrub = options.onScrub;
  }

  private emit(counts: PiiCounts): void {
    if (this.onScrub !== undefined) {
      this.onScrub(reportFromCounts(counts));
    }
  }

  private withheldTool(): CallToolResult {
    return { content: [{ type: "text", text: WITHHELD_TEXT }] };
  }

  private withheldResource(): ReadResourceResult {
    return {
      contents: [{ uri: "pii-mcp:withheld", text: WITHHELD_RESOURCE_TEXT }],
    };
  }

  private withheldPrompt(): GetPromptResult {
    return {
      messages: [
        {
          role: "user",
          content: { type: "text", text: WITHHELD_PROMPT_TEXT },
        },
      ],
    };
  }

  scrubToolResult(value: unknown): unknown {
    const { result, wrap } = unwrapToolResult(value);
    const parts: PiiCounts[] = [];
    const content = [...(result.content ?? [])];
    const scrubbedContent = scrubTextBlocks(content, this.languages);
    parts.push(scrubbedContent.counts);

    let structured = result.structuredContent;
    if (structured !== undefined) {
      const scrubbed = scrubPayload(structured, { languages: this.languages });
      structured = scrubbed.payload;
      parts.push(scrubbed.counts);
    }

    const meta = scrubMeta(result._meta, this.languages);
    parts.push(meta.counts);

    this.emit(mergeCounts(parts));
    const next: CallToolResult = {
      ...result,
      content: scrubbedContent.blocks,
      structuredContent: structured,
      _meta: meta.meta,
    };
    return wrap(next);
  }

  scrubResourceResult(value: unknown): ReadResourceResult {
    if (typeof value === "string") {
      const scrubbed = scrubText(value, { languages: this.languages });
      this.emit(scrubbed.counts);
      return {
        contents: [{ uri: "pii-mcp:text", text: scrubbed.text }],
      };
    }
    if (!looksLikeResourceResult(value)) {
      throw new PiiScrubError(
        "resource result is not a scrubbable ReadResourceResult shape",
      );
    }
    const parts: PiiCounts[] = [];
    const contents: ResourceContents[] = [];
    for (const item of value.contents ?? []) {
      const itemMeta = scrubMeta(item._meta, this.languages);
      parts.push(itemMeta.counts);
      if (typeof item.text === "string") {
        const scrubbed = scrubText(item.text, { languages: this.languages });
        parts.push(scrubbed.counts);
        contents.push({ ...item, text: scrubbed.text, _meta: itemMeta.meta });
      } else {
        contents.push({ ...item, _meta: itemMeta.meta });
      }
    }
    const meta = scrubMeta(value._meta, this.languages);
    parts.push(meta.counts);
    this.emit(mergeCounts(parts));
    return { ...value, contents, _meta: meta.meta };
  }

  scrubPromptResult(value: unknown): GetPromptResult {
    if (!looksLikePromptResult(value)) {
      throw new PiiScrubError(
        "prompt result is not a scrubbable GetPromptResult shape",
      );
    }
    const parts: PiiCounts[] = [];
    const messages: PromptMessage[] = [];
    for (const message of value.messages ?? []) {
      const content = message.content;
      if (Array.isArray(content)) {
        const scrubbed = scrubTextBlocks(content, this.languages);
        parts.push(scrubbed.counts);
        messages.push({ ...message, content: scrubbed.blocks });
      } else if (content && isTextBlock(content)) {
        const scrubbed = scrubText(content.text, { languages: this.languages });
        parts.push(scrubbed.counts);
        messages.push({
          ...message,
          content: { ...content, text: scrubbed.text },
        });
      } else {
        messages.push(message);
      }
    }

    let description = value.description;
    if (typeof description === "string") {
      const desc = scrubText(description, { languages: this.languages });
      description = desc.text;
      parts.push(desc.counts);
    }

    const meta = scrubMeta(value._meta, this.languages);
    parts.push(meta.counts);
    this.emit(mergeCounts(parts));
    const next: GetPromptResult = { ...value, messages, _meta: meta.meta };
    if (description !== undefined) {
      next.description = description;
    }
    return next;
  }

  async onCallTool(
    _ctx: MiddlewareContext,
    next: Next,
  ): Promise<unknown> {
    const result = await next();
    if (isInputRequired(result)) {
      return result;
    }
    try {
      return this.scrubToolResult(result);
    } catch {
      return this.withheldTool();
    }
  }

  async onReadResource(
    _ctx: MiddlewareContext,
    next: Next,
  ): Promise<unknown> {
    const result = await next();
    if (isInputRequired(result)) {
      return result;
    }
    try {
      return this.scrubResourceResult(result);
    } catch {
      return this.withheldResource();
    }
  }

  async onGetPrompt(
    _ctx: MiddlewareContext,
    next: Next,
  ): Promise<unknown> {
    const result = await next();
    if (isInputRequired(result)) {
      return result;
    }
    try {
      return this.scrubPromptResult(result);
    } catch {
      return this.withheldPrompt();
    }
  }
}

function isInputRequired(value: unknown): boolean {
  return (
    value !== null &&
    typeof value === "object" &&
    (value as { resultType?: unknown }).resultType === "input_required"
  );
}

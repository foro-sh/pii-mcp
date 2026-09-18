import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resetNativeCache } from "../src/native.js";
import {
  PiiScrubMiddleware,
  WITHHELD_TEXT,
} from "../src/fastmcp.js";
import type { ScrubReport } from "../src/scrub.js";

const originalBackend = process.env.PII_MCP_BACKEND;

beforeEach(() => {
  if (originalBackend === undefined) {
    process.env.PII_MCP_BACKEND = "js";
  } else {
    process.env.PII_MCP_BACKEND = originalBackend;
  }
  resetNativeCache();
});

afterEach(() => {
  if (originalBackend === undefined) {
    delete process.env.PII_MCP_BACKEND;
  } else {
    process.env.PII_MCP_BACKEND = originalBackend;
  }
  resetNativeCache();
});

describe("PiiScrubMiddleware", () => {
  it("masks tool result content", async () => {
    const mw = new PiiScrubMiddleware();
    const result = await mw.onCallTool({ method: "tools/call", request: {} }, async () => ({
      content: [
        {
          type: "text",
          text: "Contact ada@example.com or NL91ABNA0417164300",
        },
      ],
    }));
    expect(result).toEqual({
      content: [{ type: "text", text: "Contact [EMAIL] or [IBAN]" }],
    });
  });

  it("masks structured content", async () => {
    const mw = new PiiScrubMiddleware();
    const result = (await mw.onCallTool(
      { method: "tools/call", request: {} },
      async () => ({
        content: [{ type: "text", text: "ok" }],
        structuredContent: { email: "ada@example.com" },
      }),
    )) as {
      structuredContent: { email: string };
    };
    expect(result.structuredContent).toEqual({ email: "[EMAIL]" });
  });

  it("emits onScrub report without plaintext", async () => {
    const reports: ScrubReport[] = [];
    const mw = new PiiScrubMiddleware({ onScrub: (r) => reports.push(r) });
    await mw.onCallTool({ method: "tools/call", request: {} }, async () => ({
      content: [{ type: "text", text: "mail ada@example.com" }],
    }));
    expect(reports).toHaveLength(1);
    expect(reports[0]?.found).toBe(true);
    expect(reports[0]?.counts.email).toBe(1);
    expect(JSON.stringify(reports[0])).not.toContain("ada@");
  });

  it("withholds on scrub failure", async () => {
    const mw = new PiiScrubMiddleware();
    const result = (await mw.onCallTool(
      { method: "tools/call", request: {} },
      async () => ({ when: new Date() }),
    )) as { content: { text: string }[] };
    expect(result.content[0]?.text).toBe(WITHHELD_TEXT);
  });

  it("masks resource text", async () => {
    const mw = new PiiScrubMiddleware();
    const result = (await mw.onReadResource(
      { method: "resources/read", request: {} },
      async () => ({
        contents: [{ uri: "note://1", text: "mail ada@example.com" }],
      }),
    )) as { contents: { text: string }[] };
    expect(result.contents[0]?.text).toBe("mail [EMAIL]");
  });

  it("masks prompt messages", async () => {
    const mw = new PiiScrubMiddleware();
    const result = (await mw.onGetPrompt(
      { method: "prompts/get", request: {} },
      async () => ({
        messages: [
          {
            role: "user",
            content: { type: "text", text: "reach ada@example.com" },
          },
        ],
      }),
    )) as { messages: { content: { text: string } }[] };
    expect(result.messages[0]?.content.text).toBe("reach [EMAIL]");
  });
});

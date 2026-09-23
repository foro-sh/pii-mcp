"""FastMCP middleware: scrub outbound tool/resource/prompt results.

Requires ``pip install pii-mcp[fastmcp]`` (FastMCP 3.x).
Results only — does not scrub tool arguments or list_tools schemas.

Fail closed: any scrub/walk error withholds the result (never forwards
unmasked text). Scrubs text content, structured payloads, ``meta``, and
prompt ``description``. Binary resource bodies are left as-is; their meta
is still scrubbed.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from mcp.types import TextContent

from fastmcp.prompts.prompt import PromptResult
from fastmcp.resources.resource import ResourceContent, ResourceResult
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.tools.tool import ToolResult

from pii_mcp.scrub import (
    DEFAULT_LANGUAGES,
    PiiCounts,
    PiiScrubError,
    ScrubReport,
    empty_pii_counts,
    merge_counts,
    scrub_payload,
    scrub_text,
    total_pii_count,
)

WITHHELD_TEXT = "Tool result withheld: it could not be scrubbed for PII."
WITHHELD_RESOURCE_TEXT = "Resource withheld: it could not be scrubbed for PII."
WITHHELD_PROMPT_TEXT = "Prompt withheld: it could not be scrubbed for PII."

OnScrub = Callable[[ScrubReport], None]


def _report_from_counts(counts: PiiCounts) -> ScrubReport:
    return ScrubReport(found=total_pii_count(counts) > 0, counts=counts)


def _scrub_text_blocks(
    blocks: list[Any],
    *,
    languages: Sequence[str] | None,
) -> tuple[list[Any], PiiCounts]:
    counts = empty_pii_counts()
    out: list[Any] = []
    for block in blocks:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            result = scrub_text(text, languages=languages)
            for t, n in result["counts"].items():
                counts[t] += n
            if hasattr(block, "model_copy"):
                out.append(block.model_copy(update={"text": result["text"]}))
            else:
                out.append(TextContent(type="text", text=result["text"]))
        else:
            out.append(block)
    return out, counts


def _scrub_meta(
    meta: Any,
    *,
    languages: Sequence[str] | None,
) -> tuple[Any, PiiCounts]:
    """Scrub JSON-like meta; leave None as-is. Fail closed via scrub_payload."""
    if meta is None:
        return None, empty_pii_counts()
    if isinstance(meta, str):
        result = scrub_text(meta, languages=languages)
        return result["text"], result["counts"]
    result = scrub_payload(meta, languages=languages)
    return result["payload"], result["counts"]


class PiiScrubMiddleware(Middleware):
    """Redact pattern-based PII in outbound MCP results (tools, resources, prompts)."""

    def __init__(
        self,
        *,
        languages: Sequence[str] | None = None,
        on_scrub: OnScrub | None = None,
    ) -> None:
        super().__init__()
        self._languages: Sequence[str] = (
            tuple(languages) if languages is not None else DEFAULT_LANGUAGES
        )
        self._on_scrub = on_scrub

    def _emit(self, counts: PiiCounts) -> None:
        if self._on_scrub is not None:
            self._on_scrub(_report_from_counts(counts))

    def _withheld_tool(self) -> ToolResult:
        return ToolResult(
            content=[TextContent(type="text", text=WITHHELD_TEXT)],
            structured_content=None,
        )

    def _withheld_resource(self) -> ResourceResult:
        return ResourceResult(contents=WITHHELD_RESOURCE_TEXT)

    def _withheld_prompt(self) -> PromptResult:
        return PromptResult(messages=WITHHELD_PROMPT_TEXT)

    def _scrub_tool_result(self, result: ToolResult) -> ToolResult:
        parts: list[PiiCounts] = []
        content = list(result.content or [])
        new_content, c_counts = _scrub_text_blocks(
            content, languages=self._languages
        )
        parts.append(c_counts)

        structured = result.structured_content
        new_structured = structured
        if structured is not None:
            scrubbed = scrub_payload(structured, languages=self._languages)
            new_structured = scrubbed["payload"]
            parts.append(scrubbed["counts"])

        new_meta, meta_counts = _scrub_meta(
            result.meta, languages=self._languages
        )
        parts.append(meta_counts)

        merged = merge_counts(parts)
        self._emit(merged)
        return ToolResult(
            content=new_content,
            structured_content=new_structured,
            meta=new_meta,
        )

    def _scrub_resource_result(self, result: ResourceResult) -> ResourceResult:
        parts: list[PiiCounts] = []
        new_contents: list[ResourceContent] = []
        for item in result.contents:
            content = item.content
            item_meta = getattr(item, "meta", None)
            new_item_meta, item_meta_counts = _scrub_meta(
                item_meta, languages=self._languages
            )
            parts.append(item_meta_counts)
            if isinstance(content, str):
                scrubbed = scrub_text(content, languages=self._languages)
                parts.append(scrubbed["counts"])
                if hasattr(item, "model_copy"):
                    new_contents.append(
                        item.model_copy(
                            update={
                                "content": scrubbed["text"],
                                "meta": new_item_meta,
                            }
                        )
                    )
                else:
                    new_contents.append(
                        ResourceContent(
                            content=scrubbed["text"],
                            mime_type=item.mime_type,
                            meta=new_item_meta,
                        )
                    )
            elif hasattr(item, "model_copy"):
                new_contents.append(
                    item.model_copy(update={"meta": new_item_meta})
                )
            else:
                new_contents.append(item)
        new_meta, meta_counts = _scrub_meta(
            result.meta, languages=self._languages
        )
        parts.append(meta_counts)
        self._emit(merge_counts(parts) if parts else empty_pii_counts())
        return ResourceResult(contents=new_contents, meta=new_meta)

    def _scrub_prompt_result(self, result: PromptResult) -> PromptResult:
        parts: list[PiiCounts] = []
        new_messages = []
        for message in result.messages:
            content = message.content
            text = getattr(content, "text", None)
            if isinstance(text, str):
                scrubbed = scrub_text(text, languages=self._languages)
                parts.append(scrubbed["counts"])
                if hasattr(content, "model_copy"):
                    new_content = content.model_copy(
                        update={"text": scrubbed["text"]}
                    )
                else:
                    new_content = TextContent(type="text", text=scrubbed["text"])
                if hasattr(message, "model_copy"):
                    new_messages.append(
                        message.model_copy(update={"content": new_content})
                    )
                else:
                    new_messages.append(
                        type(message)(role=message.role, content=new_content)
                    )
            else:
                new_messages.append(message)
        new_description = result.description
        if isinstance(result.description, str):
            desc = scrub_text(result.description, languages=self._languages)
            new_description = desc["text"]
            parts.append(desc["counts"])

        new_meta, meta_counts = _scrub_meta(
            result.meta, languages=self._languages
        )
        parts.append(meta_counts)

        self._emit(merge_counts(parts) if parts else empty_pii_counts())
        return PromptResult(
            messages=new_messages,
            description=new_description,
            meta=new_meta,
        )

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: Callable[[MiddlewareContext[Any]], Awaitable[ToolResult]],
    ) -> ToolResult:
        result = await call_next(context)
        try:
            return self._scrub_tool_result(result)
        except PiiScrubError:
            return self._withheld_tool()
        except Exception:
            return self._withheld_tool()

    async def on_read_resource(
        self,
        context: MiddlewareContext[Any],
        call_next: Callable[[MiddlewareContext[Any]], Awaitable[ResourceResult]],
    ) -> ResourceResult:
        result = await call_next(context)
        try:
            return self._scrub_resource_result(result)
        except PiiScrubError:
            return self._withheld_resource()
        except Exception:
            return self._withheld_resource()

    async def on_get_prompt(
        self,
        context: MiddlewareContext[Any],
        call_next: Callable[[MiddlewareContext[Any]], Awaitable[PromptResult]],
    ) -> PromptResult:
        result = await call_next(context)
        try:
            return self._scrub_prompt_result(result)
        except PiiScrubError:
            return self._withheld_prompt()
        except Exception:
            return self._withheld_prompt()

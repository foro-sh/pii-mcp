"""FastMCP PiiScrubMiddleware tests (mock call_next)."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from mcp.types import TextContent

from fastmcp.tools.tool import ToolResult

from pii_mcp.fastmcp import WITHHELD_TEXT, PiiScrubMiddleware
from pii_mcp.scrub import ScrubReport


@pytest.fixture
def middleware() -> PiiScrubMiddleware:
    return PiiScrubMiddleware()


async def test_masks_tool_result_content(middleware: PiiScrubMiddleware) -> None:
    async def call_next(_ctx: Any) -> ToolResult:
        return ToolResult(
            content=[
                TextContent(
                    type="text",
                    text="Contact ada@example.com or NL91ABNA0417164300",
                )
            ]
        )

    result = await middleware.on_call_tool(MagicMock(), call_next)
    assert isinstance(result.content[0], TextContent)
    assert result.content[0].text == "Contact [EMAIL] or [IBAN]"


async def test_masks_structured_content(middleware: PiiScrubMiddleware) -> None:
    async def call_next(_ctx: Any) -> ToolResult:
        return ToolResult(
            content=[TextContent(type="text", text="ok")],
            structured_content={"email": "ada@example.com"},
        )

    result = await middleware.on_call_tool(MagicMock(), call_next)
    assert result.structured_content == {"email": "[EMAIL]"}


async def test_on_scrub_receives_report_only() -> None:
    reports: list[ScrubReport] = []

    mw = PiiScrubMiddleware(on_scrub=reports.append)

    async def call_next(_ctx: Any) -> ToolResult:
        return ToolResult(
            content=[TextContent(type="text", text="mail ada@example.com")]
        )

    await mw.on_call_tool(MagicMock(), call_next)
    assert len(reports) == 1
    assert reports[0].found is True
    assert reports[0].counts["email"] == 1
    # No plaintext on the report object.
    assert not hasattr(reports[0], "text")
    assert "ada@" not in repr(reports[0])


async def test_fail_closed_oversize_withholds() -> None:
    import pii_mcp.scrub as scrub_mod

    original = scrub_mod.MAX_SCRUB_BYTES
    scrub_mod.MAX_SCRUB_BYTES = 32
    mw = PiiScrubMiddleware()
    try:

        async def call_next(_ctx: Any) -> ToolResult:
            return ToolResult(
                content=[TextContent(type="text", text="x" * 100 + " ada@example.com")]
            )

        result = await mw.on_call_tool(MagicMock(), call_next)
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == WITHHELD_TEXT
        assert "ada@" not in result.content[0].text
        assert "xxxx" not in result.content[0].text
    finally:
        scrub_mod.MAX_SCRUB_BYTES = original


async def test_languages_en_skips_bsn() -> None:
    mw = PiiScrubMiddleware(languages=["en"])

    async def call_next(_ctx: Any) -> ToolResult:
        # Valid BSN that fails SSN rules (group 00).
        return ToolResult(
            content=[TextContent(type="text", text="BSN 100000009")]
        )

    result = await mw.on_call_tool(MagicMock(), call_next)
    assert result.content[0].text == "BSN 100000009"


async def test_masks_tool_result_meta(middleware: PiiScrubMiddleware) -> None:
    async def call_next(_ctx: Any) -> ToolResult:
        return ToolResult(
            content=[TextContent(type="text", text="ok")],
            meta={"email": "ada@example.com"},
        )

    result = await middleware.on_call_tool(MagicMock(), call_next)
    assert result.meta == {"email": "[EMAIL]"}

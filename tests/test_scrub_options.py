"""Shared ``types`` / ``allow`` cases (``eval/fixtures/scrub_options.json``)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastmcp.tools import ToolResult
from mcp.types import TextContent

from pii_mcp import PII_TYPES, PiiScrubError, scrub_payload, scrub_text
from pii_mcp import scrub as scrub_mod
from pii_mcp.fastmcp import PiiScrubMiddleware

FIXTURE = Path(__file__).resolve().parent.parent / "eval" / "fixtures" / "scrub_options.json"
_CASES = json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", _CASES, ids=[c["name"] for c in _CASES])
def test_scrub_options_case(case: dict) -> None:
    options = case["options"]
    if "payload" in case:
        run = lambda: scrub_payload(case["payload"], **options)  # noqa: E731
        key = "payload"
    else:
        run = lambda: scrub_text(case["text"], **options)  # noqa: E731
        key = "text"
    if "error" in case:
        with pytest.raises(ValueError, match=case["error"]):
            run()
        return
    result = run()
    expected = case["expected"]
    assert result[key] == expected[key]
    assert result["counts"] == {t: expected["counts"].get(t, 0) for t in PII_TYPES}
    assert result["found"] == bool(expected["counts"])


def test_unprotected_call_never_needs_a_sentinel() -> None:
    every_pua = "".join(chr(c) for c in range(0xE000, 0xF900))
    text = every_pua + " a@b.com"
    assert scrub_text(text, allow=[])["text"] == every_pua + " [EMAIL]"
    assert scrub_text(text, types=["email"])["text"] == every_pua + " [EMAIL]"
    with pytest.raises(PiiScrubError, match="private-use character"):
        scrub_text(text, allow=["a@b.com"])


def test_native_gets_only_the_options_that_are_set(monkeypatch: pytest.MonkeyPatch) -> None:
    native = MagicMock()
    native.scrub_text.return_value = {}
    monkeypatch.setattr(scrub_mod, "_native_mod", native)
    monkeypatch.setattr(scrub_mod, "_resolve_backend", lambda: "native")
    scrub_text("x")
    scrub_text("x", types=["email"], allow=["a"])
    assert native.scrub_text.call_args_list[0].kwargs == {}
    assert native.scrub_text.call_args_list[1].kwargs == {"types": ["email"], "allow": ["a"]}


async def test_middleware_passes_types_and_allow() -> None:
    mw = PiiScrubMiddleware(types=["email"], allow=["ops@foro.sh"])

    async def call_next(_ctx: Any) -> ToolResult:
        return ToolResult(
            content=[TextContent(type="text", text="ops@foro.sh a@b.com 123456782")],
            structured_content={"m": "ops@foro.sh a@b.com"},
        )

    result = await mw.on_call_tool(MagicMock(), call_next)
    assert result.content[0].text == "ops@foro.sh [EMAIL] 123456782"
    assert result.structured_content == {"m": "ops@foro.sh [EMAIL]"}


def test_middleware_rejects_an_unknown_type_up_front() -> None:
    with pytest.raises(ValueError, match="unknown type 'nope'"):
        PiiScrubMiddleware(types=["nope"])

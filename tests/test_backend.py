"""Backend selection for optional Rust acceleration."""

from __future__ import annotations

import pytest

from pii_mcp import scrub_text, using_native
from pii_mcp import scrub as scrub_mod


def test_default_backend_is_python_without_native(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scrub_mod, "_native_mod", None)
    monkeypatch.delenv("PII_MCP_BACKEND", raising=False)
    assert using_native() is False
    result = scrub_text("Contact ada@example.com")
    assert result["text"] == "Contact [EMAIL]"


def test_force_python_even_if_native_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PII_MCP_BACKEND", "python")
    assert using_native() is False


def test_force_native_without_extension_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scrub_mod, "_native_mod", None)
    monkeypatch.setenv("PII_MCP_BACKEND", "native")
    with pytest.raises(ImportError, match="pii_mcp._native"):
        using_native()

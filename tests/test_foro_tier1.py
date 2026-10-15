"""Adoption-gate fixtures from foro-pii Tier 1 (shared JSON pack)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pii_mcp import scrub_text

FIXTURE = Path(__file__).resolve().parent.parent / "eval" / "fixtures" / "foro_tier1.json"
_PACK = json.loads(FIXTURE.read_text(encoding="utf-8"))
_CASES = _PACK["cases"]
_LANGS = tuple(_PACK["default_languages"])


@pytest.mark.parametrize("case", _CASES, ids=[c["id"] for c in _CASES])
def test_foro_tier1_case(case: dict) -> None:
    result = scrub_text(case["input"], languages=_LANGS)
    if "expect_text" in case:
        assert result["text"] == case["expect_text"]
    for key, want in case["expect_counts"].items():
        assert result["counts"][key] == want, key

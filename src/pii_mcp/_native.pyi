from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from pii_mcp.scrub import ScrubPayloadResult, ScrubTextResult

__version__: str

def scrub_text(
    text: str,
    *,
    languages: Sequence[str] | None = ...,
    types: Sequence[str] | None = ...,
    allow: Sequence[str] | None = ...,
) -> ScrubTextResult: ...

def scrub_payload(
    payload: Any,
    *,
    languages: Sequence[str] | None = ...,
    types: Sequence[str] | None = ...,
    allow: Sequence[str] | None = ...,
) -> ScrubPayloadResult: ...

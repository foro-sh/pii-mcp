"""Pattern-based PII scrubbing for MCP tool/resource/prompt results.

Sync, in-process, regex + checksum detectors, including street + house
number addresses. Person names need ``ner=True`` and the native extension
built with the optional ``ner`` feature.
"""

from __future__ import annotations

from pii_mcp.scrub import (
    DEFAULT_LANGUAGES,
    MAX_SCRUB_BYTES,
    PII_TYPES,
    PiiCounts,
    PiiScrubError,
    PiiType,
    ScrubPayloadResult,
    ScrubReport,
    ScrubTextResult,
    empty_pii_counts,
    scrub_payload,
    scrub_text,
    total_pii_count,
    using_native,
)

__all__ = [
    "DEFAULT_LANGUAGES",
    "MAX_SCRUB_BYTES",
    "PII_TYPES",
    "PiiCounts",
    "PiiScrubError",
    "PiiType",
    "ScrubPayloadResult",
    "ScrubReport",
    "ScrubTextResult",
    "empty_pii_counts",
    "scrub_payload",
    "scrub_text",
    "total_pii_count",
    "using_native",
]

__version__ = "0.1.0"

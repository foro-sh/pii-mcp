"""Pattern-based PII scrubbing for MCP tool/resource/prompt results.

Sync, in-process, regex + checksum detectors. Does not include NER for
person names or full street addresses (e.g. Presidio).
"""

from __future__ import annotations

from pii_mcp.scrub import (
    DEFAULT_LANGUAGES,
    MAX_SCRUB_BYTES,
    PII_TYPES,
    PiiCounts,
    PiiScrubError,
    PiiType,
    ScrubReport,
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
    "ScrubReport",
    "empty_pii_counts",
    "scrub_payload",
    "scrub_text",
    "total_pii_count",
    "using_native",
]

__version__ = "0.1.0"

"""Tier-1 PII scrubbing for MCP tool/resource/prompt results.

Sync, in-process, regex + checksum detectors. Not full foro.sh Data
protection (no Tier-2 NER / Presidio).
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
]

__version__ = "0.1.0"

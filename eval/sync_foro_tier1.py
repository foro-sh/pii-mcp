"""Refresh foro Tier 1 fixture metadata from the local ``../platform`` checkout.

Hand-maintained cases stay in ``eval/fixtures/foro_tier1.json`` so public CI
needs no private access. This script records which platform files and commit
the pack tracks, and fails if those sources are missing or unreadable.

Usage (from a machine with platform cloned beside pii-mcp)::

    python eval/sync_foro_tier1.py
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent
ROOT = EVAL_DIR.parent
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))

from platform_root import platform_file, platform_root  # noqa: E402

FIXTURE = ROOT / "eval" / "fixtures" / "foro_tier1.json"

SOURCES = (
    "packages/types/pii.test.ts",
    "infra/templates/tests/pii-scrub.test.mts",
    "infra/templates/foro-pii.mts",
)


def main() -> None:
    root = platform_root(required=True)
    assert root is not None
    commit = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    resolved: list[str] = []
    for rel in SOURCES:
        path = platform_file(*rel.split("/"), required=True)
        assert path is not None
        resolved.append(rel)
        path.read_text(encoding="utf-8")

    pack = json.loads(FIXTURE.read_text(encoding="utf-8"))
    pack["source"] = (
        "Local ../platform checkout (private). Vendored cases for public CI. "
        "Run python eval/sync_foro_tier1.py after editing platform Tier 1 tests."
    )
    pack["platform"] = {
        "root_env": "PII_MCP_PLATFORM",
        "default_relative": "../platform",
        "commit": commit,
        "files": resolved,
    }
    FIXTURE.write_text(
        json.dumps(pack, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"updated {FIXTURE.relative_to(ROOT)} from {root} @ {commit[:12]}")
    print("cases unchanged; re-edit JSON by hand when platform expectations move.")
    sys.exit(0)


if __name__ == "__main__":
    main()

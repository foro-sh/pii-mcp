"""Locate the private foro-sh/platform checkout next to this public repo.

pii-mcp is public; platform is private. CI and published artifacts must not
fetch platform. Maintainers with both checkouts use a sibling directory::

    repos/
      pii-mcp/
      platform/

Override with ``PII_MCP_PLATFORM`` when the checkout lives elsewhere. Worktrees
resolve against the main checkout (``git rev-parse --git-common-dir``) so
``.worktrees/...`` still finds ``../platform``.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent
REPO_ROOT = EVAL_DIR.parent


def main_checkout() -> Path:
    """Return the primary pii-mcp working tree (not a linked worktree path)."""
    common = subprocess.check_output(
        ["git", "rev-parse", "--git-common-dir"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    common_path = Path(common)
    if not common_path.is_absolute():
        common_path = (REPO_ROOT / common_path).resolve()
    return common_path.parent


def platform_root(*, required: bool = False) -> Path | None:
    """Return the platform checkout path, or None when absent.

    When ``required`` is True, raise ``FileNotFoundError`` with setup hints.
    """
    override = os.environ.get("PII_MCP_PLATFORM")
    if override:
        root = Path(override).expanduser().resolve()
    else:
        root = (main_checkout().parent / "platform").resolve()
    if root.is_dir():
        return root
    if required:
        raise FileNotFoundError(
            f"platform checkout not found at {root}. "
            "Clone foro-sh/platform as a sibling of pii-mcp, or set "
            "PII_MCP_PLATFORM to the checkout path. Public CI must not "
            "depend on this path."
        )
    return None


def platform_file(*parts: str, required: bool = False) -> Path | None:
    """Resolve a path under the platform checkout."""
    root = platform_root(required=required)
    if root is None:
        return None
    path = root.joinpath(*parts)
    if path.is_file():
        return path
    if required:
        raise FileNotFoundError(f"expected platform file missing: {path}")
    return None

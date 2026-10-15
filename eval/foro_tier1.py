"""Run the foro Tier 1 adoption-gate fixtures against the Python scrubber.

Fixtures live in ``eval/fixtures/foro_tier1.json`` (ported from
``foro-sh/platform`` ``packages/types/pii.test.ts``). Exit status 1 if any
case regresses: a positive that fails to mask as expected, or a listed clean
sample that is newly masked (or masked differently than recorded).

Usage::

    python eval/foro_tier1.py

Optional ``PII_MCP_BACKEND=native`` exercises the Rust path after
``maturin develop --release``. Prints a go/no-go summary with pass counts and
wall time for the pack.
"""

from __future__ import annotations

import json
import importlib.util
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

if importlib.util.find_spec("pii_mcp") is None:
    sys.path.insert(0, str(ROOT / "src"))

from pii_mcp import scrub_text  # noqa: E402

FIXTURE = ROOT / "eval" / "fixtures" / "foro_tier1.json"


def main() -> None:
    pack = json.loads(FIXTURE.read_text(encoding="utf-8"))
    languages = tuple(pack["default_languages"])
    cases = pack["cases"]
    failures: list[str] = []
    start = time.perf_counter()
    for case in cases:
        result = scrub_text(case["input"], languages=languages)
        expect_text = case.get("expect_text")
        if expect_text is not None and result["text"] != expect_text:
            failures.append(
                f"{case['id']}: text {result['text']!r} != {expect_text!r}"
            )
            continue
        for key, want in case["expect_counts"].items():
            got = result["counts"].get(key, 0)
            if got != want:
                failures.append(
                    f"{case['id']}: counts[{key}]={got} != {want}"
                )
    elapsed_ms = (time.perf_counter() - start) * 1000
    passed = len(cases) - len(failures)
    print(f"foro Tier 1 fixtures: {passed}/{len(cases)} passed in {elapsed_ms:.1f} ms")
    if failures:
        print("FAIL — not ready to replace foro-pii")
        for line in failures:
            print(f"  {line}")
        sys.exit(1)
    print("GO — ready to replace foro-pii on this Tier 1 slice")
    sys.exit(0)


if __name__ == "__main__":
    main()

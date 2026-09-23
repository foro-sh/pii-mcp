"""Compare the Python and native (Rust) backends on generated text.

    maturin develop --release && python eval/parity.py [n]

Inputs splice generated PII, clean values, and random separator noise so
boundary handling is exercised. Exit status 1 on any mismatch.
"""

from __future__ import annotations

import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "eval"))

from generators import CLEAN, PII  # noqa: E402

from pii_mcp import scrub as backend  # noqa: E402

NOISE = "0123456789abcdefABx:.,;-/ @+()\n"


def sample(r: random.Random) -> str:
    parts = []
    for _ in range(r.randint(1, 4)):
        roll = r.random()
        if roll < 0.4:
            parts.append(r.choice(PII)[1](r))
        elif roll < 0.6:
            parts.append(r.choice(CLEAN)[1](r))
        else:
            parts.append("".join(r.choice(NOISE) for _ in range(r.randint(0, 6))))
    return "".join(parts)


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20_000
    r = random.Random(42)
    langs = ["en", "nl", "de"]
    mismatches = 0
    for _ in range(n):
        text = sample(r)
        os.environ["PII_MCP_BACKEND"] = "python"
        py = backend.scrub_text(text, languages=langs)["text"]
        os.environ["PII_MCP_BACKEND"] = "native"
        rs = backend.scrub_text(text, languages=langs)["text"]
        if py != rs:
            mismatches += 1
            if mismatches <= 10:
                print(f"{text!r}\n  py {py!r}\n  rs {rs!r}")
    print(f"mismatches {mismatches} / {n}")
    sys.exit(1 if mismatches else 0)


if __name__ == "__main__":
    main()

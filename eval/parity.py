"""Compare the Python and native (Rust) backends on generated text.

    maturin develop --release && python eval/parity.py [n]

Inputs splice generated PII, clean values, and random separator noise so
boundary handling is exercised. Exit status 1 on any mismatch.

``pii_mcp`` is imported from wherever it resolves first: an installed wheel in
CI, or ``src`` in a checkout that has not been installed. The repo source is
only put on the path when no installed package is importable, so a run in the
wheel job compares the Rust extension in that wheel rather than the checkout.
"""

from __future__ import annotations

import importlib.util
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

if importlib.util.find_spec("pii_mcp") is None:
    sys.path.insert(0, str(ROOT / "src"))

from generators import CLEAN, PII  # noqa: E402

from pii_mcp import PII_TYPES  # noqa: E402
from pii_mcp import scrub as backend  # noqa: E402

NOISE = "0123456789abcdefABx:.,;-/ @+()\n"


def sample(r: random.Random) -> tuple[str, list[str]]:
    """Return a mixed input and the PII values spliced into it."""
    parts = []
    pii = []
    for _ in range(r.randint(1, 4)):
        roll = r.random()
        if roll < 0.4:
            value = r.choice(PII)[1](r)
            parts.append(value)
            pii.append(value)
        elif roll < 0.6:
            parts.append(r.choice(CLEAN)[1](r))
        else:
            parts.append("".join(r.choice(NOISE) for _ in range(r.randint(0, 6))))
    return "".join(parts), pii


def options(r: random.Random, pii: list[str]) -> dict:
    """Random ``types`` / ``allow``, so the protect path is compared too."""
    opts: dict = {}
    if r.random() < 0.3:
        opts["types"] = r.sample(PII_TYPES, r.randint(0, len(PII_TYPES)))
    if pii and r.random() < 0.3:
        opts["allow"] = [v.upper() if r.random() < 0.5 else v for v in r.sample(pii, r.randint(1, len(pii)))]
    return opts


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20_000
    r = random.Random(42)
    langs = ["en", "nl", "de"]
    mismatches = 0
    for _ in range(n):
        text, pii = sample(r)
        opts = options(r, pii)
        os.environ["PII_MCP_BACKEND"] = "python"
        py = backend.scrub_text(text, languages=langs, **opts)
        os.environ["PII_MCP_BACKEND"] = "native"
        rs = backend.scrub_text(text, languages=langs, **opts)
        if py != rs:
            mismatches += 1
            if mismatches <= 10:
                print(f"{text!r} {opts!r}\n  py {py!r}\n  rs {rs!r}")
    print(f"mismatches {mismatches} / {n}")
    sys.exit(1 if mismatches else 0)


if __name__ == "__main__":
    main()

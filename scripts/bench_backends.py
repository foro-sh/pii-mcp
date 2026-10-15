#!/usr/bin/env python3
"""Side-by-side scrub performance: pure Python vs optional Rust native.

Build a release extension first (debug builds look slower than Python):

  maturin develop --release --manifest-path crates/pii-mcp-native/Cargo.toml
  python scripts/bench_backends.py
"""

from __future__ import annotations

import os
import statistics
import time
from typing import Any, Callable

import pii_mcp.scrub as scrub


def _require_native() -> None:
    if scrub._native_mod is None:
        raise SystemExit(
            "pii_mcp._native not installed; build with:\n"
            "  maturin develop --manifest-path crates/pii-mcp-native/Cargo.toml"
        )


def _time_ms(fn: Callable[[], Any], rounds: int, warmup: int = 3) -> list[float]:
    for _ in range(warmup):
        fn()
    samples: list[float] = []
    for _ in range(rounds):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return samples


def _fmt(samples: list[float]) -> str:
    return (
        f"median={statistics.median(samples):8.3f} ms  "
        f"mean={statistics.mean(samples):8.3f} ms"
    )


def _speedup(py: list[float], rust: list[float]) -> str:
    ratio = statistics.median(py) / statistics.median(rust)
    if ratio >= 1:
        return f"{ratio:5.2f}× Rust"
    return f"{1 / ratio:5.2f}× Python"


def _with_backend(backend: str, fn: Callable[[], Any], rounds: int) -> list[float]:
    previous = os.environ.get("PII_MCP_BACKEND")
    os.environ["PII_MCP_BACKEND"] = backend
    try:
        return _time_ms(fn, rounds=rounds)
    finally:
        if previous is None:
            os.environ.pop("PII_MCP_BACKEND", None)
        else:
            os.environ["PII_MCP_BACKEND"] = previous


def main() -> None:
    _require_native()

    mixed = (
        "Contact ada@example.com or pay NL91ABNA0417164300 with "
        "4111111111111111 from 203.0.113.42 / +31 6 12345678 / "
        "BSN 111222333 / ssn 078-05-1120 / IdNr 36574261809 / "
        "postcode 1012 AB"
    )
    clean = "The server exposes a search tool and a fetch tool. " * 20
    sparse_block = ("lorem ipsum dolor sit amet " * 40) + mixed + "\n"
    large_100k = sparse_block * max(1, 100_000 // len(sparse_block))
    large_1m = sparse_block * max(1, 1_000_000 // len(sparse_block))
    payload = {
        "user": {"email": "ada@example.com", "note": clean},
        "contacts": [mixed, clean, "reach 06 12345678"],
        "items": [{"id": i, "bio": mixed if i % 10 == 0 else clean} for i in range(50)],
    }

    cases: list[tuple[str, Callable[[], Any], int]] = [
        ("short clean text", lambda: scrub.scrub_text(clean), 300),
        (
            "short mixed PII (en+nl+de)",
            lambda: scrub.scrub_text(mixed, languages=["en", "nl", "de"]),
            300,
        ),
        ("100 KiB sparse PII", lambda: scrub.scrub_text(large_100k), 50),
        ("1 MiB sparse PII", lambda: scrub.scrub_text(large_1m), 12),
        (
            "nested JSON payload",
            lambda: scrub.scrub_payload(payload, languages=["en", "nl", "de"]),
            100,
        ),
        (
            "1k× tiny scrub_text calls",
            lambda: [scrub.scrub_text(mixed) for _ in range(1000)],
            25,
        ),
    ]

    print("pii-mcp backend benchmark (Python vs Rust native)\n")
    header = f"{'case':<28} {'Python':<40} {'Rust':<40} relative"
    print(header)
    print("-" * len(header))

    for name, fn, rounds in cases:
        py = _with_backend("python", fn, rounds)
        rust = _with_backend("native", fn, rounds)
        print(f"{name:<28} {_fmt(py):<40} {_fmt(rust):<40} {_speedup(py, rust)}")

    print(
        "\nNote: medians over repeated rounds after warmup. "
        "Relative = median(Python) / median(Rust)."
    )


if __name__ == "__main__":
    main()

"""External benchmark: score pii-mcp against real ai4privacy text.

    python eval/external.py                  # phone/address/structured-id recall+precision
    python eval/external.py --ner             # also print person/place (context only)
    python eval/external.py --n 500 --seed 1  # larger sample, different draw

Opt-in: needs the ``datasets`` package (``pip install -e ".[eval]"``) and
network access to the Hugging Face Hub. The validation split is ~900 MB and
is cached by ``datasets`` after the first run; it is never vendored into this
repository.

Dataset: ``ai4privacy/pii-masking-openpii-1m`` (CC BY 4.0), not the
``ai4privacy/pii-masking-300k`` dataset named in issue #56. That dataset's
license restricts use to non-commercial academic research and forbids
derivative products without a separate written license from AI4Privacy,
terms this MIT-licensed, commercially deployed package cannot meet. The
``openpii`` dataset is the CC-BY sibling from the same project: same
``privacy_mask`` schema, same ``en``/``nl``/``de`` locales, licensed for
reuse with attribution. Credit: AI4Privacy, ai4privacy/pii-masking-openpii-1m,
https://huggingface.co/datasets/ai4privacy/pii-masking-openpii-1m (CC BY 4.0).

Its 19-label set has no IP/MAC/IBAN/coordinate labels, so this benchmark
cannot score those categories; ``eval/score.py``'s synthetic generators
already cover them.

Scoring: for each text, pii-mcp's output is aligned back to the source by
anchoring the literal (non-placeholder) chunks of the output onto the source
in order with ``str.find``; whatever source text falls between two anchors
is the span the placeholder between them replaced. A character-level
``difflib`` diff was tried first and rejected: a placeholder such as
``[ADDRESS]`` can share a letter with nearby source text (``...Street`` /
``...[ADDRE``), and ``SequenceMatcher`` then aligns on that coincidence,
splitting one masked span into two and losing its placeholder label.
Anchoring on whole literal chunks has no such failure mode. A gold span
counts as caught when none of its alphanumeric characters survive unchanged
in the output. Gold labels are
grouped: ``person`` (GIVENNAME, SURNAME), ``street_address`` (STREET,
BUILDINGNUM, ZIPCODE), ``place`` (CITY), ``phone`` (TELEPHONENUM) and
``structured_id`` (SOCIALNUM, TAXNUM, IDCARDNUM, PASSPORTNUM,
DRIVERLICENSENUM, CREDITCARDNUMBER). ``person`` and ``place`` are printed
only with ``--ner``: pii-mcp's pattern layer does not target prose names or
city/place names (README "Scope"; a Presidio/NER sidecar owns that tier on
foro), so they are reported as platform-baseline context, never a gate.

Precision per group and the share of masked runs with no gold overlap at all
both come from pii-mcp's own ``[LABEL]`` placeholders: each anchored run is
attributed to the detector category named in its placeholder, then checked
against gold spans of the matching group.

The last line printed is machine-readable JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import statistics
import sys
import time
from pathlib import Path

os.environ.setdefault("PII_MCP_BACKEND", "python")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "eval"))

from score import PLACEHOLDER_RE  # noqa: E402

from pii_mcp import scrub_text  # noqa: E402

_SPLIT_RE = re.compile(f"({PLACEHOLDER_RE.pattern})")

DATASET = "ai4privacy/pii-masking-openpii-1m"
DATASET_URL = "https://huggingface.co/datasets/ai4privacy/pii-masking-openpii-1m"
LANGUAGES: tuple[str, ...] = ("en", "nl", "de")
DEFAULT_N = 300
DEFAULT_SEED = 0

GROUPS: dict[str, tuple[str, ...]] = {
    "person": ("GIVENNAME", "SURNAME"),
    "street_address": ("STREET", "BUILDINGNUM", "ZIPCODE"),
    "place": ("CITY",),
    "phone": ("TELEPHONENUM",),
    "structured_id": (
        "SOCIALNUM",
        "TAXNUM",
        "IDCARDNUM",
        "PASSPORTNUM",
        "DRIVERLICENSENUM",
        "CREDITCARDNUMBER",
    ),
}
LABEL_TO_GROUP: dict[str, str] = {
    label: group for group, labels in GROUPS.items() for label in labels
}
CONTEXT_ONLY_GROUPS = frozenset({"person", "place"})

MCP_LABEL_TO_GROUP: dict[str, str] = {
    "PERSON": "person",
    "ADDRESS": "street_address",
    "PHONE": "phone",
    "BSN": "structured_id",
    "SSN": "structured_id",
    "TAX_ID": "structured_id",
    "PASSPORT": "structured_id",
    "VAT_ID": "structured_id",
    "CREDIT_CARD": "structured_id",
    "LICENSE_PLATE": "structured_id",
}


def _load_sample(n_per_language: int, seed: int) -> list[tuple[str, dict]]:
    """Reservoir-sample ``n_per_language`` validation rows per language.

    A single streamed pass over the split, so memory never exceeds
    ``n_per_language`` rows per language regardless of split size.
    """
    try:
        from datasets import load_dataset
    except ImportError:
        sys.exit(
            "eval/external.py needs the `datasets` package: "
            'pip install -e ".[eval]"'
        )
    rows = load_dataset(DATASET, split="validation", streaming=True)
    rng = random.Random(seed)
    buckets: dict[str, list[dict]] = {lang: [] for lang in LANGUAGES}
    seen: dict[str, int] = dict.fromkeys(LANGUAGES, 0)
    for row in rows:
        lang = row.get("language")
        if lang not in buckets:
            continue
        seen[lang] += 1
        bucket = buckets[lang]
        if len(bucket) < n_per_language:
            bucket.append(row)
        else:
            j = rng.randrange(seen[lang])
            if j < n_per_language:
                bucket[j] = row
    missing = {lang: len(buckets[lang]) for lang in LANGUAGES if len(buckets[lang]) < n_per_language}
    if missing:
        sys.exit(f"{DATASET} validation split has too few rows for {missing}")
    return [(lang, row) for lang in LANGUAGES for row in buckets[lang]]


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def _diff_runs(source: str, output: str) -> tuple[list[bool], list[tuple[int, int, str | None]]]:
    """(kept, runs): per-char survival on ``source``, and masked source runs.

    ``kept[i]`` is True when ``source[i]`` survives unchanged in ``output``.
    Each run is a ``(start, end, mcp_label)`` source-side range pii-mcp
    changed; ``mcp_label`` is the placeholder (``[PHONE]`` etc.) that
    replaced it, without the brackets, or ``None`` for a trailing gap that
    could not be anchored (see module docstring).

    ``output`` is split on ``[LABEL]`` placeholders; each literal chunk
    between them is anchored onto ``source`` in order with ``str.find``, and
    the gap before an anchor is the span its preceding placeholder replaced.
    A literal chunk that cannot be found downstream (the detector damaged
    surrounding text) ends anchoring early: the remainder of ``source`` is
    reported as one masked run under the last seen label.
    """
    kept = [True] * len(source)
    runs: list[tuple[int, int, str | None]] = []
    parts = _SPLIT_RE.split(output)
    last_idx = len(parts) - 1
    pos = 0
    label: str | None = None
    for idx, part in enumerate(parts):
        if idx % 2 == 1:
            label = part[1:-1]
            continue
        if idx == last_idx and part == "" and label is not None:
            found = len(source)
        elif part:
            found = source.find(part, pos)
            if found == -1:
                found = len(source)
        else:
            found = pos
        if found > pos:
            for i in range(pos, found):
                kept[i] = False
            runs.append((pos, found, label))
        pos = found + len(part)
        label = None
    return kept, runs


def score_sample(sample: list[tuple[str, dict]]) -> dict:
    group_totals: dict[str, int] = dict.fromkeys(GROUPS, 0)
    group_leaks: dict[str, int] = dict.fromkeys(GROUPS, 0)
    group_hits: dict[str, int] = dict.fromkeys(GROUPS, 0)
    group_fps: dict[str, int] = dict.fromkeys(GROUPS, 0)
    total_runs = 0
    no_overlap_runs = 0
    latencies_ms: list[float] = []

    for _lang, row in sample:
        source = row["source_text"]
        gold = row["privacy_mask"]
        t0 = time.perf_counter()
        output = scrub_text(source, languages=list(LANGUAGES))["text"]
        latencies_ms.append((time.perf_counter() - t0) * 1000)

        kept, runs = _diff_runs(source, output)
        gold_spans = [(g["start"], g["end"]) for g in gold]
        gold_spans_by_group: dict[str, list[tuple[int, int]]] = {g: [] for g in GROUPS}
        for g in gold:
            group = LABEL_TO_GROUP.get(g["label"])
            if group is None:
                continue
            span = (g["start"], g["end"])
            gold_spans_by_group[group].append(span)
            group_totals[group] += 1
            alnum = [i for i in range(span[0], span[1]) if source[i].isalnum()]
            if any(kept[i] for i in alnum):
                group_leaks[group] += 1

        for start, end, mcp_label in runs:
            total_runs += 1
            run = (start, end)
            if not any(_overlaps(run, gs) for gs in gold_spans):
                no_overlap_runs += 1
            group = MCP_LABEL_TO_GROUP.get(mcp_label or "")
            if group is None:
                continue
            if any(_overlaps(run, gs) for gs in gold_spans_by_group[group]):
                group_hits[group] += 1
            else:
                group_fps[group] += 1

    per_group = {}
    for group in GROUPS:
        total = group_totals[group]
        hits, fps = group_hits[group], group_fps[group]
        per_group[group] = {
            "n": total,
            "recall": round(1 - group_leaks[group] / total, 4) if total else None,
            "precision": round(hits / (hits + fps), 4) if (hits + fps) else None,
        }

    return {
        "dataset": DATASET,
        "n_texts": len(sample),
        "per_group": per_group,
        "no_gold_overlap_rate": round(no_overlap_runs / total_runs, 4) if total_runs else 0.0,
        "median_latency_ms": round(statistics.median(latencies_ms), 3) if latencies_ms else 0.0,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=DEFAULT_N, help="texts per language")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--ner", action="store_true", help="also print person/place (context only, not a target)")
    args = ap.parse_args()

    print(f"ai4privacy/pii-masking-openpii-1m (CC BY 4.0): {DATASET_URL}")
    sample = _load_sample(args.n, args.seed)
    result = score_sample(sample)

    for group, stats in result["per_group"].items():
        if group in CONTEXT_ONLY_GROUPS and not args.ner:
            continue
        suffix = " (context only, not a pii-mcp target)" if group in CONTEXT_ONLY_GROUPS else ""
        print(f"{group}: recall={stats['recall']} precision={stats['precision']} n={stats['n']}{suffix}")
    print(f"masked runs with no gold overlap: {result['no_gold_overlap_rate']}")
    print(f"median latency per text: {result['median_latency_ms']} ms")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
